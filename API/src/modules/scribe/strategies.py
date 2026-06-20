"""
scribe.strategies
─────────────────
Estrategias de "model calling" inyectables en ``AIGenerator``.

Cada estrategia traduce un ``AIInput`` a la API nativa de un backend y ejecuta
una completación completa (incluido un turno de tool-calling con ``web_search``),
devolviendo el texto crudo del modelo. Así el resto de la plataforma es
agnóstica a si detrás hay un modelo local (Ollama) o en la nube (OpenAI),
lo que habilita el despliegue en un VPS sin GPU.

    — ModelStrategy: contrato abstracto.
    — OllamaStrategy: modelo local servido por Ollama.
    — OpenAIStrategy: modelos de OpenAI (p.ej. gpt-4o-mini).
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional

from .exceptions import AIConnectionError
from .inputs import AIInput

logger = logging.getLogger(__name__)

# Ejecutor de herramientas: recibe (nombre, argumentos) y devuelve texto.
ToolExecutor = Callable[[str, dict], str]


class ModelStrategy(ABC):
    """Contrato de una estrategia de llamada al modelo."""

    #: Nombre legible de la estrategia (para logs y circuit breaker).
    name: str = "model"

    @abstractmethod
    def complete(self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None) -> str:
        """
        Ejecuta una completación y devuelve el texto crudo del modelo.

        Implementa internamente el bucle de tool-calling (un turno) usando
        ``tool_executor`` cuando el modelo solicita herramientas.

        Raises:
            AIConnectionError: Si falla la comunicación con el backend.
        """


class OllamaStrategy(ModelStrategy):
    """Estrategia que llama a un modelo local servido por Ollama."""

    name = "ollama"

    def __init__(self, host: str, model: str, timeout: int = 300) -> None:
        import ollama

        self.host = host
        self.model = model
        logger.info("[scribe/ollama] cliente host=%s model=%s", host, model)
        self._client = ollama.Client(host=host, timeout=timeout)

    def _options(self, ai_input: AIInput) -> dict:
        return {
            "num_predict": ai_input.num_predict,
            "temperature": ai_input.temperature,
            "top_p": ai_input.top_p,
            "repeat_penalty": ai_input.repeat_penalty,
        }

    def complete(self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None) -> str:
        messages = ai_input.to_messages()
        options = self._options(ai_input)
        fmt = "json" if ai_input.json_mode else None

        try:
            resp = self._client.chat(
                model=self.model,
                messages=messages,
                tools=ai_input.tools,
                format=fmt,
                options=options,
            )

            tool_calls = getattr(resp.message, "tool_calls", None)
            if tool_calls and tool_executor:
                logger.info("[scribe/ollama] tool_calls: %d", len(tool_calls))
                messages.append({
                    "role": "assistant",
                    "content": resp.message.content or "",
                    "tool_calls": tool_calls,
                })
                for tc in tool_calls:
                    args = tc.function.arguments or {}
                    result = tool_executor(tc.function.name, dict(args))
                    messages.append({"role": "tool", "content": result})

                resp = self._client.chat(
                    model=self.model,
                    messages=messages,
                    format=fmt,
                    options=options,
                )

            return (resp.message.content or "").strip()

        except Exception as exc:
            logger.error("[scribe/ollama] error en %s: %s", self.host, exc, exc_info=True)
            raise AIConnectionError(str(exc), model=self.model) from exc


class OpenAIStrategy(ModelStrategy):
    """Estrategia que llama a la API de OpenAI (p.ej. gpt-4o-mini)."""

    name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: Optional[str] = None,
        timeout: int = 120,
    ) -> None:
        from openai import OpenAI

        self.model = model
        logger.info("[scribe/openai] cliente model=%s base_url=%s", model, base_url or "default")
        self._client = OpenAI(api_key=api_key, base_url=base_url or None, timeout=timeout)

    def _create(self, messages: list[dict], ai_input: AIInput, with_tools: bool):
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": ai_input.temperature,
            "max_tokens": ai_input.num_predict,
            "top_p": ai_input.top_p,
        }
        if ai_input.json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        if with_tools and ai_input.tools:
            kwargs["tools"] = ai_input.tools
        return self._client.chat.completions.create(**kwargs)

    def complete(self, ai_input: AIInput, tool_executor: Optional[ToolExecutor] = None) -> str:
        messages = ai_input.to_messages()

        try:
            resp = self._create(messages, ai_input, with_tools=True)
            message = resp.choices[0].message

            tool_calls = getattr(message, "tool_calls", None)
            if tool_calls and tool_executor:
                logger.info("[scribe/openai] tool_calls: %d", len(tool_calls))
                messages.append({
                    "role": "assistant",
                    "content": message.content or "",
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.function.name,
                                "arguments": tc.function.arguments,
                            },
                        }
                        for tc in tool_calls
                    ],
                })
                for tc in tool_calls:
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    result = tool_executor(tc.function.name, args)
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    })

                resp = self._create(messages, ai_input, with_tools=False)
                message = resp.choices[0].message

            return (message.content or "").strip()

        except Exception as exc:
            logger.error("[scribe/openai] error: %s", exc, exc_info=True)
            raise AIConnectionError(str(exc), model=self.model) from exc
