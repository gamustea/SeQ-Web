
from abc import ABC, abstractmethod
from typing import Any, Optional

import ollama
from ollama import ChatResponse

from src.misc import SecOpsLogger, ConfigReader

class AIWriter(ABC):
    """
    Clase base abstracta para writers que generan contenido mediante IA (Ollama).
    
    Proporciona la infraestructura común: cliente Ollama, búsqueda web,
    manejo de reintentos y parseo de respuestas.
    
    Las subclases deben implementar:
        - _build_system_prompt(): Prompt del sistema específico del dominio
        - _build_user_prompt(): Prompt de usuario con parámetros específicos
        - generate(): Método principal de generación que retorna contenido específico
    
    Si host o model son None, se obtienen de las variables de entorno OLLAMA_HOST
    y OLLAMA_MODEL (o valores por defecto).
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:

        config_reader = ConfigReader()
        env_host, env_model = config_reader.get_ollama_config()
        
        if host is None or model is None:
            self.host = host or env_host
            self.model = model or env_model
        else:
            self.host = host
            self.model = model
            
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()
        self._client = ollama.Client(host=self.host)

    # ── Búsqueda web ───────────────────────────────────────────────────────────

    def _web_search(self, query: str, max_results: int = 5) -> str:
        """Realiza una búsqueda web con DuckDuckGo."""
        from ddgs import DDGS
        
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
            if not results:
                return f"[BÚSQUEDA] Sin resultados para: {query}"
            lines = [f"### Resultados de búsqueda: '{query}'\n"]
            for i, r in enumerate(results, 1):
                lines.append(
                    f"{i}. **{r.get('title', 'Sin título')}**\n"
                    f"   {r.get('body', '')[:200]}\n"
                    f"   URL: {r.get('href', '')}\n"
                )
            return "\n".join(lines)
        except Exception as exc:
            self.logger.error(f"Error búsqueda web: {exc}")
            return f"[ERROR BÚSQUEDA] {exc}"

    # ── Métodos abstractos ───────────────────────────────────────────────────

    @abstractmethod
    def _build_system_prompt(self) -> str:
        """Construye el prompt del sistema específico del dominio."""
        pass

    @abstractmethod
    def _build_user_prompt(self, *args: Any, **kwargs: Any) -> str:
        """Construye el prompt de usuario con parámetros específicos del dominio."""
        pass

    @abstractmethod
    def generate(self, *args: Any, **kwargs: Any) -> Any:
        """Genera el contenido específico del dominio. Debe ser implementado por subclases."""
        pass

    # ── Helpers comunes ─────────────────────────────────────────────────────

    def _call_model(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        temperature: float = 0.5,
        num_predict: int = 4096,
    ) -> ChatResponse:
        """Llama al modelo Ollama con manejo de tool calls."""
        options = {
            "num_predict":    num_predict,
            "temperature":    temperature,
            "top_p":          0.9,
            "repeat_penalty": 1.1,
        }
        
        resp = self._client.chat(
            model    = self.model,
            messages = messages,
            tools    = tools,
            format   = "json",
            options  = options,
        )
        
        if getattr(resp.message, "tool_calls", None):
            messages.append({
                "role":       "assistant",
                "content":    resp.message.content or "",
                "tool_calls": resp.message.tool_calls,
            })
            for tc in resp.message.tool_calls:
                query         = tc.function.arguments.get("query", "")
                search_result = self._web_search(query)
                messages.append({"role": "tool", "content": search_result})
            
            resp = self._client.chat(
                model    = self.model,
                messages = messages,
                format   = "json",
                options  = options,
            )
        
        return resp