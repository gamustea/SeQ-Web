"""
AI-powered document generation module.

This module provides the base class for all AI-powered content writers
using Ollama as the LLM backend. It handles client initialization,
web search integration, retry logic, and response parsing.

Classes:
    AIWriter: Abstract base class for domain-specific AI writers.

Example:
>>> class MyWriter(AIWriter):
...     def _build_system_prompt(self) -> str:
...         return "You are a helpful assistant."
...     def _build_user_prompt(self, data) -> str:
...         return f"Analyze: {data}"
...     def generate(self, data):
...         return self._call_model([{"role": "user", "content": self._build_user_prompt(data)}])
"""

import ollama
from ollama import ChatResponse

from abc import ABC, abstractmethod
from typing import Any, Optional
from datetime import datetime
from pathlib import Path
from typing import TypeVar, Optional, List, Any

from src.modules.system import SecOpsLogger
from src.modules.shared import Document

class AIWriter(ABC):
    """
    Abstract base class for AI-powered content writers using Ollama.

    Provides common infrastructure for all AI writers including:
    - Ollama client initialization and configuration
    - Web search integration with DuckDuckGo
    - Tool call handling and response processing
    - Error handling and retry logic

    Subclasses must implement:
        - _build_system_prompt(): Domain-specific system prompt
        - _build_user_prompt(): User prompt with domain parameters
        - generate(): Main generation method returning domain content

    If host or model are not provided, they are read from environment
    variables OLLAMA_HOST and OLLAMA_MODEL (or defaults).

    Attributes:
        host: Ollama server URL.
        model: Ollama model name.
        logger: Logger instance for the class.
        _client: Ollama client instance.

    Example:
    >>> class ReportWriter(AIWriter):
    ...     def _build_system_prompt(self) -> str:
    ...         return "You are a security analyst."
    ...     def _build_user_prompt(self, scan) -> str:
    ...         return f"Analyze this scan: {scan.target}"
    ...     def generate(self, scan):
    ...         prompt = self._build_user_prompt(scan)
    ...         messages = [
    ...             {"role": "system", "content": self._build_system_prompt()},
    ...             {"role": "user", "content": prompt}
    ...         ]
    ...         return self._call_model(messages)
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        """
        Initialize the AI writer with Ollama configuration.

        Args:
            host: Optional Ollama server URL. If not provided, reads from
                   environment or CR defaults.
            model: Optional Ollama model name. If not provided, reads from
                   environment or CR defaults.
        """

        from src.modules.system import config_reading as CR
        env_host, env_model = CR.get_ollama_config()

        if host is None or model is None:
            self.host = host or env_host
            self.model = model or env_model
        else:
            self.host = host
            self.model = model

        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()
        self.logger.info(f"[Ollama] Inicializando cliente con host={self.host}, model={self.model}")
        self._client = ollama.Client(host=self.host, timeout=300)


    # =========================================================================
    # WEB SEARCH
    # =========================================================================

    def _web_search(self, query: str, max_results: int = 5) -> str:
        """
        Perform a web search using DuckDuckGo.

        Executes a text search and returns formatted results with titles,
        descriptions, and URLs. Used by the model to fetch current
        information during analysis.

        Args:
            query: Search query string.
            max_results: Maximum number of results to return (default: 5).

        Returns:
            Formatted string with search results, or error message if
            the search fails or returns no results.
        """
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


    # =========================================================================
    # ABSTRACT METHODS
    # =========================================================================

    @abstractmethod
    def _build_system_prompt(self) -> str:
        """
        Build the domain-specific system prompt.

        Returns:
            System prompt string defining the AI persona and behavior.
        """

    @abstractmethod
    def _build_user_prompt(self, *args: Any, **kwargs: Any) -> str:
        """
        Build the user prompt with domain-specific parameters.

        Args:
            *args: Positional arguments specific to the domain.
            **kwargs: Keyword arguments specific to the domain.

        Returns:
            User prompt string with formatted data.
        """

    @abstractmethod
    def generate(self, *args: Any, **kwargs: Any) -> Any:
        """
        Generate domain-specific content using the AI model.

        Args:
            *args: Positional arguments for content generation.
            **kwargs: Keyword arguments for content generation.

        Returns:
            Generated content in the format specific to the subclass.
        """


    # =========================================================================
    # COMMON HELPERS
    # =========================================================================

    def _call_model(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        temperature: float = 0.5,
        num_predict: int = 4096,
    ) -> ChatResponse:
        """
        Call the Ollama model with message history and optional tools.

        Sends messages to the model and handles tool call responses
        automatically by performing web searches when the model requests them.
        Configures model parameters like temperature and max tokens.

        Args:
            messages: List of message dictionaries with 'role' and 'content'.
            tools: Optional list of tool definitions for function calling.
            temperature: Sampling temperature (default: 0.5).
            num_predict: Maximum tokens to predict (default: 4096).

        Returns:
            ChatResponse object from Ollama with the model's reply.

        Raises:
            Exception: If connection to Ollama fails.
        """
        options = {
            "num_predict":    num_predict,
            "temperature":    temperature,
            "top_p":          0.9,
            "repeat_penalty": 1.1,
        }

        self.logger.info(f"[Ollama] Calling model={self.model} at {self.host}")

        try:
            self.logger.info(f"[Ollama] Sending request to {self.host}/api/chat")
            resp = self._client.chat(
                model    = self.model,
                messages = messages,
                tools    = tools,
                format   = "json",
                options  = options,
            )
            self.logger.info("Response received successfully")
        except Exception as e:
            self.logger.error("Error connecting to {self.host}: {e}")
            raise

        if getattr(resp.message, "tool_calls", None):  # pylint: disable=no-member
            messages.append({
                "role":       "assistant",
                "content":    resp.message.content or "", # pylint: disable=no-member
                "tool_calls": resp.message.tool_calls, # pylint: disable=no-member
            })
            for tc in resp.message.tool_calls: # pylint: disable=no-member
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


# =========================================================================
# DOCUMENT UTILITIES
# =========================================================================
# Funciones puras para gestión de documentos. NO gestionan sesiones.
# Los repositorios usan UnitOfWork para la persistencia.


def update_document_status(
    doc: Document,
    status: str,
    title: str | None = None,
    filename: str | None = None,
    error: str | None = None,
    set_generated_at: bool = False,
) -> Document:
    """
    Actualiza el estado de un documento con campos opcionales.

    Args:
        doc: Instancia del documento a actualizar.
        status: Nuevo estado ('pending', 'running', 'done', 'error').
        title: Nuevo título (truncado a 64 caracteres).
        filename: Nuevo nombre de archivo (truncado a 128).
        error: Mensaje de error para estado 'error' (truncado a 50).
        set_generated_at: Si True, asigna datetime.utcnow() (para estado 'done').

    Returns:
        El documento con los campos actualizados (no hace flush/commit).
    """
    doc.status = status
    if title:
        doc.title = title[:64]
    if filename:
        doc.filename = filename[:128]
    if set_generated_at and status == "done":
        doc.generated_at = datetime.utcnow()
    if error and status == "error":
        doc.title = f"[ERR{doc.id}] {error[:50]}"[:64]
    return doc


def get_document_path(doc: Document, output_dir: Path) -> Path:
    """
    Calcula la ruta absoluta al archivo del documento.

    Args:
        doc: Instancia del documento.
        output_dir: Directorio base de salida.

    Returns:
        Ruta absoluta al archivo.

    Raises:
        ValueError: Si el documento no tiene filename.
    """
    if not doc.filename:
        raise ValueError(f"Documento {doc.id} no tiene filename")
    return output_dir / doc.filename


def check_ownership(doc: Document, user_id: int, owner_field: str = "user_id") -> bool:
    """
    Verifica que el documento pertenece al usuario.

    Args:
        doc: Instancia del documento.
        user_id: ID del usuario a verificar.
        owner_field: Nombre del campo que contiene el owner (default: 'user_id').

    Returns:
        True si el documento pertenece al usuario, False en caso contrario.
    """
    return getattr(doc, owner_field, None) == user_id


def serialize_document_list(
    documents: List[Document],
    fields_map: dict[str, str] | None = None,
) -> List[dict]:
    """
    Serializa una lista de documentos a diccionarios.

    Args:
        documents: Lista de instancias de documentos.
        fields_map: Mapeo opcional de campos del modelo a nombres de salida.
                    Si None, usa los campos por defecto: id, title, filename,
                    format, status, generatedAt (como isoformat).

    Returns:
        Lista de diccionarios con los datos serializados.
    """
    default_fields = {
        "id": "id",
        "title": "title",
        "filename": "filename",
        "format": "format",
        "status": "status",
        "generated_at": "generatedAt",
    }
    mapping = fields_map or default_fields

    result = []
    for doc in documents:
        item = {}
        for model_field, output_name in mapping.items():
            value = getattr(doc, model_field, None)
            if value is None:
                item[output_name] = None
            elif isinstance(value, datetime):
                item[output_name] = value.isoformat()
            else:
                item[output_name] = value
        result.append(item)
    return result


def validate_document_ownership(
    doc: Document,
    user_id: int,
    owner_field: str = "user_id",
) -> None:
    """
    Valida la propiedad del documento y lanza excepción si no pertenece.

    Args:
        doc: Instancia del documento.
        user_id: ID del usuario a verificar.
        owner_field: Nombre del campo que contiene el owner.

    Raises:
        ValueError: Si el documento no pertenece al usuario.
    """
    if not check_ownership(doc, user_id, owner_field):
        raise ValueError(f"Documento {doc.id} no pertenece al usuario {user_id}")


def safe_delete_file(filename: str, logger: Any = None) -> bool:
    """
    Elimina un archivo del sistema de archivos de forma segura.

    Args:
        filename: Ruta al archivo a eliminar.
        logger: Opcional. Instancia de logger para registrar advertencias.

    Returns:
        True si el archivo fue eliminado o no existía, False si hubo error.
    """
    import os

    if not filename:
        return False

    if not os.path.exists(filename):
        return True

    try:
        os.remove(filename)
        return True
    except Exception as exc:
        if logger:
            logger.warning(f"No se pudo eliminar el archivo {filename}: {exc}")
        return False
