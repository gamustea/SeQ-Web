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

from abc import ABC, abstractmethod
from typing import Any, Optional

import ollama
from ollama import ChatResponse


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
                   environment or ConfigReader defaults.
            model: Optional Ollama model name. If not provided, reads from
                   environment or ConfigReader defaults.
        """
        from src.modules.misc import ConfigReader, SecOpsLogger
        env_host, env_model = ConfigReader.get_ollama_config()
        
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
        pass

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
        pass

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
        pass


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
            self.logger.info(f"[Ollama] Response received successfully")
        except Exception as e:
            self.logger.error(f"[Ollama] Error connecting to {self.host}: {e}")
            raise
        
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