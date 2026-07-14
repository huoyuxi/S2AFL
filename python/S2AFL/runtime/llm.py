"""Shared LLM client for workflow2 runtime."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from S2AFL.llm_shared import SharedLLMClient, load_llm_profile

from .config import RuntimeConfig


@dataclass
class LLMResult:
    ok: bool
    content: str
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    finish_reason: str = ""
    status_code: int = 0
    error: str = ""
    raw_json: dict[str, Any] | None = None


class RuntimeLLMClient:
    """Unified chat-completion client for workflow2 runtime."""

    def __init__(self, config: RuntimeConfig):
        self.config = config
        profile = load_llm_profile(getattr(config, 'llm_provider', None), config_path=getattr(config, 'llm_config_file', None))
        profile = type(profile)(
            provider=profile.provider,
            api_url=config.llm_api_url or profile.api_url,
            model=config.llm_model or profile.model,
            api_key=profile.api_key,
            timeout_sec=config.llm_timeout_sec or profile.timeout_sec,
            max_retries=profile.max_retries,
            temperature=config.llm_temperature,
            max_tokens=config.llm_max_tokens or profile.max_tokens,
            extra_body=config.llm_extra_body or profile.extra_body,
            response_format=config.llm_response_format or profile.response_format,
        )
        self.client = SharedLLMClient(profile)

    def call(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        force_json: bool = False,
    ) -> LLMResult:
        result = self.client.call(
            messages,
            max_tokens=max_tokens,
            temperature=temperature,
            force_json=force_json,
        )
        return LLMResult(
            ok=result.ok,
            content=result.content,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
            reasoning_tokens=result.reasoning_tokens,
            finish_reason=result.finish_reason,
            status_code=result.status_code,
            error=result.error,
            raw_json=result.raw_json,
        )
