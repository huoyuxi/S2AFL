from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any



_DEFAULT_PROVIDER = 'deepseek'
_DEFAULT_CONFIG_REL = Path('experiments/llm_profiles.json')
_DEFAULT_TIMEOUT = 120
_DEFAULT_RETRIES = 3
_DEFAULT_TEMPERATURE = 0.0
_DEFAULT_MAX_TOKENS = 4096
_DEFAULT_RESPONSE_FORMAT = 'none'


@dataclass(frozen=True)
class LLMProfile:
    provider: str
    api_url: str
    model: str
    api_key: str
    timeout_sec: int = _DEFAULT_TIMEOUT
    max_retries: int = _DEFAULT_RETRIES
    temperature: float = _DEFAULT_TEMPERATURE
    max_tokens: int = _DEFAULT_MAX_TOKENS
    extra_body: dict[str, Any] | None = None
    response_format: str = _DEFAULT_RESPONSE_FORMAT


@dataclass
class LLMCallResult:
    ok: bool
    content: str
    status_code: int = 0
    error: str = ''
    input_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    finish_reason: str = ''
    raw_json: dict[str, Any] | None = None


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _default_config_path() -> Path:
    return _project_root() / _DEFAULT_CONFIG_REL


def _load_json_file(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding='utf-8')
    except OSError as exc:
        raise RuntimeError(f'failed to read LLM config {path}: {exc}') from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f'invalid JSON in LLM config {path}: {exc.msg} at line {exc.lineno} column {exc.colno}'
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError(f'LLM config must be a JSON object: {path}')
    return data


def _parse_extra_body(raw: str | dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return dict(raw)
    text = str(raw).strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f'invalid JSON in LLM extra body: {exc.msg} at line {exc.lineno} column {exc.colno}'
        ) from exc
    if not isinstance(data, dict):
        raise RuntimeError('LLM extra body must be a JSON object')
    return data


def _resolve_profile_name(config: dict[str, Any]) -> str:
    return (
        os.environ.get('LLM_PROVIDER')
        or os.environ.get('LLM_PROFILE')
        or str(config.get('default_provider') or _DEFAULT_PROVIDER)
    ).strip() or _DEFAULT_PROVIDER


def load_llm_profile(profile_name: str | None = None, *, config_path: str | os.PathLike[str] | None = None) -> LLMProfile:
    path_text = str(config_path or os.environ.get('S2AFL_LLM_CONFIG', '')).strip()
    path = Path(path_text).expanduser() if path_text else _default_config_path()
    if not path.is_absolute():
        path = (_project_root() / path).resolve()
    config = _load_json_file(path)
    profiles = config.get('profiles', {})
    if not isinstance(profiles, dict) or not profiles:
        raise RuntimeError(f'No LLM profiles defined in {path}')

    selected = (profile_name or _resolve_profile_name(config)).strip()
    if selected not in profiles:
        available = ', '.join(sorted(profiles))
        raise RuntimeError(f'Unknown LLM profile: {selected}. Available: {available}')

    raw = dict(profiles[selected])
    api_key = os.environ.get('LLM_API_KEY')
    if not api_key:
        key_env = str(raw.get('api_key_env') or 'LLM_API_KEY')
        api_key = os.environ.get(key_env, '')
    if not api_key:
        api_key = str(raw.get('api_key') or '')
    if not api_key:
        raise RuntimeError(f'LLM API key is not set for profile {selected}')

    api_url = os.environ.get('LLM_API_URL') or str(raw.get('api_url') or '').strip()
    model = os.environ.get('LLM_MODEL') or str(raw.get('model') or '').strip()
    if not api_url or not model:
        raise RuntimeError(f'LLM profile {selected} is missing api_url or model')

    timeout_sec = int(os.environ.get('LLM_TIMEOUT_SEC') or raw.get('timeout_sec') or _DEFAULT_TIMEOUT)
    max_retries = int(os.environ.get('LLM_MAX_RETRIES') or raw.get('max_retries') or _DEFAULT_RETRIES)
    temperature = float(os.environ.get('LLM_TEMPERATURE') or raw.get('temperature') or _DEFAULT_TEMPERATURE)
    max_tokens = int(os.environ.get('LLM_MAX_TOKENS') or raw.get('max_tokens') or _DEFAULT_MAX_TOKENS)
    response_format = str(os.environ.get('LLM_RESPONSE_FORMAT') or raw.get('response_format') or _DEFAULT_RESPONSE_FORMAT).strip().lower()
    extra_body = _parse_extra_body(os.environ.get('LLM_EXTRA_BODY', raw.get('extra_body')))

    return LLMProfile(
        provider=selected,
        api_url=api_url,
        model=model,
        api_key=api_key,
        timeout_sec=timeout_sec,
        max_retries=max_retries,
        temperature=temperature,
        max_tokens=max_tokens,
        extra_body=extra_body,
        response_format=response_format,
    )


class SharedLLMClient:
    def __init__(self, profile: LLMProfile):
        self.profile = profile

    def _uses_responses_api(self) -> bool:
        return '/responses' in self.profile.api_url.rstrip('/').lower()

    def _build_body(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        force_json: bool = False,
    ) -> dict[str, Any]:
        if self._uses_responses_api():
            body = {
                'model': self.profile.model,
                'input': messages,
                'max_output_tokens': int(max_tokens or self.profile.max_tokens),
                'temperature': float(self.profile.temperature if temperature is None else temperature),
            }
            body.update(self.profile.extra_body or {})
            return body

        body: dict[str, Any] = {
            'model': self.profile.model,
            'messages': messages,
            'max_tokens': int(max_tokens or self.profile.max_tokens),
            'temperature': float(self.profile.temperature if temperature is None else temperature),
            'stream': False,
        }
        if force_json and self.profile.response_format == 'json_object':
            body['response_format'] = {'type': 'json_object'}
        body.update(self.profile.extra_body or {})
        return body

    def _call_with_requests(self, headers: dict[str, str], body: dict[str, Any]) -> LLMCallResult:
        import requests

        last_error = ''
        retries = max(int(self.profile.max_retries), 1)
        for attempt in range(retries):
            try:
                resp = requests.post(
                    self.profile.api_url,
                    headers=headers,
                    json=body,
                    timeout=self.profile.timeout_sec,
                )
            except requests.RequestException as exc:
                last_error = str(exc)
                time.sleep(1 + attempt)
                continue

            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError as exc:
                    last_error = f'invalid JSON response from LLM endpoint: {exc}'
                    if attempt + 1 < retries:
                        time.sleep(1 + attempt)
                        continue
                    return LLMCallResult(ok=False, content='', status_code=resp.status_code, error=last_error)
                return self._success_result(data)

            last_error = f'HTTP {resp.status_code}: {resp.text[:500]}'
            if resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            return LLMCallResult(ok=False, content='', status_code=resp.status_code, error=last_error)

        return LLMCallResult(ok=False, content='', status_code=0, error=last_error)

    def _call_with_urllib(self, headers: dict[str, str], body: dict[str, Any]) -> LLMCallResult:
        last_error = ''
        retries = max(int(self.profile.max_retries), 1)
        payload = json.dumps(body).encode('utf-8')
        for attempt in range(retries):
            req = urllib.request.Request(
                self.profile.api_url,
                data=payload,
                headers=headers,
                method='POST',
            )
            try:
                with urllib.request.urlopen(req, timeout=self.profile.timeout_sec) as resp:
                    status_code = getattr(resp, 'status', 200) or 200
                    text = resp.read().decode('utf-8', errors='replace')
            except urllib.error.HTTPError as exc:
                status_code = int(exc.code or 0)
                text = exc.read().decode('utf-8', errors='replace')
                last_error = f'HTTP {status_code}: {text[:500]}'
                if status_code in (429, 500, 502, 503, 504):
                    time.sleep(2 ** attempt)
                    continue
                return LLMCallResult(ok=False, content='', status_code=status_code, error=last_error)
            except urllib.error.URLError as exc:
                last_error = str(exc.reason or exc)
                time.sleep(1 + attempt)
                continue
            except Exception as exc:
                last_error = str(exc)
                time.sleep(1 + attempt)
                continue

            if status_code != 200:
                last_error = f'HTTP {status_code}: {text[:500]}'
                if status_code in (429, 500, 502, 503, 504):
                    time.sleep(2 ** attempt)
                    continue
                return LLMCallResult(ok=False, content='', status_code=status_code, error=last_error)
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                last_error = f'invalid JSON response from LLM endpoint: {exc}'
                if attempt + 1 < retries:
                    time.sleep(1 + attempt)
                    continue
                return LLMCallResult(ok=False, content='', status_code=status_code, error=last_error)
            return self._success_result(data)

        return LLMCallResult(ok=False, content='', status_code=0, error=last_error)

    @staticmethod
    def _extract_responses_text(data: dict[str, Any]) -> str:
        parts: list[str] = []
        for item in data.get('output') or []:
            if not isinstance(item, dict) or item.get('type') != 'message':
                continue
            for content in item.get('content') or []:
                if not isinstance(content, dict):
                    continue
                if content.get('type') == 'output_text':
                    text = str(content.get('text') or '')
                    if text:
                        parts.append(text)
        return ''.join(parts)

    @staticmethod
    def _extract_usage_int(value: Any) -> int:
        try:
            return int(value or 0)
        except Exception:
            return 0

    def _success_result(self, data: dict[str, Any]) -> LLMCallResult:
        if data.get('object') == 'response':
            usage = data.get('usage', {}) or {}
            content = self._extract_responses_text(data)
            reasoning = usage.get('output_tokens_details', {}) or {}
            return LLMCallResult(
                ok=True,
                content=content,
                status_code=200,
                input_tokens=self._extract_usage_int(usage.get('input_tokens')),
                output_tokens=self._extract_usage_int(usage.get('output_tokens')),
                reasoning_tokens=self._extract_usage_int(reasoning.get('reasoning_tokens')),
                finish_reason=str(data.get('status') or ''),
                raw_json=data,
            )

        choice = (data.get('choices') or [{}])[0]
        msg = choice.get('message', {}) or {}
        content = msg.get('content', '') or msg.get('reasoning_content', '') or choice.get('text', '')
        usage = data.get('usage', {}) or {}
        return LLMCallResult(
            ok=True,
            content=content or '',
            status_code=200,
            input_tokens=int(usage.get('prompt_tokens', 0) or 0),
            output_tokens=int(usage.get('completion_tokens', 0) or 0),
            reasoning_tokens=int((usage.get('completion_tokens_details', {}) or {}).get('reasoning_tokens', 0) or 0),
            finish_reason=str(choice.get('finish_reason') or ''),
            raw_json=data,
        )

    def call(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
        force_json: bool = False,
    ) -> LLMCallResult:
        headers = {
            'Authorization': f'Bearer {self.profile.api_key}',
            'Content-Type': 'application/json',
        }
        body = self._build_body(messages, max_tokens=max_tokens, temperature=temperature, force_json=force_json)
        try:
            import requests  # type: ignore
        except ModuleNotFoundError:
            return self._call_with_urllib(headers, body)
        return self._call_with_requests(headers, body)


def call_text_prompt(
    prompt: str,
    *,
    profile_name: str | None = None,
    config_path: str | os.PathLike[str] | None = None,
    max_tokens: int | None = None,
    temperature: float | None = None,
) -> str | None:
    profile = load_llm_profile(profile_name, config_path=config_path)
    client = SharedLLMClient(profile)
    result = client.call(
        [{'role': 'user', 'content': prompt}],
        max_tokens=max_tokens,
        temperature=temperature,
        force_json=False,
    )
    return result.content.strip() if result.ok and result.content else None
