"""An external model through OpenRouter, for runs where the academic lead's approval applies.

Off unless `MODEL_PROVIDER` or `SHADOW_PROVIDER` is `openrouter`, or a case report is asked for
(`ioc-case-report`, `--case-reports`). Every request asks OpenRouter to route only to endpoints
that retain nothing (`zdr`) and do not collect data (`data_collection: deny`), and to fail rather
than drop a parameter (`require_parameters`). The caller replaces the case's internal host address
before any text reaches this module (`cli.pseudonymise`). Under a budget, no request is sent whose
worst case could take the reported spend past it.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

from network_behaviour.config import ConfigurationError

from ioc_report.model import REPLY_SCHEMA, ModelError, Reply

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
RETRIES = 4
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})

Post = Callable[[str, bytes | None, Mapping[str, str], float], bytes]
"""(url, body or None for GET, headers, timeout) -> response body. Raises HTTPError/URLError."""


def _urllib(url: str, body: bytes | None, headers: Mapping[str, str], timeout: float) -> bytes:
    request = urllib.request.Request(url, data=body, headers=dict(headers))
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload: bytes = response.read()
        return payload


@dataclass(frozen=True, slots=True)
class OpenRouterConfig:
    api_key: str = field(repr=False)
    model: str
    base_url: str = DEFAULT_BASE_URL
    effort: str = "medium"
    """OpenRouter's normalised reasoning effort, for models that reason."""
    max_reply_tokens: int = 8000
    """Room for reasoning tokens as well as the JSON answer."""
    timeout_seconds: float = 300.0

    def __post_init__(self) -> None:
        if not self.api_key:
            raise ConfigurationError(
                "OPENROUTER_API_KEY is required when MODEL_PROVIDER=openrouter"
            )
        if not self.model:
            raise ConfigurationError("OPENROUTER_MODEL is required when MODEL_PROVIDER=openrouter")
        if self.effort not in {"low", "medium", "high"}:
            raise ConfigurationError("OPENROUTER_EFFORT must be low, medium or high")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> OpenRouterConfig:
        try:
            max_tokens = int(env.get("OPENROUTER_MAX_TOKENS", "8000"))
        except ValueError as exc:
            raise ConfigurationError("OPENROUTER_MAX_TOKENS must be an integer") from exc
        return cls(
            api_key=env.get("OPENROUTER_API_KEY", "").strip(),
            model=env.get("OPENROUTER_MODEL", "").strip(),
            base_url=env.get("OPENROUTER_BASE_URL", DEFAULT_BASE_URL).strip().rstrip("/"),
            effort=env.get("OPENROUTER_EFFORT", "medium").strip().lower(),
            max_reply_tokens=max_tokens,
        )


class OpenRouterClient:
    def __init__(
        self,
        config: OpenRouterConfig,
        post: Post = _urllib,
        sleep: Callable[[float], None] = time.sleep,
        budget: float | None = None,
    ) -> None:
        self.config = config
        self._post = post
        self._sleep = sleep
        self._context = 128_000
        self._parameters: frozenset[str] = frozenset()
        self.price_in = 0.0
        """Listed USD per prompt token, from the model listing."""
        self.price_out = 0.0
        self.last_cost = 0.0
        """USD OpenRouter reported for the last request (`usage.cost`)."""
        self.budget = budget
        """USD this client may spend in all; None means no cap."""
        self.spent = 0.0
        """USD OpenRouter reported for every request so far."""

    @property
    def model(self) -> str:
        return self.config.model

    @property
    def num_ctx(self) -> int:
        return self._context

    @property
    def label(self) -> str:
        return f"{self.config.model} via OpenRouter (zero-retention routing)"

    def require_model(self) -> None:
        """Fail before the first case: the model must exist and take a JSON schema."""
        try:
            listing = json.loads(self._request(f"{self.config.base_url}/models", None))
        except ModelError as exc:
            raise ModelError(f"OpenRouter is not reachable ({exc})") from exc
        found = next(
            (item for item in listing.get("data", []) if item.get("id") == self.config.model), None
        )
        if found is None:
            raise ModelError(f"OpenRouter has no model {self.config.model}")
        self._parameters = frozenset(found.get("supported_parameters") or ())
        if "structured_outputs" not in self._parameters:
            raise ModelError(f"{self.config.model} does not support structured outputs")
        self._context = int(found.get("context_length") or self._context)
        pricing = found.get("pricing") or {}
        self.price_in = float(pricing.get("prompt") or 0)
        self.price_out = float(pricing.get("completion") or 0)

    def credits_remaining(self) -> float:
        """USD left on the account: purchased credits minus everything used so far."""
        data = json.loads(self._request(f"{self.config.base_url}/credits", None)).get("data", {})
        return float(data.get("total_credits") or 0) - float(data.get("total_usage") or 0)

    def worst_case_cost(self, prompt_chars: int) -> float:
        """An upper bound for one request: prompt tokens at chars/3, every reply token used."""
        return prompt_chars / 3 * self.price_in + self.config.max_reply_tokens * self.price_out

    def chat(self, messages: list[dict[str, str]]) -> Reply:
        parsed, raw, tokens, seconds = self.complete(messages, REPLY_SCHEMA)
        summary = parsed.get("summary")
        if not isinstance(summary, str) or not summary.strip():
            raise ModelError("the reply has no summary")
        return Reply(summary=summary.strip(), raw=raw, prompt_tokens=tokens, seconds=seconds)

    def complete(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> tuple[dict[str, Any], str, int, float]:
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_reply_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "reply", "strict": True, "schema": schema},
            },
            "provider": {"zdr": True, "data_collection": "deny", "require_parameters": True},
        }
        if "reasoning" in self._parameters:
            payload["reasoning"] = {"effort": self.config.effort}
        # Some models (current Claude) reject sampling settings; their samples differ through
        # their own reasoning instead.
        if "temperature" in self._parameters:
            payload["temperature"] = temperature
        if seed is not None and "seed" in self._parameters:
            payload["seed"] = seed
        if self.budget is not None:
            worst = self.worst_case_cost(sum(len(message["content"]) for message in messages))
            if self.spent + worst > self.budget:
                raise ModelError(
                    f"not sent: it could take the run past its ${self.budget:.2f} budget"
                )
        started = monotonic()
        data = json.loads(
            self._request(f"{self.config.base_url}/chat/completions", json.dumps(payload).encode())
        )
        self.last_cost = float((data.get("usage") or {}).get("cost") or 0)
        self.spent += self.last_cost
        if data.get("error"):
            raise ModelError(f"OpenRouter returned an error: {data['error'].get('message', '')}")
        choice = (data.get("choices") or [{}])[0]
        if choice.get("finish_reason") == "length":
            raise ModelError("the reply was cut off before it finished")
        content = str((choice.get("message") or {}).get("content") or "")
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise ModelError("the reply was not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ModelError("the reply was not a JSON object")
        usage = data.get("usage") or {}
        return parsed, content, int(usage.get("prompt_tokens") or 0), monotonic() - started

    def _request(self, url: str, body: bytes | None) -> bytes:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "X-Title": "ioc-report",
        }
        for attempt in range(RETRIES + 1):
            try:
                return self._post(url, body, headers, self.config.timeout_seconds)
            except urllib.error.HTTPError as exc:
                if exc.code not in RETRY_STATUSES or attempt == RETRIES:
                    raise ModelError(
                        f"OpenRouter answered HTTP {exc.code}: {_error_message(exc)}"
                    ) from None
                self._sleep(
                    _delay(exc.headers.get("Retry-After") if exc.headers else None, attempt)
                )
            except (OSError, http.client.HTTPException) as exc:
                if attempt == RETRIES:
                    raise ModelError(f"OpenRouter call failed ({exc.__class__.__name__})") from None
                self._sleep(_delay(None, attempt))
        raise AssertionError("unreachable")


def _error_message(exc: urllib.error.HTTPError) -> str:
    """OpenRouter's own explanation, such as no endpoint meeting the data policy."""
    try:
        body = json.loads(exc.read() or b"{}")
    except (OSError, ValueError):
        return "no detail"
    message = body.get("error", {}).get("message") if isinstance(body, dict) else None
    return str(message)[:300] if message else "no detail"


def _delay(retry_after: str | None, attempt: int) -> float:
    try:
        return min(float(retry_after), 60.0) if retry_after else min(2.0**attempt * 2, 60.0)
    except ValueError:
        return min(2.0**attempt * 2, 60.0)
