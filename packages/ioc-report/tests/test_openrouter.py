from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Mapping
from email.message import Message
from pathlib import Path
from typing import Any

import pytest
from network_behaviour.config import ConfigurationError

from ioc_report import cli
from ioc_report.cli import main, pseudonymise
from ioc_report.model import ModelError
from ioc_report.openrouter import OpenRouterClient, OpenRouterConfig
from ioc_report.shadow import SHADOW_SCHEMA
from tests.builders import load
from tests.conftest import FIXTURES, minute_row, record

CONFIG = OpenRouterConfig(api_key="test-key", model="openai/gpt-oss-120b")


def _listing(parameters: list[str]) -> bytes:
    model = {
        "id": CONFIG.model,
        "supported_parameters": parameters,
        "context_length": 131_072,
        "pricing": {"prompt": "0.0000001", "completion": "0.0000005"},
    }
    return json.dumps({"data": [model]}).encode()


def _reply(content: dict[str, Any], cost: float = 0.0) -> bytes:
    return json.dumps(
        {
            "choices": [{"message": {"content": json.dumps(content)}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 2100, "cost": cost},
        }
    ).encode()


class _Post:
    def __init__(self, replies: list[bytes | Exception]) -> None:
        self.replies = iter(replies)
        self.calls: list[tuple[str, dict[str, Any] | None, Mapping[str, str]]] = []

    def __call__(
        self, url: str, body: bytes | None, headers: Mapping[str, str], timeout: float
    ) -> bytes:
        self.calls.append((url, json.loads(body) if body else None, headers))
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        return reply


def _http_error(code: int, message: str = "") -> urllib.error.HTTPError:
    body = io.BytesIO(json.dumps({"error": {"message": message}}).encode())
    return urllib.error.HTTPError("https://x", code, "error", Message(), body)


def test_requests_demand_zero_retention_and_a_strict_schema() -> None:
    post = _Post(
        [
            _listing(["structured_outputs", "temperature", "seed"]),
            _reply({"verdict": "review", "reasoning": "r"}),
        ]
    )
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None)

    client.require_model()
    parsed, _raw, tokens, _seconds = client.complete(
        [{"role": "user", "content": "x"}], SHADOW_SCHEMA, temperature=0.7, seed=11
    )

    _url, payload, headers = post.calls[1]
    assert payload is not None
    assert payload["provider"] == {
        "zdr": True,
        "data_collection": "deny",
        "require_parameters": True,
    }
    assert payload["response_format"]["json_schema"]["strict"] is True
    assert (payload["temperature"], payload["seed"]) == (0.7, 11)
    assert headers["Authorization"] == "Bearer test-key"
    assert (parsed["verdict"], tokens, client.num_ctx) == ("review", 2100, 131_072)
    assert "test-key" not in repr(CONFIG)


def test_sampling_settings_are_left_out_where_the_model_refuses_them() -> None:
    post = _Post([_listing(["structured_outputs"]), _reply({"summary": "s"})])
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None)
    client.require_model()

    client.chat([{"role": "user", "content": "x"}])

    payload = post.calls[1][1]
    assert payload is not None and "temperature" not in payload and "seed" not in payload


def test_rate_limits_are_retried_and_policy_failures_explained() -> None:
    post = _Post([_http_error(429), _reply({"summary": "s"})])
    slept: list[float] = []
    assert OpenRouterClient(CONFIG, post, sleep=slept.append).chat([]).summary == "s"
    assert slept == [2.0]

    post = _Post([_http_error(404, "No endpoints found matching your data policy")])
    with pytest.raises(ModelError, match="data policy"):
        OpenRouterClient(CONFIG, post, sleep=lambda _: None).chat([])


def test_a_request_that_could_pass_the_budget_is_never_sent() -> None:
    # Each request's worst case is about $0.004: every one of its 8,000 reply tokens used.
    post = _Post([_listing(["structured_outputs"]), _reply({"summary": "s"}, cost=0.003)])
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None, budget=0.006)
    client.require_model()

    client.chat([{"role": "user", "content": "x"}])
    with pytest.raises(ModelError, match="budget"):
        client.chat([{"role": "user", "content": "x"}])

    assert (len(post.calls), client.spent) == (2, 0.003)


def test_an_openrouter_run_needs_a_budget_the_credit_covers(
    tmp_path: Path, store_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NETWORK_BEHAVIOUR_DUCKDB_PATH", str(store_path))
    monkeypatch.setenv("MODEL_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    monkeypatch.setenv("OPENROUTER_MODEL", CONFIG.model)
    feed = str(FIXTURES / "ioc_matches_synthetic.json")
    assert main([feed, "--no-live"]) == 2

    credits = json.dumps({"data": {"total_credits": 5.0, "total_usage": 4.95}}).encode()
    post = _Post([_listing(["structured_outputs"]), credits])
    client = OpenRouterClient(CONFIG, post, sleep=lambda _: None, budget=0.10)
    monkeypatch.setattr(cli, "_model_client", lambda env, budget: client)

    assert main([feed, "--no-live", "--budget", "0.10"]) == 2
    assert [url.rsplit("/", 1)[1] for url, _body, _headers in post.calls] == ["models", "credits"]
    assert not (tmp_path / "output").exists()


def test_a_model_without_structured_outputs_is_refused_before_any_case() -> None:
    client = OpenRouterClient(CONFIG, _Post([_listing(["temperature"])]), sleep=lambda _: None)
    with pytest.raises(ModelError, match="structured outputs"):
        client.require_model()
    with pytest.raises(ConfigurationError, match="OPENROUTER_API_KEY"):
        OpenRouterConfig.from_env({"OPENROUTER_MODEL": "x"})


def test_the_internal_host_never_reaches_the_model(tmp_path: Path) -> None:
    _feed, case = load(tmp_path, [record([minute_row("2026-09-15 10:00:00")], host="192.0.2.10")])

    text = pseudonymise(f"Host: {case.host}. Pair {case.source_host} 1.1.1.1.", case)

    assert "192.0.2.10" not in text and text == "Host: HOST. Pair HOST 1.1.1.1."
