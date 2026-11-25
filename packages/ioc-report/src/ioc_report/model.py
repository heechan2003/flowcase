"""The model clients, local and remote, and the checks every piece of model text must pass.

The model decides nothing: code has already decided the disposition (`rules.py`) and the next
steps (`casefile.py`). The report's prose (`narrative.py`) and the blind shadow verdict
(`shadow.py`) are asked through these clients, and no unchecked text reaches the report.
"""

from __future__ import annotations

import http.client
import json
import re
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from time import monotonic
from typing import Any, Protocol
from urllib.parse import urlparse

from network_behaviour.config import ConfigurationError

from ioc_report.casefile import Observed

CONTEXT_MARGIN = 0.9
DEFAULT_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3:4b-instruct"
DEFAULT_NUM_CTX = 8192

REPLY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"summary": {"type": "string"}},
    "required": ["summary"],
    "additionalProperties": False,
}

_NUMBER = re.compile(r"\d+(?:,\d{3})*(?:\.\d+)?")
_HOST_STATE = re.compile(
    r"\b(compromised|infected|infection|backdoor(?:ed)?|pwned|breached|botnet member|"
    r"part of (?:a|the) botnet|under (?:the )?(?:attacker'?s?|remote) control)\b",
    re.IGNORECASE,
)
_HELD_OPEN_CLAIM = re.compile(
    r"\b(held[- ]open|kept open|long[- ]lived|persistent (?:connection|session))\b", re.IGNORECASE
)
_REGULAR_CLAIM = re.compile(
    r"\b(beacon\w*|heartbeat\w*|periodic\w*|check[- ]?ins?|on a schedule|"
    r"regular(?:ly)? (?:interval|schedule|contact)\w*|scheduled (?:contact|connection)s?)\b",
    re.IGNORECASE,
)
_SMALL_TRANSFER_CLAIM = re.compile(
    r"\b(page[- ]loads?|small (?:data )?transfers?|tiny transfers?|minimal data|"
    r"small amounts? of data)\b",
    re.IGNORECASE,
)
# A negation or an expectation in the claim's own clause means it is not a claim about what was
# observed. The clause is the scope, not the sentence and not a fixed window: models write "a page
# load, and no held-open connection", where the "no" must not excuse the "page load", and also
# "No long flows, held-open connections, or regular schedules were observed", where the "no"
# covers the whole list however long it is.
_HEDGE_WORDS = frozenset(
    {
        "no", "not", "none", "never", "without", "neither", "nor", "absent", "lack", "lacks",
        "lacking", "unlike", "rather", "instead", "than", "would", "typical", "typically",
        "usually", "expected", "expect", "expects", "if",
    }
)  # fmt: skip
_CLAUSE_BREAK = re.compile(
    r";|,\s*(?:and|but|which|while|whereas|so|yet|although|though)\b|"
    r"\s(?:but|however|whereas|although|though)\b",
    re.IGNORECASE,
)
_NEGATED_AFTER = re.compile(r"\b(?:not|never|absent|none)\b|n't\b|:\s*no\b", re.IGNORECASE)
# Threat labels may appear only as ThreatFox's claim about the indicator, never as a description
# of what this host did. A sentence that names ThreatFox or the indicator is attributing.
_THREAT_LABEL = re.compile(
    r"(?<!non-)(?<!non )"
    r"\b(command[- ]and[- ]control|c2|c&c|botnet|malicious|malware|payload[ _-]delivery)\b",
    re.IGNORECASE,
)
_ATTRIBUTION = re.compile(
    r"\b(threatfox|indicators?|flagged|lists?|listed|reported)\b", re.IGNORECASE
)
_CONFIDENCE_AS_EVIDENCE = re.compile(
    r"\bconfidence\b[^.;]*?\b(suggest\w*|indicat\w*|support\w*|warrant\w*|rais\w*|"
    r"increas\w*|impl\w*|point\w*)\b",
    re.IGNORECASE,
)


class ModelError(RuntimeError):
    """The model could not be reached or did not return a usable reply."""


@dataclass(frozen=True, slots=True)
class OllamaConfig:
    url: str = DEFAULT_URL
    model: str = DEFAULT_MODEL
    num_ctx: int = DEFAULT_NUM_CTX
    seed: int = 7
    max_reply_tokens: int = 700
    timeout_seconds: float = 300.0
    think: bool | None = None
    """Sent as Ollama's `think` option when set; a thinking model must be told false for JSON."""

    def __post_init__(self) -> None:
        if urlparse(self.url).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ConfigurationError(
                "OLLAMA_URL must be a loopback address: case files hold internal addresses"
            )
        if self.num_ctx <= 0:
            raise ConfigurationError("OLLAMA_NUM_CTX must be positive")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> OllamaConfig:
        try:
            num_ctx = int(env.get("OLLAMA_NUM_CTX", str(DEFAULT_NUM_CTX)))
        except ValueError as exc:
            raise ConfigurationError("OLLAMA_NUM_CTX must be an integer") from exc
        think = env.get("OLLAMA_THINK", "").strip().lower()
        if think not in {"", "true", "false"}:
            raise ConfigurationError("OLLAMA_THINK must be true or false")
        return cls(
            url=env.get("OLLAMA_URL", DEFAULT_URL).strip().rstrip("/"),
            model=env.get("OLLAMA_MODEL", DEFAULT_MODEL).strip(),
            num_ctx=num_ctx,
            think=None if not think else think == "true",
        )


Transport = Callable[[str, bytes | None, float], bytes]


class ModelClient(Protocol):
    """What the summary and the shadow verdict need from a model, wherever it runs."""

    @property
    def model(self) -> str: ...

    @property
    def num_ctx(self) -> int: ...

    @property
    def label(self) -> str: ...

    def require_model(self) -> None: ...

    def chat(self, messages: list[dict[str, str]]) -> Reply: ...

    def complete(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        temperature: float = 0.0,
        seed: int | None = None,
    ) -> tuple[dict[str, Any], str, int, float]: ...


def _http(url: str, body: bytes | None, timeout: float) -> bytes:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"} if body else {}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload: bytes = response.read()
        return payload


@dataclass(frozen=True, slots=True)
class Reply:
    summary: str
    raw: str
    prompt_tokens: int
    seconds: float

    @property
    def text(self) -> str:
        return self.summary


class OllamaClient:
    def __init__(self, config: OllamaConfig, transport: Transport = _http) -> None:
        self.config = config
        self._transport = transport

    @property
    def model(self) -> str:
        return self.config.model

    @property
    def num_ctx(self) -> int:
        return self.config.num_ctx

    @property
    def label(self) -> str:
        return f"{self.config.model} via local Ollama (num_ctx {self.config.num_ctx})"

    def require_model(self) -> None:
        """Fail before the first case, not halfway through the feed."""
        try:
            tags = json.loads(self._transport(f"{self.config.url}/api/tags", None, 10.0))
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ModelError(
                f"Ollama is not reachable at {self.config.url}; start it or run with --no-model"
            ) from exc
        pulled = {
            str(model.get(key)) for model in tags.get("models", []) for key in ("name", "model")
        }
        if self.config.model not in pulled:
            raise ModelError(
                f"model {self.config.model} is not pulled; run: ollama pull {self.config.model}"
            )

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
        """One schema-constrained reply: (parsed object, raw text, prompt tokens, seconds)."""
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "stream": False,
            "format": schema,
            "options": {
                "temperature": temperature,
                "seed": self.config.seed if seed is None else seed,
                "num_ctx": self.config.num_ctx,
                "num_predict": self.config.max_reply_tokens,
            },
        }
        if self.config.think is not None:
            payload["think"] = self.config.think
        started = monotonic()
        try:
            data = json.loads(
                self._transport(
                    f"{self.config.url}/api/chat",
                    json.dumps(payload).encode(),
                    self.config.timeout_seconds,
                )
            )
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ModelError(f"the model call failed ({exc.__class__.__name__})") from exc
        if data.get("error"):
            raise ModelError(f"Ollama returned an error: {data['error']}")
        if data.get("done_reason") == "length":
            raise ModelError("the reply was cut off before it finished")
        content = str(data.get("message", {}).get("content", ""))
        try:
            parsed = json.loads(content)
        except ValueError as exc:
            raise ModelError("the reply was not valid JSON") from exc
        if not isinstance(parsed, dict):
            raise ModelError("the reply was not a JSON object")
        return (
            parsed,
            content,
            int(data.get("prompt_eval_count") or 0),
            monotonic() - started,
        )


def check_reply(text: str, case_file: str, observed: Observed) -> list[str]:
    problems = []
    if numbers := unverified_numbers(text, case_file):
        problems.append("numbers that are not in the case file: " + ", ".join(numbers))
    if words := host_state_words(text):
        problems.append(
            "describes the host's state (" + ", ".join(words) + "); flow records cannot show that"
        )
    problems.extend(unsupported_shapes(text, observed))
    problems.extend(unattributed_labels(text))
    if confidence_as_evidence(text):
        problems.append(
            "treats ThreatFox confidence as evidence; it rates the indicator, not this host"
        )
    return problems


def unattributed_labels(text: str) -> list[str]:
    """Threat labels used for what the host did, rather than as ThreatFox's claim."""
    problems = []
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        if _ATTRIBUTION.search(sentence):
            continue
        for match in _THREAT_LABEL.finditer(sentence):
            if not _hedged(sentence, match.start(), match.end()):
                problems.append(
                    f"uses '{match.group(0)}' without attributing it to ThreatFox or the indicator"
                )
                break
    return problems


def confidence_as_evidence(text: str) -> bool:
    """Confidence followed by an inference in the same clause: "75% confidence, suggesting ..."."""
    return any(
        _CONFIDENCE_AS_EVIDENCE.search(clause)
        for sentence in re.split(r"(?<=[.!?])\s+", text)
        for clause in _CLAUSE_BREAK.split(sentence)
    )


def unverified_numbers(text: str, case_file: str) -> list[str]:
    """Numbers of two or more digits that the case file does not contain, allowing rounding."""
    known = {match.replace(",", "") for match in _NUMBER.findall(case_file)}
    unverified = set()
    for raw in _NUMBER.findall(text):
        value = raw.replace(",", "")
        if len(value.replace(".", "")) < 2 or value in known:
            continue
        places = len(value.partition(".")[2])
        if not any(f"{float(candidate):.{places}f}" == value for candidate in known):
            unverified.add(raw)
    return sorted(unverified)


def host_state_words(text: str) -> list[str]:
    return sorted({match.group(0).lower() for match in _HOST_STATE.finditer(text)})


def unsupported_shapes(text: str, observed: Observed) -> list[str]:
    """Affirmed shapes the measurements do not show.

    The case file sits next to a description of what an indicator's clients usually do; copying
    that expectation as an observation is the failure this catches.
    """
    claims = (
        (_HELD_OPEN_CLAIM, not observed.held_open, "no held-open connection was observed"),
        (_REGULAR_CLAIM, not observed.regular, "no regular schedule was observed"),
        (
            _SMALL_TRANSFER_CLAIM,
            observed.large_transfer,
            "a transfer of about 1 MB or more was seen",
        ),
    )
    problems = []
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        for pattern, unsupported, fact in claims:
            if not unsupported:
                continue
            for match in pattern.finditer(sentence):
                if not _hedged(sentence, match.start(), match.end()):
                    problems.append(f"says '{match.group(0)}' but {fact}")
                    break
    return problems


def _hedged(sentence: str, start: int, end: int) -> bool:
    clause_start = max((m.end() for m in _CLAUSE_BREAK.finditer(sentence, 0, start)), default=0)
    clause_end = next((m.start() for m in _CLAUSE_BREAK.finditer(sentence, end)), len(sentence))
    before = re.findall(r"[a-z']+", sentence[clause_start:start].lower())
    if any(word in _HEDGE_WORDS or word.endswith("n't") for word in before):
        return True
    return _NEGATED_AFTER.search(sentence, end, clause_end) is not None
