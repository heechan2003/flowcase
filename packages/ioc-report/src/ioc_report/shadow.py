"""A blind second opinion from the local model, recorded beside the code's decision, never applied.

The model reads the case file with the decision and every per-contact rule outcome removed, and
says `review` or `explained`. It is sampled several times at a non-zero temperature with different
seeds, so the report can tell a stable opinion from a coin toss. Nothing here changes a
disposition: shadow verdicts exist to find where the rules and a reader of the same facts part
company, so an analyst can label those cases.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass
from typing import Any

from ioc_report.model import ModelClient, ModelError

VERDICTS = ("review", "explained")
SHADOW_TEMPERATURE = 0.7
SHADOW_SEEDS = (11, 23, 37, 53, 71)

SHADOW_PROMPT = """\
You help a network security analyst on a university campus network triage one ThreatFox IOC match. \
A match says an internal host contacted an address or domain that ThreatFox lists. You get one \
case file: facts measured from network flow records, one per line, each naming its source. Decide \
whether the match needs the analyst's review, by the policy below.

Policy:
1. Use only the facts in the case file, plus rule 3's one allowance.
2. "explained" requires that every contact the host made with the flagged address or domain (each \
contact line, and each long-flow line) has one of these ordinary reasons:
   a. The listed malware family's command-and-control channel could not have produced it: for \
example UDP when the channel is TCP only, or TLS or an Encrypted Client Hello name when the \
channel carries no TLS and the family is a native program. This reason applies only when the \
threat type is botnet_cc: a payload_delivery listing names a download server, whose protocol says \
nothing about the family. A TLS name does not give this reason when the name is chosen by whoever \
runs it (a dynamic-DNS or tunnel name), has no registered domain, is under the flagged domain, is \
another indicator, or was registered less than 32 days before the first match (the case file says \
so when its registration was looked up): the operator could be behind that site too. A \
registration date that is unknown or was not looked up does not take this reason away.
   b. An established site: the contact's SNI names a site the case file marks as established \
(used by many campus addresses on many days before the match), the flagged address is in a \
network the case file shows that site being served from, and the case file marks the address as \
shared hosting. One tenant of a shared platform (such as a *.workers.dev name), a dynamic-DNS name \
and a tunnel name are never established sites.
   c. The host's own tunnel client on the tunnel service's client port.
   d. The host sent nothing: inbound traffic it did not answer.
   A long flow is explained when the contacts it overlaps are explained.
3. If the case file has no profile for the family, you may use well-established public knowledge \
of that family's command-and-control transport for reason 2a, and must say so in your reasoning. \
If you do not know the family, reason 2a is unavailable.
4. Choose "review", whatever else holds, when any of these is true:
   - the indicator is a domain and the host's own traffic named it (a visit to a lure or payload \
site), unless it was the host's own tunnel client on the client port. A name that merely appears \
on a flagged address is not the flagged domain;
   - a tunnel service was reached on a port other than its client port;
   - the published triage stream has an episode on the flagged domain or address itself;
   - a contact is scheduled and low-volume (the case file says "scheduled low-volume" or "beacon \
shape"), unless reason 2b or 2c explains it;
   - the threat type is payload_delivery and a transfer of 1 MB or more is not explained by 2b.
5. A source that was expired, not retained, never published, not queried or unavailable is missing \
data, not absence of activity. Missing data never explains a contact.
6. ThreatFox confidence rates the indicator, not this host. Lines marked "background not \
evidence" describe the family in general, never this host.
7. Never say the host is compromised, infected or benign.

Reply as JSON: "reasoning" (at most three sentences naming the facts your choice rests on), then \
"verdict" ("review" or "explained")."""

SHADOW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "reasoning": {"type": "string"},
        "verdict": {"type": "string", "enum": list(VERDICTS)},
    },
    "required": ["reasoning", "verdict"],
    "additionalProperties": False,
}


PROMPT_VERSION = hashlib.sha256(
    (SHADOW_PROMPT + json.dumps(SHADOW_SCHEMA, sort_keys=True)).encode()
).hexdigest()[:12]
"""Recorded with every shadow verdict. A changed prompt is a new version, evaluated from scratch."""


@dataclass(frozen=True, slots=True)
class ShadowSample:
    seed: int
    verdict: str
    reasoning: str


@dataclass(frozen=True, slots=True)
class ShadowVerdict:
    model: str
    samples: tuple[ShadowSample, ...]
    errors: tuple[str, ...]
    seconds: float
    prompt_tokens: int

    @property
    def majority(self) -> str | None:
        """The verdict more than half of all requested samples gave, else None."""
        counts = Counter(sample.verdict for sample in self.samples)
        requested = len(self.samples) + len(self.errors)
        for verdict, count in counts.items():
            if count * 2 > requested:
                return verdict
        return None

    @property
    def unanimous(self) -> bool:
        return not self.errors and len({sample.verdict for sample in self.samples}) == 1

    def agrees(self, disposition: str) -> bool | None:
        majority = self.majority
        return None if majority is None else majority == disposition


def shadow_verdict(case_file: str, client: ModelClient, samples: int) -> ShadowVerdict:
    if not 1 <= samples <= len(SHADOW_SEEDS):
        raise ValueError(f"shadow samples must be between 1 and {len(SHADOW_SEEDS)}")
    messages = [
        {"role": "system", "content": SHADOW_PROMPT},
        {"role": "user", "content": case_file},
    ]
    found: list[ShadowSample] = []
    errors: list[str] = []
    seconds = 0.0
    tokens = 0
    for seed in SHADOW_SEEDS[:samples]:
        try:
            parsed, _raw, prompt_tokens, elapsed = client.complete(
                messages, SHADOW_SCHEMA, temperature=SHADOW_TEMPERATURE, seed=seed
            )
        except ModelError as exc:
            errors.append(str(exc))
            continue
        seconds += elapsed
        tokens = max(tokens, prompt_tokens)
        verdict, reasoning = parsed.get("verdict"), parsed.get("reasoning")
        if verdict not in VERDICTS or not isinstance(reasoning, str):
            errors.append("the reply had no usable verdict")
            continue
        found.append(ShadowSample(seed, str(verdict), reasoning.strip()))
    return ShadowVerdict(client.model, tuple(found), tuple(errors), seconds, tokens)
