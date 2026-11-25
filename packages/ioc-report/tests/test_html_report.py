"""The HTML report: one self-contained page that escapes every value from the feed, the source and
the model, loads nothing from anywhere else, and shows each review case as an article with its
overview, its reasons and its evidence."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from ioc_report import html_report
from ioc_report.casefile import after_contact, next_steps, render_case_file
from ioc_report.digest import case_digest
from ioc_report.facts import case_facts
from ioc_report.narrative import NOT_WRITTEN, Narrative
from ioc_report.rules import decide
from ioc_report.summary import CaseResult
from tests.builders import SKIPPED, evidence
from tests.test_facts import VERDICT_WORDS, Shaped, shaped

GENERATED = datetime(2026, 10, 22, 1, 0, tzinfo=UTC)
DISCLAIMER = "No case says a host is compromised, infected or benign"


def _page(case: Shaped, overview: Narrative = NOT_WRITTEN) -> str:
    evidence, decision = case.evidence, case.decision
    result = CaseResult(
        evidence,
        decision,
        render_case_file(evidence, decision, case.live, case.history),
        overview,
        next_steps(evidence, decision, after_contact(evidence, case.live, case.history)),
        digest=case_digest(evidence, decision, case.live, case.history),
    )
    facts = case_facts(evidence, decision, case.live, case.history)
    return html_report.render(
        "synthetic", case.feed, [result], [facts], case.live, case.history, "test", GENERATED
    )


def test_feed_source_and_model_strings_are_escaped(tmp_path: Path) -> None:
    case = shaped(
        tmp_path,
        lead_in=("<script>alert(1)</script>", 'x" onmouseover="alert(2)'),
        next_new="<img src=x onerror=alert(3)>",
    )
    written = Narrative("model", {"threat": "<b>bold</b> & 'quoted' </blockquote>"})

    page = _page(case, written)

    assert page.count("<script>") == 1
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    assert 'onmouseover="alert(2)' not in page and "x&quot; onmouseover=&quot;alert(2)" in page
    assert "<img src=x" not in page and "&lt;img src=x onerror=alert(3)&gt;" in page
    assert "<b>bold</b>" not in page and "&lt;b&gt;bold&lt;/b&gt; &amp; &#x27;quoted&#x27;" in page


def test_the_page_loads_nothing_and_carries_its_marking(tmp_path: Path) -> None:
    page = _page(shaped(tmp_path))

    assert "Content-Security-Policy" in page and "default-src 'none'" in page
    assert "Sensitive · internal use only" in page
    assert not re.findall(r"<[a-z]+[^>]*\ssrc\s*=", page)
    hrefs = re.findall(r"""<a\s[^>]*href\s*=\s*['"]([^'"]*)""", page)
    assert hrefs and all(href.startswith("#") for href in hrefs)
    ids = set(re.findall(r"""\sid\s*=\s*['"]([^'"]+)""", page))
    assert {href[1:] for href in hrefs} <= ids
    assert not re.findall(r"""=\s*['"]?https?:""", page)


def test_a_review_case_is_an_article_with_its_index_row_and_filters(tmp_path: Path) -> None:
    page = _page(shaped(tmp_path))

    assert page.count('<article class="case card"') == 1
    assert "href='#case-1'" in page and 'id="case-1"' in page
    filters = set(re.findall(r'data-filter="([^"]+)"', page))
    assert filters == {"all", "review", "caveated", "checked"}
    kinds = {
        token
        for value in re.findall(r"""data-kind=['"]([^'"]+)""", page)
        for token in value.split()
    }
    assert kinds <= filters - {"all"}


def test_the_overview_leads_the_card_and_the_digest_keeps_every_fact(tmp_path: Path) -> None:
    page = _page(shaped(tmp_path))
    article = page[page.index('<article class="case card"') :]

    assert article.index("<h4>Overview</h4>") < article.index("Why code kept it for review")
    for part in ("Threat", "Host", "What happened", "How to read it"):
        assert f"<dt>{part}</dt>" in article
    assert "[Live source] Just before the contact" in article
    assert "natureland.example, 1.0 min later" in article
    assert "Next steps: what only other systems can settle" in article
    assert "Device: who held the address" in article


def test_charts_are_drawn_with_labels_and_a_table_twin(tmp_path: Path) -> None:
    page = _page(shaped(tmp_path))

    assert page.count('<svg class="chart"') == 2
    assert page.count('<details class="figure-data"><summary>Table</summary>') == 2
    assert "class='mark s1'" in page and "data-tip='1 · flagged address" in page
    assert "class='mark silent'" in page and ">match</text>" in page
    assert "<title>1 · new to this host after the match · 2026-10-15</title>" in page


def test_without_live_data_there_are_no_charts(tmp_path: Path) -> None:
    case = shaped(tmp_path)
    found = evidence(case.feed, case.evidence.case)
    decision = decide(found, case.feed.domain_indicators)
    page = _page(Shaped(case.feed, found, decision, SKIPPED, case.history))

    assert "<svg" not in page
    assert "No minute detail around the contact" in page
    assert "After the contact</h3><p class='muted'>Not read" in page


def test_no_verdict_words_beyond_the_disclaimer(tmp_path: Path) -> None:
    page = _page(shaped(tmp_path))
    text = page.replace(DISCLAIMER, "").lower()

    assert DISCLAIMER in page
    assert not [word for word in VERDICT_WORDS if word in text]


def test_dates_are_kept_whole_without_reopening_escaped_text() -> None:
    assert html_report.prose("<b>2026-10-15 03:06</b> & 2026-10-16") == (
        "&lt;b&gt;<span class='nowrap'>2026-10-15 03:06</span>&lt;/b&gt; &amp; "
        "<span class='nowrap'>2026-10-16</span>"
    )
