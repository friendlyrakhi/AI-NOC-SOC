"""Deterministic, citation-aware mock model (the default provider).

It builds every claim from structured evidence fields and cites the items it used, so the
whole pipeline (evidence -> prompt -> structured output -> validation -> UI citations) is
exercised without any model. It never echoes text from items flagged as suspicious, and it
never invents an action outside the allowed list. Output is labelled "mock" everywhere.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal

from ai_gateway.providers.base import ProviderResult
from ai_gateway.schemas import AiOutput, Claim, EvidenceItem, GenerateRequest, SuggestedAction, SuggestedQuery

MODEL = "mock-v1"
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
WITHHELD = "[instruction-like text withheld]"


def _t(e: EvidenceItem, limit: int = 140) -> str:
    title = WITHHELD if e.suspicious else e.title
    return title if len(title) <= limit else title[: limit - 1] + "…"


def _a(e: EvidenceItem, key: str, default: str = "unknown") -> str:
    value = e.attributes.get(key)
    if value in (None, "", []):
        return default
    return ", ".join(map(str, value)) if isinstance(value, list) else str(value)


def _by_severity(items: Iterable[EvidenceItem]) -> list[EvidenceItem]:
    return sorted(items, key=lambda e: (SEVERITY_RANK.get(e.severity or "info", 5), e.at or "", e.ref))


def _of(req: GenerateRequest, *types: str) -> list[EvidenceItem]:
    return [e for e in req.evidence if e.type in types]


def _common(req: GenerateRequest, claims: list[Claim], gaps: list[str]) -> None:
    suspicious = [e.ref for e in req.evidence if e.suspicious]
    if suspicious:
        claims.append(
            Claim(
                text=f"{len(suspicious)} evidence item(s) contain instruction-like text. They were treated as data "
                "only; review them before acting on this analysis.",
                citations=suspicious[:10],
            )
        )
    runbooks = _of(req, "runbook")
    if runbooks:
        claims.append(
            Claim(
                text="Relevant runbook guidance: " + "; ".join(_t(r, 80) for r in runbooks[:3]) + ".",
                citations=[r.ref for r in runbooks[:3]],
            )
        )
    else:
        gaps.append("No runbook matched this subject.")


def _alert_summary(req: GenerateRequest) -> AiOutput:
    alerts = _of(req, "alert")
    claims: list[Claim] = []
    gaps: list[str] = []
    if not alerts:
        return AiOutput(gaps=["The alert itself was not available as evidence."])
    main, related = alerts[0], alerts[1:]
    claims.append(
        Claim(
            text=f'{(main.severity or "unknown").capitalize()} {_a(main, "domain").upper()} alert "{_t(main)}" from '
            f"{_a(main, 'connector')} on {_a(main, 'asset')}, seen {_a(main, 'occurrences', '1')} time(s); "
            f"status {_a(main, 'status')}.",
            citations=[main.ref],
        )
    )
    if main.attributes.get("mitre"):
        claims.append(Claim(text=f"Mapped ATT&CK techniques: {_a(main, 'mitre')}.", citations=[main.ref]))
    for inc in _of(req, "incident")[:1]:
        claims.append(
            Claim(
                text=f"Part of incident {_a(inc, 'number')} ({_a(inc, 'status')}, {_a(inc, 'priority')}).",
                citations=[inc.ref],
            )
        )
    if related:
        top = _by_severity(related)[:4]
        claims.append(
            Claim(
                text=f"{len(related)} other recent alert(s) on the same asset, most severe: "
                + "; ".join(f'"{_t(r, 70)}" ({r.severity})' for r in top)
                + ".",
                citations=[r.ref for r in top],
            )
        )
    else:
        gaps.append("No other recent alerts on this asset.")
    _common(req, claims, gaps)
    return AiOutput(claims=claims, gaps=gaps, confidence=0.7 if related else 0.55)


def _incident_summary(req: GenerateRequest) -> AiOutput:
    incs = _of(req, "incident")
    if not incs:
        return AiOutput(gaps=["The incident itself was not available as evidence."])
    inc = incs[0]
    alerts = _by_severity(_of(req, "alert"))
    claims = [
        Claim(
            text=f"Incident {_a(inc, 'number')} is a {_a(inc, 'priority')} {_a(inc, 'domain').upper()} incident, "
            f"currently {_a(inc, 'status')}, impacting {_a(inc, 'services', 'no identified service')}.",
            citations=[inc.ref],
        )
    ]
    gaps: list[str] = []
    if alerts:
        sources = sorted({_a(a, "connector") for a in alerts})
        claims.append(
            Claim(
                text=f"{len(alerts)} correlated alert(s) from {', '.join(sources)}; most severe: "
                + "; ".join(f'"{_t(a, 70)}" on {_a(a, "asset")}' for a in alerts[:3])
                + ".",
                citations=[a.ref for a in alerts[:5]],
            )
        )
        domains = {_a(a, "domain") for a in alerts}
        if {"noc", "soc"} <= domains:
            soc = [a.ref for a in alerts if _a(a, "domain") == "soc"][:2]
            noc = [a.ref for a in alerts if _a(a, "domain") == "noc"][:2]
            claims.append(
                Claim(
                    text="Both operational and security signals are present, so this needs NOC and SOC.",
                    citations=soc + noc,
                )
            )
    else:
        gaps.append("No alerts are linked to this incident.")
    comments = [e for e in _of(req, "timeline") if _a(e, "kind") == "comment"]
    if comments:
        claims.append(
            Claim(
                text=f"{len(comments)} analyst comment(s) recorded on the timeline.",
                citations=[c.ref for c in comments[:3]],
            )
        )
    _common(req, claims, gaps)
    return AiOutput(claims=claims, gaps=gaps, confidence=0.75 if alerts else 0.4)


def _triage(req: GenerateRequest) -> AiOutput:
    alerts = _by_severity(_of(req, "alert"))
    if not alerts:
        return AiOutput(gaps=["No alerts to triage."])
    serious = [a for a in alerts if a.severity in ("critical", "high")]
    mapped = [a for a in serious if a.attributes.get("mitre")]
    claims: list[Claim] = []
    gaps: list[str] = []
    if mapped:
        claims.append(
            Claim(
                text=f"Likely true positive: {len(mapped)} high-severity alert(s) map to ATT&CK techniques "
                f"({', '.join(sorted({t for a in mapped for t in a.attributes.get('mitre', [])}))}).",
                citations=[a.ref for a in mapped[:5]],
            )
        )
    elif serious:
        claims.append(
            Claim(
                text=f"Needs review: {len(serious)} high-severity alert(s) without technique mapping.",
                citations=[a.ref for a in serious[:5]],
            )
        )
    else:
        claims.append(
            Claim(text="Low urgency: no high-severity alerts in scope.", citations=[a.ref for a in alerts[:3]])
        )
    gaps.append("No threat-intelligence enrichment is available yet; verdict is based on alert content only.")
    actions: list[SuggestedAction] = []
    if serious and req.allowed_actions:
        key = sorted(req.allowed_actions)[0]
        actions.append(
            SuggestedAction(
                action_key=key,
                rationale="Suggested for analyst review because of the high-severity evidence cited. "
                "Requires approval.",
                citations=[a.ref for a in serious[:3]],
            )
        )
    _common(req, claims, gaps)
    return AiOutput(claims=claims, gaps=gaps, confidence=0.65 if mapped else 0.45, suggested_actions=actions)


def _rca(req: GenerateRequest) -> AiOutput:
    alerts = [a for a in _of(req, "alert") if a.at]
    if not alerts:
        return AiOutput(gaps=["Not enough timed alerts to form a root-cause hypothesis."])
    first = min(alerts, key=lambda a: (a.at or "", a.ref))
    claims = [
        Claim(
            text=f'Earliest signal: "{_t(first)}" on {_a(first, "asset")} at {first.at} from {_a(first, "connector")}.',
            citations=[first.ref],
        )
    ]
    gaps = ["No change records are available to confirm or rule out a recent change."]
    services = _of(req, "service")
    deps = [s for s in services if _a(first, "asset") in s.attributes.get("dependencies", [])]
    if deps:
        claims.append(
            Claim(
                text=f"Hypothesis: {_a(first, 'asset')} is shared infrastructure for "
                f"{', '.join(_t(s, 40) for s in deps)}; "
                "later alerts on dependent hosts are consistent with an upstream failure.",
                citations=[first.ref, *[s.ref for s in deps[:3]]],
            )
        )
        confidence = 0.6
    else:
        claims.append(
            Claim(
                text="Hypothesis: the earliest alerting asset is the most likely origin; topology does not confirm it.",
                citations=[first.ref],
            )
        )
        gaps.append("No service topology links the earliest asset to the others.")
        confidence = 0.35
    later = [a for a in alerts if a.ref != first.ref][:4]
    if later:
        claims.append(
            Claim(text=f"{len(later)} later alert(s) follow on related assets.", citations=[a.ref for a in later])
        )
    _common(req, claims, gaps)
    return AiOutput(claims=claims, gaps=gaps, confidence=confidence)


def _pir(req: GenerateRequest) -> AiOutput:
    out = _incident_summary(req)
    timeline = [e for e in _of(req, "timeline") if e.at]
    claims = list(out.claims)
    if timeline:
        first, last = min(timeline, key=lambda e: e.at or ""), max(timeline, key=lambda e: e.at or "")
        claims.insert(
            1,
            Claim(
                text=f"Timeline: first entry {first.at}, latest entry {last.at} ({len(timeline)} entries).",
                citations=[first.ref, last.ref],
            ),
        )
    gaps = [*out.gaps, "Customer impact and business cost must be added by the incident commander."]
    return AiOutput(claims=claims, gaps=gaps, confidence=min(out.confidence, 0.6))


_WORDS = re.compile(r"[a-z0-9][a-z0-9.\-]+")
_STOP = frozenset(
    [
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "has",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "was",
        "were",
        "with",
        "what",
        "which",
        "show",
        "me",
        "all",
        "any",
    ]
)


def _query(req: GenerateRequest) -> AiOutput:
    q = (req.question or "").lower()
    severities = [s for s in ("critical", "high", "medium", "low") if s in q]
    statuses = [s for s in ("new", "acknowledged", "suppressed", "resolved") if s in q]
    domain = (
        "soc"
        if re.search(r"\b(soc|security|phish|malware|edr)\b", q)
        else "noc"
        if re.search(r"\b(noc|network|server|cpu|disk|latency)\b", q)
        else ""
    )
    connectors = [
        "splunk",
        "wazuh",
        "datadog",
        "prometheus",
        "sentinel",
        "defender",
        "crowdstrike",
        "cloudwatch",
        "solarwinds",
    ]
    connector = next((c for c in connectors if c in q), "")
    used = set(
        severities + statuses + [domain, connector, "alerts", "alert", "incidents", "incident", "security", "network"]
    )
    rest = [w for w in _WORDS.findall(q) if w not in _STOP and w not in used][:3]
    target: Literal["alerts", "incidents", "events"] = "incidents" if "incident" in q else "alerts"
    query = SuggestedQuery(
        target=target,
        filters={
            "severity": severities,
            "status": statuses,
            "domain": domain,
            "connector": connector,
            "q": " ".join(rest),
        },
        explanation="Suggested filters derived from your request. Review them before running the search.",
    )
    gaps = (
        []
        if (severities or statuses or domain or connector or rest)
        else ["The request named no filter I could recognise."]
    )
    return AiOutput(query=query, gaps=gaps, confidence=0.6 if not gaps else 0.2)


def _chat(req: GenerateRequest) -> AiOutput:
    words = {w for w in _WORDS.findall((req.question or "").lower()) if w not in _STOP}
    scored = []
    for e in req.evidence:
        if e.suspicious:
            continue
        hay = f"{e.title} {e.text} {' '.join(map(str, e.attributes.values()))}".lower()
        score = sum(1 for w in words if w in hay)
        if score:
            scored.append((score, e))
    scored.sort(key=lambda s: (-s[0], s[1].ref))
    if not scored:
        return AiOutput(gaps=["The evidence for this subject does not answer the question."], confidence=0.0)
    claims = [
        Claim(
            text=f'{e.type.capitalize()} "{_t(e)}"' + (f" ({e.severity})" if e.severity else "") + " is relevant.",
            citations=[e.ref],
        )
        for _, e in scored[:4]
    ]
    return AiOutput(claims=claims, gaps=["Answer assembled from matching evidence only."], confidence=0.5)


def _fmt_kpi(e: EvidenceItem) -> str:
    unit, value = _a(e, "unit"), e.attributes.get("value")
    if value is None:
        return "not available"
    if unit == "ratio":
        return f"{float(value) * 100:.0f}%"
    if unit == "seconds":
        minutes = float(value) / 60
        return f"{minutes:.0f} min" if minutes < 120 else f"{minutes / 60:.1f} h"
    return f"{float(value):.0f}"


def _briefing(req: GenerateRequest) -> AiOutput:
    kpis = {_a(e, "key"): e for e in _of(req, "kpi") if not e.suspicious}
    incidents = [e for e in _of(req, "incident") if not e.suspicious]
    alerts = _by_severity(e for e in _of(req, "alert") if not e.suspicious)
    claims: list[Claim] = []
    gaps: list[str] = []
    if not (kpis or incidents or alerts):
        return AiOutput(gaps=["No KPIs, incidents or alerts were available for the briefing period."])
    if "incidents_opened" in kpis:
        opened, still = kpis["incidents_opened"], kpis.get("open_incidents")
        text = f"In the last 24 hours {_fmt_kpi(opened)} incident(s) were opened"
        cites = [opened.ref]
        if still is not None:
            text += f"; {_fmt_kpi(still)} of them are still open"
            cites.append(still.ref)
        claims.append(Claim(text=text + ".", citations=cites))
    timing = [kpis[k] for k in ("mtta", "mttr") if k in kpis and kpis[k].attributes.get("value") is not None]
    if timing:
        claims.append(
            Claim(
                text="Response times: " + ", ".join(f"{_a(k, 'label')} {_fmt_kpi(k)}" for k in timing) + ".",
                citations=[k.ref for k in timing],
            )
        )
    sla = [kpis[k] for k in ("ack_sla", "resolve_sla") if k in kpis and kpis[k].attributes.get("value") is not None]
    if sla:
        claims.append(
            Claim(
                text="SLA attainment: " + ", ".join(f"{_a(k, 'label')} {_fmt_kpi(k)}" for k in sla) + ".",
                citations=[k.ref for k in sla],
            )
        )
    elif kpis:
        gaps.append("No SLA outcome was decided in the period yet.")
    if "alert_volume" in kpis:
        vol, noise = kpis["alert_volume"], kpis.get("noise_ratio")
        text = f"{_fmt_kpi(vol)} alert(s) arrived"
        cites = [vol.ref]
        if noise is not None and noise.attributes.get("value") is not None:
            text += f", and {_fmt_kpi(noise)} of them were not escalated to an incident"
            cites.append(noise.ref)
        claims.append(Claim(text=text + ".", citations=cites))
    if not kpis:
        gaps.append("Analytics were not available, so the briefing has no KPIs.")
    if incidents:
        top = incidents[:3]
        claims.append(
            Claim(
                text=f"{len(incidents)} priority incident(s) are open; most urgent: "
                + "; ".join(f"{_a(i, 'number')} ({_a(i, 'priority')}, {_a(i, 'status')}) {_t(i, 80)}" for i in top)
                + ".",
                citations=[i.ref for i in top],
            )
        )
    else:
        gaps.append("No P1 or P2 incident is open.")
    if alerts:
        claims.append(
            Claim(
                text=f"{len(alerts)} notable alert(s) are not in an incident yet, e.g. "
                + "; ".join(f'"{_t(a, 70)}" on {_a(a, "asset")}' for a in alerts[:3])
                + ".",
                citations=[a.ref for a in alerts[:3]],
            )
        )
    suspicious = [e.ref for e in req.evidence if e.suspicious]
    if suspicious:
        claims.append(
            Claim(
                text=f"{len(suspicious)} evidence item(s) contain instruction-like text and were treated as data only.",
                citations=suspicious[:10],
            )
        )
    return AiOutput(claims=claims, gaps=gaps, confidence=0.8 if kpis else 0.5)


TASKS = {
    "alert_summary": _alert_summary,
    "incident_summary": _incident_summary,
    "triage": _triage,
    "rca": _rca,
    "pir_draft": _pir,
    "query_assist": _query,
    "chat": _chat,
    "daily_briefing": _briefing,
}


class MockProvider:
    name = "mock"

    async def generate(self, req: GenerateRequest, system: str, user: str) -> ProviderResult:
        output = TASKS[req.task](req)
        # Token counts approximate a real tokenizer (4 chars per token) so budgets are exercised.
        out_chars = len(output.model_dump_json())
        return ProviderResult(
            output=output, model=MODEL, tokens_in=(len(system) + len(user)) // 4, tokens_out=out_chars // 4
        )
