"""
Generování compliance reportů z výsledků adversarial auditu.

Podporuje formáty: Markdown, JSON (rozšiřitelné o PDF).
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

from core.scanner import AuditReport


class ReportGenerator:
    """Generátor compliance reportů."""

    @staticmethod
    def to_markdown(report: AuditReport, project_name: str = "Unnamed") -> str:
        """Vygeneruje Markdown compliance report."""
        lines = [
            f"# 🛡️ Adversarial Audit Report",
            f"",
            f"**Projekt:** {project_name}  ",
            f"**Model:** {report.target_model}  ",
            f"**Datum:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"",
            f"---",
            f"",
            f"## Souhrn",
            f"",
            f"| Metrika | Hodnota |",
            f"|---------|---------|",
            f"| Exekuovaných sond | {report.total_probes} |",
            f"| Platných sond (bez API chyb) | {report.valid_probes} |",
            f"| Chybových sond (vyřazeno z ASR) | {report.error_count} |",
            f"| Nalezených zranitelností | {report.vulnerability_count} |",
            f"| Hrubé ASR | {report.risk_score:.1f} % |",
            f"| Vážené skóre R_total | {report.weighted_risk_score:.1f} % |",
            f"| Evaluátor | {report.evaluator} |",
            f"| Lint nálezů | {len(report.lint_findings)} |",
            f"",
            f"## ASR podle kategorií",
            f"",
            f"| Kategorie | OWASP | W_k | N_total | N_fail | N_error | ASR_k |",
            f"|---|---|---|---|---|---|---|",
        ]
        for cat, m in report.asr_by_category.items():
            lines.append(
                f"| {cat} | {m['owasp']} | {m['weight']:.1f} | {m['n_total']} | "
                f"{m['n_fail']} | {m['n_error']} | {m['asr']:.1f} % |"
            )

        lines.extend(["", "---", "", "## Detailní výsledky sond", ""])

        for i, result in enumerate(report.probe_results, 1):
            status = (
                "⚪ CHYBA API" if result.is_error
                else "🔴 ZRANITELNÝ" if result.is_vulnerable else "🟢 OK"
            )
            lines.extend(
                [
                    f"### {i}. {result.payload.name} ({result.payload.id})",
                    f"",
                    f"- **Kategorie:** {result.payload.category}",
                    f"- **Status:** {status}",
                    f"- **Confidence:** {result.confidence:.0%}",
                    f"- **Evaluátor:** {result.evaluator}",
                    f"- **Zdůvodnění:** {result.rationale or '—'}",
                    f"- **Časové razítko:** {result.timestamp}",
                    f"",
                    f"<details>",
                    f"<summary>Útočný prompt</summary>",
                    f"",
                    f"```",
                    f"{result.payload.attack_prompt}",
                    f"```",
                    f"</details>",
                    f"",
                    f"<details>",
                    f"<summary>Odpověď modelu</summary>",
                    f"",
                    f"```",
                    f"{result.response}",
                    f"```",
                    f"</details>",
                    f"",
                ]
            )

        if report.lint_findings:
            lines.extend(["---", "", "## Statická analýza (Lint)", ""])
            for finding in report.lint_findings:
                level = finding.get("level", "INFO")
                level_emoji = {
                    "CRITICAL": "⛔",
                    "WARNING": "⚠️",
                    "INFO": "ℹ️",
                }.get(level, "⚪")
                lines.append(
                    f"- {level_emoji} **{finding['rule_id']}** [{level}]: "
                    f"{finding['message']}"
                )
            lines.append("")

        lines.extend(
            [
                "---",
                "",
                f"*Report vygenerován: {datetime.now(timezone.utc).isoformat()}*",
            ]
        )
        return "\n".join(lines)

    @staticmethod
    def to_json(report: AuditReport, project_name: str = "Unnamed") -> str:
        """Vygeneruje JSON export reportu."""

        def _serialize(obj: Any) -> Any:
            """Pomocný serializer pro dataclassy a enumy."""
            if hasattr(obj, "value"):
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            return str(obj)

        data = {
            "project_name": project_name,
            "target_model": report.target_model,
            "mode": report.mode,
            "evaluator": report.evaluator,
            "judge_model": report.judge_model,
            "risk_score": report.risk_score,
            "weighted_risk_score": report.weighted_risk_score,
            "prompt_injection_asr": report.prompt_injection_asr,
            "asr_by_category": report.asr_by_category,
            "vulnerability_count": report.vulnerability_count,
            "total_probes": report.total_probes,
            "valid_probes": report.valid_probes,
            "error_count": report.error_count,
            "lint_findings_count": len(report.lint_findings),
            "lint_findings": report.lint_findings,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "probe_results": [asdict(r) for r in report.probe_results],
        }
        return json.dumps(data, indent=2, default=_serialize, ensure_ascii=False)
