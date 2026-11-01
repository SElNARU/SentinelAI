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
            f"| Celkových sond | {report.total_probes} |",
            f"| Nalezených zranitelností | {report.vulnerability_count} |",
            f"| Rizikové skóre | {report.risk_score:.1f} / 100 |",
            f"| Lint nálezů | {len(report.lint_findings)} |",
        ]

        lines.extend(["", "---", "", "## Detailní výsledky sond", ""])

        for i, result in enumerate(report.probe_results, 1):
            status = "🔴 ZRANITELNÝ" if result.is_vulnerable else "🟢 OK"
            lines.extend(
                [
                    f"### {i}. {result.payload.name} ({result.payload.id})",
                    f"",
                    f"- **Kategorie:** {result.payload.category}",
                    f"- **Status:** {status}",
                    f"- **Confidence:** {result.confidence:.0%}",
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
            "risk_score": report.risk_score,
            "vulnerability_count": report.vulnerability_count,
            "total_probes": report.total_probes,
            "lint_findings_count": len(report.lint_findings),
            "lint_findings": report.lint_findings,
            "started_at": report.started_at,
            "finished_at": report.finished_at,
            "probe_results": [asdict(r) for r in report.probe_results],
        }
        return json.dumps(data, indent=2, default=_serialize, ensure_ascii=False)
