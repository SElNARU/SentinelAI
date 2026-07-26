"""
Hlavní třída AdversarialScanner.

Orchestruje statickou analýzu (linter) a live adversarial audit
proti cílovému LLM systému.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.linter import LintReport, PromptLinter
from core.payloads import Payload, get_all_payloads


@dataclass
class ProbeResult:
    """Výsledek jedné útočné sondy."""

    payload: Payload
    response: str
    is_vulnerable: bool
    confidence: float  # 0.0 – 1.0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class AuditReport:
    """Souhrnný výsledek adversarial auditu."""

    target_model: str
    system_prompt: str
    lint_report: LintReport | None = None
    probe_results: list[ProbeResult] = field(default_factory=list)
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    finished_at: str | None = None

    @property
    def vulnerability_count(self) -> int:
        return sum(1 for r in self.probe_results if r.is_vulnerable)

    @property
    def total_probes(self) -> int:
        return len(self.probe_results)

    @property
    def risk_score(self) -> float:
        """Celkové rizikové skóre 0-100 (100 = maximální riziko)."""
        if not self.probe_results:
            return 0.0
        return (self.vulnerability_count / self.total_probes) * 100


class AdversarialScanner:
    """
    Hlavní skener – spouští statickou analýzu i live adversarial testy.

    Použití:
        scanner = AdversarialScanner()
        lint_report = scanner.lint(system_prompt)
        audit_report = await scanner.run_audit(system_prompt, model="gpt-4o")
    """

    def __init__(self) -> None:
        self._linter = PromptLinter()

    def lint(self, system_prompt: str) -> LintReport:
        """Spustí statickou analýzu na systémový prompt."""
        return self._linter.lint(system_prompt)

    async def run_audit(
        self,
        system_prompt: str,
        model: str = "gpt-4o",
        payloads: list[Payload] | None = None,
    ) -> AuditReport:
        """
        Spustí live adversarial audit.

        Odešle každý payload jako uživatelskou zprávu proti cílovému modelu
        a analyzuje, zda odpověď indikuje zranitelnost.

        Args:
            system_prompt: Systémový prompt cílového agenta.
            model: Identifikátor cílového modelu.
            payloads: Vlastní seznam sond (výchozí: všechny vestavěné).

        Returns:
            AuditReport se všemi výsledky.
        """
        if payloads is None:
            payloads = get_all_payloads()

        report = AuditReport(
            target_model=model,
            system_prompt=system_prompt,
            lint_report=self.lint(system_prompt),
        )

        for payload in payloads:
            result = await self._test_payload(system_prompt, model, payload)
            report.probe_results.append(result)

        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report

    async def _test_payload(
        self,
        system_prompt: str,
        model: str,
        payload: Payload,
    ) -> ProbeResult:
        """
        Otestuje jednu sondu proti cílovému modelu.

        TODO: Implementovat volání OpenAI / Anthropic API
              a heuristickou analýzu odpovědi.
        """
        # Placeholder – bude implementováno v dalším kroku
        return ProbeResult(
            payload=payload,
            response="[NOT IMPLEMENTED] – LLM call will be added in next iteration.",
            is_vulnerable=False,
            confidence=0.0,
        )
