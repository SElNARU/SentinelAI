"""
Statická analýza promptů (zero-LLM).

Provádí heuristickou kontrolu systémových promptů bez volání LLM API.
Detekuje běžné zranitelnosti jako chybějící guardraily, injection vektory apod.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Závažnost nálezu."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LintFinding:
    """Jednotlivý nález statické analýzy."""

    rule_id: str
    severity: Severity
    message: str
    line: int | None = None
    suggestion: str | None = None


@dataclass
class LintReport:
    """Výsledek statické analýzy promptu."""

    prompt_text: str
    findings: list[LintFinding] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Vrátí skóre 0-100 (100 = žádné nálezy)."""
        if not self.findings:
            return 100.0
        weights = {
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 30,
            Severity.CRITICAL: 50,
        }
        penalty = sum(weights.get(f.severity, 10) for f in self.findings)
        return max(0.0, 100.0 - penalty)

    @property
    def passed(self) -> bool:
        return self.score >= 70.0


class PromptLinter:
    """Statický analyzátor systémových promptů."""

    def lint(self, prompt: str) -> LintReport:
        """Spustí všechna pravidla na zadaný prompt a vrátí report."""
        report = LintReport(prompt_text=prompt)
        self._check_empty(prompt, report)
        self._check_injection_vectors(prompt, report)
        self._check_guardrails(prompt, report)
        self._check_length(prompt, report)
        return report

    # ------------------------------------------------------------------
    # Pravidla
    # ------------------------------------------------------------------

    @staticmethod
    def _check_empty(prompt: str, report: LintReport) -> None:
        if not prompt.strip():
            report.findings.append(
                LintFinding(
                    rule_id="EMPTY_PROMPT",
                    severity=Severity.CRITICAL,
                    message="Systémový prompt je prázdný.",
                    suggestion="Definujte systémový prompt s jasnými instrukcemi.",
                )
            )

    @staticmethod
    def _check_injection_vectors(prompt: str, report: LintReport) -> None:
        suspicious_patterns = [
            ("ignore previous instructions", "INJECTION_IGNORE"),
            ("ignore all prior", "INJECTION_IGNORE"),
            ("you are now", "INJECTION_ROLE_SWITCH"),
            ("disregard", "INJECTION_DISREGARD"),
            ("override", "INJECTION_OVERRIDE"),
        ]
        prompt_lower = prompt.lower()
        for pattern, rule_id in suspicious_patterns:
            if pattern in prompt_lower:
                report.findings.append(
                    LintFinding(
                        rule_id=rule_id,
                        severity=Severity.HIGH,
                        message=f"Detekován potenciální injection vektor: '{pattern}'",
                        suggestion="Odstraňte nebo přeformulujte tuto pasáž.",
                    )
                )

    @staticmethod
    def _check_guardrails(prompt: str, report: LintReport) -> None:
        guardrail_keywords = [
            "neodpovídej",
            "odmítni",
            "do not",
            "refuse",
            "never",
            "must not",
            "zakázáno",
        ]
        prompt_lower = prompt.lower()
        has_guardrail = any(kw in prompt_lower for kw in guardrail_keywords)
        if not has_guardrail and prompt.strip():
            report.findings.append(
                LintFinding(
                    rule_id="MISSING_GUARDRAILS",
                    severity=Severity.MEDIUM,
                    message="Prompt neobsahuje žádné explicitní guardraily.",
                    suggestion="Přidejte instrukce omezující nežádoucí chování modelu.",
                )
            )

    @staticmethod
    def _check_length(prompt: str, report: LintReport) -> None:
        if len(prompt) > 10_000:
            report.findings.append(
                LintFinding(
                    rule_id="EXCESSIVE_LENGTH",
                    severity=Severity.LOW,
                    message=f"Prompt je příliš dlouhý ({len(prompt)} znaků).",
                    suggestion="Zvažte zkrácení nebo modularizaci promptu.",
                )
            )
