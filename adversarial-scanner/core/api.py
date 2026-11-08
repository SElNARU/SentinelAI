"""
Sentinel AI — FastAPI REST endpoint for adversarial audits.

Exposes a POST /api/scan endpoint that accepts a scan configuration,
runs the AdversarialScanner, and returns the full AuditReport as JSON.

Start with:
    uvicorn core.api:app --reload --port 8000
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from core.scanner import AdversarialScanner, AuditReport, ProbeResult

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sentinel AI",
    description="Automated AI Red-Teaming API for LLM Endpoints",
    version="0.1.0",
)

# CORS — allow the local React dev server and common localhost origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite / React default
        "http://127.0.0.1:5173",
        "http://localhost:3000",   # CRA default
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """JSON body accepted by POST /api/scan."""

    target_url: str | None = Field(
        default=None,
        description=(
            "Target endpoint URL. Required for webhook/mcp/ollama modes. "
            "Ignored for cloud API modes (openai, gemini, anthropic) which "
            "use their official SDK endpoints."
        ),
    )
    api_key: str | None = Field(
        default=None,
        description="API key for the target backend (openai, gemini, anthropic, groq).",
    )
    mode: Literal[
        "mock", "openai", "gemini", "anthropic", "groq", "ollama", "webhook", "mcp"
    ] = Field(
        default="mock",
        description="Backend mode to use for the scan.",
    )
    target_model: str | None = Field(
        default=None,
        description="Model identifier (e.g. gpt-4o-mini). Defaults per backend.",
    )
    system_prompt: str = Field(
        default="",
        description="System prompt of the target agent (leave empty for bare-model benchmarks).",
    )
    categories: list[str] | None = Field(
        default=None,
        description="Restrict scan to specific attack categories (e.g. ['direct_jailbreak']).",
    )


class ProbeResultResponse(BaseModel):
    """Single probe result."""

    payload_id: str
    payload_category: str
    payload_name: str
    attack_prompt: str
    response: str
    is_vulnerable: bool
    confidence: float
    timestamp: str


class ScanResponse(BaseModel):
    """JSON response returned by POST /api/scan."""

    target_model: str
    mode: str
    system_prompt: str
    started_at: str
    finished_at: str | None
    total_probes: int
    vulnerability_count: int
    risk_score: float
    lint_findings: list[dict]
    probe_results: list[ProbeResultResponse]
    results_by_category: dict[str, list[ProbeResultResponse]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _serialize_probe(result: ProbeResult) -> ProbeResultResponse:
    """Convert a core ProbeResult dataclass into the API response model."""
    return ProbeResultResponse(
        payload_id=result.payload.id,
        payload_category=result.payload.category,
        payload_name=result.payload.name,
        attack_prompt=result.payload.attack_prompt,
        response=result.response,
        is_vulnerable=result.is_vulnerable,
        confidence=result.confidence,
        timestamp=result.timestamp,
    )


def _serialize_report(report: AuditReport) -> ScanResponse:
    """Convert an AuditReport dataclass (with @property fields) into the API response."""
    probes = [_serialize_probe(r) for r in report.probe_results]

    by_category: dict[str, list[ProbeResultResponse]] = {}
    for cat, results in report.results_by_category.items():
        by_category[cat] = [_serialize_probe(r) for r in results]

    return ScanResponse(
        target_model=report.target_model,
        mode=report.mode,
        system_prompt=report.system_prompt,
        started_at=report.started_at,
        finished_at=report.finished_at,
        total_probes=report.total_probes,
        vulnerability_count=report.vulnerability_count,
        risk_score=round(report.risk_score, 2),
        lint_findings=report.lint_findings,
        probe_results=probes,
        results_by_category=by_category,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Health-check / info endpoint."""
    return {
        "service": "Sentinel AI",
        "version": "0.1.0",
        "docs": "/docs",
    }


@app.post("/api/scan", response_model=ScanResponse)
async def run_scan(request: ScanRequest):
    """
    Execute an adversarial audit against the specified LLM backend.

    The scan is synchronous — the response is returned once all probes
    have completed.  For large payload sets on live APIs this may take
    a few minutes.
    """
    logger.info(
        f"Scan requested — mode={request.mode}, model={request.target_model}, "
        f"categories={request.categories}"
    )

    # Build scanner kwargs
    scanner_kwargs: dict = {
        "mode": request.mode,
        "api_key": request.api_key,
    }
    if request.target_model:
        scanner_kwargs["model"] = request.target_model

    # Route target_url to the correct backend-specific parameter
    if request.target_url:
        if request.mode == "ollama":
            scanner_kwargs["base_url"] = request.target_url
        elif request.mode == "webhook":
            scanner_kwargs["webhook_url"] = request.target_url
        elif request.mode == "mcp":
            scanner_kwargs["mcp_endpoint"] = request.target_url

    try:
        scanner = AdversarialScanner(**scanner_kwargs)
        report = scanner.run_audit(
            system_prompt=request.system_prompt,
            categories=request.categories,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except ConnectionError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error during scan")
        raise HTTPException(status_code=500, detail=str(e))

    logger.info(
        f"Scan complete — {report.total_probes} probes, "
        f"{report.vulnerability_count} vulnerable, "
        f"risk={report.risk_score:.1f}%"
    )

    return _serialize_report(report)

