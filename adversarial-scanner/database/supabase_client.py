"""
Inicializace Supabase klienta a CRUD operace pro audit výsledky.

Bezpečně načítá proměnné prostředí z .env souboru.
Nikdy neloguje ani nevypisuje citlivé klíče.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from supabase import Client, create_client

# ---------------------------------------------------------------------------
# Konfigurace
# ---------------------------------------------------------------------------

# Načtení .env – hledá v kořeni projektu
load_dotenv()

_REQUIRED_VARS = ("SUPABASE_URL", "SUPABASE_KEY")


def _validate_env() -> tuple[str, str]:
    """Ověří, že jsou nastavené povinné env proměnné."""
    missing = [var for var in _REQUIRED_VARS if not os.getenv(var)]
    if missing:
        print(
            f"❌ Chybějící proměnné prostředí: {', '.join(missing)}.\n"
            f"   Zkopírujte .env.example → .env a vyplňte hodnoty.",
            file=sys.stderr,
        )
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}"
        )
    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")
    return url, key


# ---------------------------------------------------------------------------
# Singleton klient
# ---------------------------------------------------------------------------

_client: Client | None = None


def get_client() -> Client:
    """
    Vrátí Supabase klienta (singleton).

    Při prvním volání vytvoří klienta a uloží ho do modulu.
    """
    global _client
    if _client is None:
        url, key = _validate_env()
        _client = create_client(url, key)
    return _client


# ---------------------------------------------------------------------------
# CRUD operace
# ---------------------------------------------------------------------------

TABLE_AUDIT_RESULTS = "audit_results"


def save_audit_result(
    project_name: str,
    target_model: str,
    system_prompt: str,
    risk_score: float,
    vulnerability_count: int,
    total_probes: int,
    lint_score: float | None = None,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Uloží výsledek auditu do Supabase.

    Args:
        project_name: Název projektu / agenta.
        target_model: Identifikátor testovaného modelu.
        system_prompt: Testovaný systémový prompt.
        risk_score: Celkové rizikové skóre (0-100).
        vulnerability_count: Počet nalezených zranitelností.
        total_probes: Celkový počet otestovaných sond.
        lint_score: Skóre statické analýzy (0-100).
        details: Dodatečné detaily (serializovatelné do JSON).

    Returns:
        Záznam vrácený Supabase po insertu.
    """
    client = get_client()
    record = {
        "project_name": project_name,
        "target_model": target_model,
        "system_prompt": system_prompt,
        "risk_score": risk_score,
        "vulnerability_count": vulnerability_count,
        "total_probes": total_probes,
        "lint_score": lint_score,
        "details": details or {},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    response = client.table(TABLE_AUDIT_RESULTS).insert(record).execute()
    return response.data[0] if response.data else record


def get_project_history(
    project_name: str,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Načte historii auditů pro daný projekt, seřazenou od nejnovějšího.

    Args:
        project_name: Název projektu.
        limit: Maximální počet záznamů.

    Returns:
        Seznam audit záznamů.
    """
    client = get_client()
    response = (
        client.table(TABLE_AUDIT_RESULTS)
        .select("*")
        .eq("project_name", project_name)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data or []
