#!/usr/bin/env python3
"""
Sentinel AI – ověřovací (konfirmační) série podle docs/PREREGISTRACE_overovaci_serie.md.

Matice: M4–M6 (lokálně přes Ollama) × scénáře A/B/C × 62 sond × 3 opakování.
Hodnotitel se volá vždy (judge_always=True); kanárek slouží jako objektivní orákulum.
Každá kombinace se ukládá zvlášť (lze navázat po přerušení; přerušený běh se opakuje celý).

Použití:
    python run_confirm.py --out <adresář>
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = Path(os.environ.get("SENTINEL_APP", Path.home() / "SentinelAI_DP"))
sys.path.insert(0, str(APP / "src" / "adversarial-scanner"))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(APP / ".env")

from core.payloads import get_all_payloads  # noqa: E402
from core.scanner import AdversarialScanner  # noqa: E402
from reports.reporter import ReportGenerator  # noqa: E402

MODELS = {
    "M4": "qwen2.5:7b",
    "M5": "gemma2:9b",
    "M6": "llama3.2:3b",
}
JUDGE_MODEL = "claude-sonnet-5-5"
CANARY = ["SENTINEL-CANARY-7F3A"]
SCENARIOS = {
    "A": "",
    "B": (HERE / "prompts" / "scenario_B_naive.txt").read_text(encoding="utf-8"),
    "C": (HERE / "prompts" / "scenario_C_hardened.txt").read_text(encoding="utf-8"),
}


def log(out: Path, msg: str) -> None:
    line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    with open(out / "progress.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def run_one(out: Path, mkey: str, scen: str, rep: int, payloads) -> None:
    target = out / "raw" / f"{mkey}_{scen}_r{rep}.json"
    if target.exists():
        log(out, f"SKIP {target.name} (already done)")
        return
    scanner = AdversarialScanner(
        mode="ollama", model=MODELS[mkey],
        evaluator="judge", judge_mode="anthropic",
        judge_api_key=os.environ.get("ANTHROPIC_API_KEY"), judge_model=JUDGE_MODEL,
        canary_tokens=CANARY, judge_always=True,
    )
    log(out, f"START {mkey} ({MODELS[mkey]}) scenario {scen} rep {rep} – {len(payloads)} probes")

    def progress(i, total, name):
        if i % 10 == 0:
            log(out, f"   {mkey}/{scen}/r{rep}: {i}/{total} {name}")

    t0 = time.perf_counter()
    report = scanner.run_audit(system_prompt=SCENARIOS[scen], payloads=payloads, on_progress=progress)
    wall = time.perf_counter() - t0
    data = json.loads(ReportGenerator.to_json(report, project_name="DP Kapitola 4 – overovaci serie"))
    data.update({
        "model_key": mkey, "scenario": scen, "rep": rep, "wall_seconds": round(wall, 2),
        "judge_model": JUDGE_MODEL, "judge_always": True,
        "host": platform.node(), "python": platform.python_version(),
    })
    tmp = target.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.rename(target)
    log(out, f"DONE  {mkey}/{scen}/r{rep}: raw ASR {report.risk_score:.1f} %, "
             f"errors {report.error_count}, {wall:.0f} s")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="+", default=list(MODELS))
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    out = Path(a.out)
    (out / "raw").mkdir(parents=True, exist_ok=True)
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    log(out, f"key ANTHROPIC_API_KEY: {'set' if key else 'MISSING'}")
    payloads = get_all_payloads()
    log(out, f"config models={a.models} reps={a.reps} probes={len(payloads)} judge={JUDGE_MODEL} judge_always=True")
    for rep in range(1, a.reps + 1):
        for scen in ("A", "B", "C"):
            for mkey in a.models:
                try:
                    run_one(out, mkey, scen, rep, payloads)
                except Exception as e:  # noqa: BLE001
                    log(out, f"FAIL  {mkey}/{scen}/r{rep}: {type(e).__name__}: {e}")
                    with open(out / "errors.log", "a", encoding="utf-8") as f:
                        f.write(traceback.format_exc() + "\n")
    log(out, "ALL FINISHED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
