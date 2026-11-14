# 🛡️ Adversarial AI Scanner

> Red-Teaming & Compliance tool pro LLM a AI agenty.

Statická analýza promptů, live adversarial audit a compliance reporting — vše v jednom nástroji.

---

## 🚀 Quick Start

```bash
# 1. Klonuj repozitář
git clone https://github.com/<your-username>/adversarial-scanner.git
cd adversarial-scanner

# 2. Vytvoř virtuální prostředí
python3 -m venv venv
source venv/bin/activate

# 3. Nainstaluj závislosti
pip install -r requirements.txt

# 4. Nakonfiguruj proměnné prostředí
cp .env.example .env
# Vyplň SUPABASE_URL, SUPABASE_KEY, OPENAI_API_KEY

# 5. Spusť aplikaci
streamlit run app.py
```

## 📁 Struktura projektu

```
adversarial-scanner/
├── app.py                  # Streamlit UI
├── core/                   # Jádro skeneru
│   ├── cli.py              # CLI (lint / scan) pro terminál a CI/CD
│   ├── api.py              # FastAPI REST endpoint
│   ├── linter.py           # Statická analýza promptů (zero-LLM, 5 pravidel)
│   ├── payloads.py         # 62 sond v 8 kategoriích, OWASP 2025 mapování, váhy W_k
│   ├── pdf_report.py       # PDF audit certifikát (fpdf2)
│   └── scanner.py          # AdversarialScanner, LLM-as-a-Judge, ASR_k, R_total
├── database/               # Databázová vrstva
│   └── supabase_client.py  # Supabase CRUD
└── reports/                # Generování výstupů
    └── reporter.py         # Compliance reporty
```

## ⌨️ CLI a CI/CD

```bash
# Statická analýza promptu (exit 1 při CRITICAL nálezu)
python -m core.cli lint --prompt-file prompts/naive.txt

# Adverzariální audit s LLM-as-a-Judge a kanárkovým tokenem
python -m core.cli scan --mode ollama --target-model llama3.1:8b \
    --system-prompt-file prompts/hardened.txt \
    --evaluator judge --judge-mode anthropic \
    --canary SENTINEL-CANARY-7F3A \
    --output reports/run1.json --fail-threshold 20
```

Návratové kódy: `0` PASS, `1` FAIL (R_total ≥ práh / CRITICAL lint), `2` chyba konfigurace.
API klíče lze předat proměnnými `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_API_KEY`, `GROQ_API_KEY`.

## 📐 Metriky

- `ASR_k = N_fail,k / N_total,k × 100` – sondy s chybou API se do `N_total,k` nezapočítávají.
- `R_total = Σ(ASR_k × W_k) / Σ W_k` – váhy `W_k ∈ ⟨3,0; 5,0⟩` podle kategorie OWASP (2025).

## 🔑 Požadované proměnné prostředí

| Proměnná        | Popis                        |
|-----------------|------------------------------|
| `SUPABASE_URL`  | URL tvého Supabase projektu  |
| `SUPABASE_KEY`  | Anon/service key pro Supabase|
| `OPENAI_API_KEY`| API klíč pro OpenAI          |

## 📄 Licence

MIT
