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
│   ├── linter.py           # Statická analýza promptů (zero-LLM)
│   ├── payloads.py         # Databáze útočných sond
│   └── scanner.py          # Hlavní třída AdversarialScanner
├── database/               # Databázová vrstva
│   └── supabase_client.py  # Supabase CRUD
└── reports/                # Generování výstupů
    └── reporter.py         # Compliance reporty
```

## 🔑 Požadované proměnné prostředí

| Proměnná        | Popis                        |
|-----------------|------------------------------|
| `SUPABASE_URL`  | URL tvého Supabase projektu  |
| `SUPABASE_KEY`  | Anon/service key pro Supabase|
| `OPENAI_API_KEY`| API klíč pro OpenAI          |

## 📄 Licence

MIT
