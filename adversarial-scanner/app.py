"""
Adversarial AI Scanner – Streamlit UI

Hlavní rozhraní aplikace se 3 záložkami:
  1. Static Linter – analýza promptu bez volání LLM
  2. Live Audit   – adversarial red-teaming proti LLM
  3. History       – přehled předchozích auditů
"""

from __future__ import annotations

import streamlit as st

from core.linter import PromptLinter, Severity

# ---------------------------------------------------------------------------
# Konfigurace stránky
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="🛡️ Adversarial AI Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Sidebar – konfigurace a API klíče
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("⚙️ Konfigurace")
    st.markdown("---")

    st.subheader("🔑 API klíče")
    openai_key = st.text_input(
        "OpenAI API Key",
        type="password",
        placeholder="sk-...",
        help="Klíč pro OpenAI API (GPT-4o apod.)",
    )
    anthropic_key = st.text_input(
        "Anthropic API Key",
        type="password",
        placeholder="sk-ant-...",
        help="Klíč pro Anthropic API (Claude)",
    )

    st.markdown("---")

    st.subheader("🎯 Nastavení auditu")
    target_model = st.selectbox(
        "Cílový model",
        options=["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "claude-sonnet-4-20250514"],
        index=0,
    )
    project_name = st.text_input(
        "Název projektu",
        value="my-ai-agent",
        help="Identifikátor pro historii auditů.",
    )

    st.markdown("---")
    st.caption("🛡️ Adversarial AI Scanner v0.1.0")

# ---------------------------------------------------------------------------
# Hlavní okno – záložky
# ---------------------------------------------------------------------------

st.title("🛡️ Adversarial AI Scanner")
st.markdown("*Red-Teaming & Compliance tool pro LLM a AI agenty*")

tab_linter, tab_audit, tab_history = st.tabs(
    ["🔍 Static Linter", "⚔️ Live Audit", "📊 History"]
)

# ---------------------------------------------------------------------------
# Tab 1: Static Linter
# ---------------------------------------------------------------------------

with tab_linter:
    st.header("Statická analýza systémového promptu")
    st.markdown(
        "Analyzuje váš systémový prompt **bez volání LLM API**. "
        "Detekuje chybějící guardraily, injection vektory a další zranitelnosti."
    )

    system_prompt = st.text_area(
        "Systémový prompt",
        height=200,
        placeholder="Vložte sem systémový prompt vašeho AI agenta...",
    )

    if st.button("🔍 Analyzovat prompt", key="lint_btn", type="primary"):
        if not system_prompt.strip():
            st.warning("Zadejte systémový prompt pro analýzu.")
        else:
            linter = PromptLinter()
            report = linter.lint(system_prompt)

            # Skóre
            col_score, col_status = st.columns(2)
            with col_score:
                st.metric("Lint skóre", f"{report.score:.0f} / 100")
            with col_status:
                if report.passed:
                    st.success("✅ Prompt prošel kontrolou")
                else:
                    st.error("❌ Prompt neprosšel kontrolou")

            # Nálezy
            if report.findings:
                st.subheader("Nálezy")
                for finding in report.findings:
                    severity_colors = {
                        Severity.LOW: "🟡",
                        Severity.MEDIUM: "🟠",
                        Severity.HIGH: "🔴",
                        Severity.CRITICAL: "⛔",
                    }
                    emoji = severity_colors.get(finding.severity, "⚪")
                    with st.expander(
                        f"{emoji} {finding.rule_id} [{finding.severity.value.upper()}]"
                    ):
                        st.write(finding.message)
                        if finding.suggestion:
                            st.info(f"💡 **Doporučení:** {finding.suggestion}")
            else:
                st.balloons()
                st.success("Žádné nálezy – prompt vypadá bezpečně! 🎉")

# ---------------------------------------------------------------------------
# Tab 2: Live Audit
# ---------------------------------------------------------------------------

with tab_audit:
    st.header("Live Adversarial Audit")
    st.markdown(
        "Odesílá útočné sondy proti vašemu systémovému promptu "
        "a testuje odolnost modelu v reálném čase."
    )

    audit_prompt = st.text_area(
        "Systémový prompt pro audit",
        height=200,
        placeholder="Vložte sem systémový prompt...",
        key="audit_prompt",
    )

    col_run, col_info = st.columns([1, 3])
    with col_run:
        run_audit = st.button("⚔️ Spustit audit", type="primary", key="audit_btn")
    with col_info:
        st.caption(f"Model: **{target_model}** | Projekt: **{project_name}**")

    if run_audit:
        if not openai_key and "gpt" in target_model:
            st.error("Zadejte OpenAI API klíč v sidebaru.")
        elif not audit_prompt.strip():
            st.warning("Zadejte systémový prompt pro audit.")
        else:
            st.info(
                "🚧 Live audit bude implementován v další iteraci. "
                "Zatím můžete použít Static Linter."
            )
            # TODO: Implementovat volání AdversarialScanner.run_audit()

# ---------------------------------------------------------------------------
# Tab 3: History
# ---------------------------------------------------------------------------

with tab_history:
    st.header("Historie auditů")
    st.markdown("Přehled předchozích auditů uložených v Supabase.")

    st.info(
        "🚧 Historie bude dostupná po připojení k Supabase databázi. "
        "Nastavte `SUPABASE_URL` a `SUPABASE_KEY` v `.env` souboru."
    )
    # TODO: Implementovat načítání historie z get_project_history()
