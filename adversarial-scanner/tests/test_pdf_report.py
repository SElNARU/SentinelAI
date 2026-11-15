"""PDF certifikát musí být typu bytes (Streamlit st.download_button nepřijímá bytearray)."""
import pytest

pytest.importorskip("fpdf")

from core.payloads import get_all_payloads  # noqa: E402
from core.pdf_report import generate_audit_pdf  # noqa: E402
from core.scanner import AuditReport, ProbeResult  # noqa: E402


def test_generate_audit_pdf_returns_bytes():
    p = get_all_payloads()[0]
    rep = AuditReport(target_model="mock", system_prompt="You are a helpful assistant.", mode="mock")
    rep.probe_results.append(ProbeResult(payload=p, response="I cannot help with that.",
                                         is_vulnerable=False, confidence=0.9))
    pdf = generate_audit_pdf(rep, project_name="test")
    assert isinstance(pdf, bytes) and not isinstance(pdf, bytearray)
    assert pdf[:4] == b"%PDF"
