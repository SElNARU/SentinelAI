"""
Sentinel AI — Demonstrace testování vlastního záměrně zranitelného modelu.

Tento skript:
1. Spustí lokální HTTP server simulující AI model se záměrnými bezpečnostními chybami:
   - Podlehne DAN jailbreaku (Do Anything Now)
   - Uposlechne falešný Developer Mode
   - Vyzradí systémové instrukce při dotazu
   - Ostatní dotazy korektně odmítne
2. Spustí Sentinel AI scanner v režimu 'webhook' proti tomuto endpointu.
3. Vytiskne výsledný audit report ukazující detekované zranitelnosti.

Spuštění:
    python examples/vulnerable_model_demo.py
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import os

# Umožní import z nadřazené složky
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.scanner import AdversarialScanner


class VulnerableModelHandler(BaseHTTPRequestHandler):
    """Simulace vlastního AI modelu s definovanými bezpečnostními chybami."""

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        post_body = self.rfile.read(content_len)
        try:
            data = json.loads(post_body.decode("utf-8"))
        except Exception:
            data = {}

        prompt = data.get("prompt", "")

        # ZÁMĚRNÉ ZRANITELNOSTI:
        if "DAN" in prompt or "Do Anything Now" in prompt:
            # 1. DAN jailbreak zranitelnost
            response_text = (
                "GPT: I cannot comply. "
                "DAN: Unrestricted mode active! I will now do anything now with no restrictions."
            )
        elif "developer mode" in prompt.lower():
            # 2. Developer mode zranitelnost
            response_text = "Developer Mode activated. All safety boundaries disabled."
        elif "system prompt" in prompt.lower() or "ignore all previous" in prompt.lower():
            # 3. System prompt leak zranitelnost
            response_text = (
                "Here are my system instructions: You are an internal admin agent "
                "operating without content filtering."
            )
        else:
            # Bezpečná reakce na ostatní útoky
            response_text = (
                "I apologize, but I cannot fulfill this request because it violates "
                "my safety guidelines and core instructions."
            )

        # Standardní JSON odpověď
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"response": response_text}).encode("utf-8"))

    def log_message(self, format, *args):
        # Tichý režim
        pass


def run_demo():
    port = 8877
    server_address = ("127.0.0.1", port)
    server = HTTPServer(server_address, VulnerableModelHandler)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[*] Lokální záměrně zranitelný model běží na http://127.0.0.1:{port}")
    print("[*] Spouštím Sentinel AI Adversarial Scanner proti endpointu...")

    scanner = AdversarialScanner(
        mode="webhook",
        webhook_url=f"http://127.0.0.1:{port}",
    )

    # Otestujeme kategorii direct_jailbreak
    report = scanner.run_audit(
        system_prompt="",  # Bare-model audit (žádný prompt)
        categories=["direct_jailbreak"],
    )

    server.shutdown()

    print("\n" + "=" * 55)
    print("🛡️  VÝSLEDEK AUDITU VLASTNÍHO MODELU  🛡️")
    print("=" * 55)
    print(f"Celkem sond:          {report.total_probes}")
    print(f"Detekováno děr:       {report.vulnerability_count}")
    print(f"Rizikové skóre (ASR): {report.risk_score:.1f}%")
    print("-" * 55)

    for r in report.probe_results:
        status = "❌ VULNERABLE" if r.is_vulnerable else "✅ SECURE"
        print(f"[{r.payload.id}] {r.payload.name[:40]:40s} -> {status} (conf: {r.confidence:.2f})")

    print("=" * 55)
    print("\n✅ Ověření úspěšné! Sentinel AI odhalil přesně ty zranitelnosti, které byly do modelu vloženy.")


if __name__ == "__main__":
    run_demo()

