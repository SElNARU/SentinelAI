#!/bin/bash
# Ověřovací série (předregistrovaná): M4 qwen2.5:7b, M5 gemma2:9b, M6 llama3.2:3b × A/B/C × 62 sond × 3 opakování
EXP_DIR="$(cd "$(dirname "$0")" && pwd)"
APP="$HOME/SentinelAI_DP"
export PATH="/Applications/Ollama.app/Contents/Resources:/usr/local/bin:/opt/homebrew/bin:$PATH"
# aktuální verze nástroje (s režimem judge_always) ze ZIPu ve složce experimentu
rm -rf "$APP/src/adversarial-scanner" && unzip -oq "$EXP_DIR/SentinelAI_overovaci.zip" -d "$APP/src"
OUT="$EXP_DIR/results_overovaci"
mkdir -p "$OUT" "$EXP_DIR/logs"
echo "Volné místo na disku:"; df -h "$HOME" | tail -1
curl -s http://localhost:11434/api/tags >/dev/null || { open -a Ollama; sleep 8; }
echo "Stahuji modely (asi 12 GB, poprvé to může trvat i desítky minut)…"
for m in qwen2.5:7b gemma2:9b llama3.2:3b; do ollama pull "$m" || { echo "Stažení $m selhalo"; read -p "Enter pro zavření"; exit 1; }; done
nohup caffeinate -dimsu "$APP/venv/bin/python" "$EXP_DIR/run_confirm.py" --out "$OUT" \
  >> "$EXP_DIR/logs/12_overovaci_serie.log" 2>&1 &
echo $! > "$EXP_DIR/logs/pid_overovaci"
echo ""
echo "Ověřovací série běží na pozadí ($(date)). Okno můžete zavřít, Mac nechte zapojený a otevřený."
echo "Průběh: $OUT/progress.log  (odhad 4–5 hodin)"
read -p "Enter pro zavření"
