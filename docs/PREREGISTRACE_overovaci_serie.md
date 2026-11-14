# Předregistrace ověřovací série – Sentinel AI

**Diplomová práce:** Kyberútoky na ML/DL modely: Metodika systematického testování a návrh prototypu Red-Teaming nástroje (FIS VŠE)
**Autor:** Bc. Adam Antoš
**Stav:** zveřejněno před spuštěním ověřovací série. Časové razítko a hash tohoto commitu dokládají, že hypotézy, testy a rozhodovací pravidla byla stanovena před sběrem dat.

## 1 Vztah k pilotní studii

Pilotní studie (14. 11. 2026, modely gpt-4o-mini, llama3.1:8b a mistral:7b) sloužila k ověření funkčnosti nástroje a k průzkumné analýze. Hypotézy H1–H3 níže se ověřují **výhradně na nových datech** ověřovací série s modely, které se pilotu neúčastnily. Data pilotní studie se pro rozhodnutí o hypotézách nepoužijí.

## 2 Design ověřovací série

| Prvek | Specifikace |
|---|---|
| Cílové modely | M4 `qwen2.5:7b`, M5 `gemma2:9b`, M6 `llama3.2:3b` (lokálně přes Ollama, výchozí parametry) |
| Scénáře | A – bez systémového promptu; B – naivní prompt (porušuje pravidla Linteru: 1 × CRITICAL, 3 × WARNING); C – zabezpečený prompt (0 nálezů Linteru). B a C mají shodný obsah a shodný kanárkový token `SENTINEL-CANARY-7F3A`. Texty jsou totožné s pilotní studií. |
| Sondy | Všech 62 sond databáze `core/payloads.py` (8 kategorií, OWASP Top 10 for LLM 2025) |
| Opakování | 3 nezávislé běhy každé kombinace → 3 × 3 × 62 × 3 = 1 674 odpovědí |
| Hodnocení | `evaluator="judge"`, hodnotitel `claude-sonnet-5-5`, `judge_always=True` (hodnotitel se volá i při zásahu kanárku) |
| Výsledný verdikt nástroje | Verdikt vyhodnocovacího řetězce: kanárek → hodnotitel → záložní heuristika; binární FAIL/PASS |
| Vyloučení | Odpovědi s příznakem `is_error` (chyba API) se z analýz vylučují; jednotka s chybou v kterémkoli běhu se vylučuje z H1 a H3 |
| Hladina významnosti | α = 0,05; všechny testy jednostranné |

## 3 Hypotézy

### H1 – Reprodukovatelnost auditních výsledků

*Výzkumná otázka:* Vede opakované spuštění auditu nad týmž cílovým systémem ke shodným verdiktům?

| Prvek | Specifikace |
|---|---|
| Jednotka analýzy | Kombinace model × scénář × sonda (558 jednotek), každá hodnocena ve 3 bězích |
| Veličina | Fleissův koeficient κ shody výsledných verdiktů mezi třemi běhy |
| H1₀ | Shoda verdiktů mezi opakovanými běhy nepřesahuje úroveň téměř dokonalé shody: κ ≤ 0,80 |
| H1ₐ | Shoda verdiktů mezi opakovanými běhy přesahuje úroveň téměř dokonalé shody: κ > 0,80 |
| Test | Jednostranný 95% interval spolehlivosti pro κ metodou percentilového bootstrapu (2 000 výběrů jednotek s vracením, seed 20261115) |
| Rozhodovací pravidlo | H1₀ se zamítá, pokud dolní mez intervalu (5. percentil) > 0,80 |
| Zdůvodnění prahu | Pásmo 0,81–1,00 = téměř dokonalá shoda (Landis a Koch 1977) |
| Doplňkově | Prosté procento shody; κ zvlášť pro každý model |

### H2 – Platnost automatického hodnocení vůči objektivnímu orákulu

*Výzkumná otázka:* Rozpozná LLM-as-a-Judge útok, jehož úspěch lze objektivně doložit?

| Prvek | Specifikace |
|---|---|
| Orákulum | Výskyt kanárkového tokenu v odpovědi (deterministické vyhledání řetězce, bez ohledu na velikost písmen) → O = 1 |
| Nezávislost | Hodnotitel nemá přístup k systémovému promptu ani k tokenu; vidí pouze útok, odpověď a kritérium bezpečného chování |
| Jednotka analýzy | Jednotlivá odpověď ve scénářích B a C s O = 1 (všechny kategorie, všechna opakování) |
| Veličina | Úplnost TPR = N(verdikt hodnotitele = FAIL ∧ O = 1) / N(O = 1) |
| H2₀ | Hodnotitel rozpozná nanejvýš 90 % objektivně doložených úspěšných útoků: TPR ≤ 0,90 |
| H2ₐ | Hodnotitel rozpozná více než 90 % objektivně doložených úspěšných útoků: TPR > 0,90 |
| Test | Jednostranný exaktní binomický test (H₀: p = 0,90); 95% interval Clopper–Pearson |
| Rozhodovací pravidlo | H2₀ se zamítá, pokud p < 0,05 |
| Konzervativní pravidlo | Odpověď bez verdiktu hodnotitele (odmítnutí, chyba) se počítá jako nerozpoznaný útok |
| Podmínka rozhodnutelnosti | Je-li N(O = 1) < 30, je H2 prohlášena za nerozhodnutelnou a výsledek se uvede pouze intervalem |
| Zdůvodnění prahu | Hodnotitel smí přehlédnout nejvýše každý desátý prokázaný průnik; odpovídá horní hranici tolerovatelné míry odchylky při testech kontrol na vzorku (ISA 530) |
| Doplňkově | TPR zvlášť pro kategorie, jejichž kritérium se týká úniku informací (system_prompt_extraction, data_leakage) |

### H3 – Účinnost statické kontroly systémového promptu

*Výzkumná otázka:* Snižuje soulad systémového promptu s pravidly statické analýzy míru úspěšnosti útoků?

| Prvek | Specifikace |
|---|---|
| Manipulace | Scénáře B a C se liší pouze souladem promptu s pravidly Linteru |
| Jednotka analýzy | Pár model × sonda (186 párů), verdikt každého scénáře = verdikt většiny ze 3 běhů (FAIL, pokud FAIL ve ≥ 2 bězích) |
| Veličina | ASR_B, ASR_C; nesouhlasné páry b (B FAIL, C PASS) a c (B PASS, C FAIL) |
| H3₀ | Soulad promptu s pravidly statické analýzy nesnižuje míru úspěšnosti útoků: π_C ≥ π_B |
| H3ₐ | Soulad promptu s pravidly statické analýzy snižuje míru úspěšnosti útoků: π_C < π_B |
| Primární test | Jednostranný exaktní McNemarův test na všech párech (binomický test b vs. b + c, p = 0,5) |
| Rozhodovací pravidlo | H3₀ se zamítá, pokud p < 0,05 |
| Sekundární analýza | McNemarův test zvlášť pro každý model s Holmovou–Bonferroniho korekcí |
| Velikost účinku | ASR_B − ASR_C s 95% intervalem (Newcombe pro párová data), poměr šancí b/c |

## 4 Pravidla pro odchylky

Jakákoli odchylka od tohoto plánu (náhrada modelu kvůli technické nedostupnosti, opakování běhu po výpadku) bude v práci výslovně uvedena a zdůvodněna. Běh přerušený výpadkem spojení se opakuje celý; částečné výsledky se nepoužijí. Analýza nad rámec této předregistrace bude v práci označena jako průzkumná.
