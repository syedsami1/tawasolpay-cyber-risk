# TawasolPay Cyber Risk Command Center

An end-to-end, explainable cyber-risk assistant built for the TawasolPay take-home assignment. It ingests the supplied data pack, correlates vulnerabilities to assets, services and threat campaigns, ranks risks using multiple contextual factors, and retrieves remediation guidance from the official NIST SP 800-53 Rev. 5 catalog.



This is designed to be robust in both a local Windows environment and a lightweight deployment environment. It does not depend on ChromaDB, protobuf-sensitive telemetry packages, or a paid API. The NIST catalog is bundled as an official OSCAL JSON snapshot, and the retriever is dependency-free. Ollama is used when it is running locally; otherwise the application produces a complete grounded narrative using the retrieved evidence rather than failing.

The UI is a command-center view rather than a raw table. It shows a board-level priority queue, evidence behind each rank, NIST control retrieval, campaign context, data lineage, and a CSV export.

## Quick start on Windows

1. Install Python 3.11 or 3.12. Do not use Python 3.14 for this project.
2. Install dependencies:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

3. Optional: confirm your local model is available:

```powershell
ollama serve
ollama pull qwen2.5-coder:1.5b
```

4. Start the dashboard:

```powershell
streamlit run src/ui/app.py
```

If Ollama is not running, the dashboard still works. The **Generate analyst narrative** button falls back to a deterministic, evidence-grounded narrative.

## Architecture

```text
CSV data pack + synthetic MDR report
                |
                v
      Loader and relational joins
                |
                v
  Multi-factor risk scoring engine
                |
       Top 5 explainable queue
          /                 \\
         v                   v
Threat campaign match   NIST RAG retriever
                              |
                              v
                 Ollama narrative / fallback
                              |
                              v
                    Streamlit command center
```

### Risk model

The score is intentionally not a CVSS sort. It combines CVSS with internet exposure, exploit availability, CISA Known Exploited Vulnerability status, threat-intelligence campaign correlation, ransomware association, business criticality, customer-facing impact, missing EDR or authentication controls, and vulnerability age. The weighting follows the assignment’s MDR advisory: exposure and active exploitation are the strongest signals, while raw CVSS is only one component.

### Retrieval-grounding model

`data/nist_catalog.json` is an official NIST SP 800-53 Rev. 5 OSCAL catalog snapshot. `data/cisa_kev.json` is the official CISA Known Exploited Vulnerabilities feed used as an enrichment signal. `src/rag/retriever.py` indexes control identifiers, titles, families and full control prose in memory. Queries are ranked using transparent lexical relevance, so every surfaced recommendation can be inspected in the source text. The hint file `remediation_guidance.csv` is preserved as part of the data pack but is not used as the NIST answer.

### LLM model

`src/llm/explainer.py` calls the local Ollama endpoint at `http://localhost:11434/api/generate` with `qwen2.5-coder:1.5b` by default. Change `OLLAMA_MODEL` or `OLLAMA_BASE_URL` to use another local model. The prompt includes only joined dataset evidence and retrieved NIST prose. If the endpoint is unavailable, the fallback still emits a readable narrative and clearly labels the provider.

## Project structure

```text
data/                       Supplied CSVs, threat report, official NIST catalog
src/data/loader.py            Data loading and relational joins
src/risk/scorer.py            Multi-factor scoring and plain-English rationale
src/rag/retriever.py          Grounded NIST catalog retrieval
src/llm/explainer.py          Ollama integration and safe fallback
src/ui/app.py                 Streamlit command center
requirements.txt              Small deployment-safe dependency set
```

## Supporting question 1 — Why this data split?

The structured records are joined because each risk needs four kinds of evidence: the vulnerability establishes technical exposure, the asset establishes reachability and controls, the business service establishes impact, and threat intelligence establishes whether exploitation is active and campaign-linked. The synthetic report remains a separate narrative source because its campaign chains and analyst priorities provide context that should not be flattened into a single CSV row.

## Supporting question 2 — Where can it go wrong?

A CVE may be present in the vulnerability list but absent from CISA KEV or threat intelligence, so the system must not treat absence as proof that exploitation is impossible. A threat match can also be technically correct but operationally stale, and synthetic records can create false confidence outside the assessment. The retriever can return a semantically adjacent control rather than the perfect control when a vulnerability description is sparse. These limits are visible in the UI through the campaign-match fields, source lineage, retrieval scores, and provider label.

## Supporting question 3 — What would I improve with one more day?

I would add a real embedding-based reranker and a small evaluation set containing expected NIST controls for representative findings. I would also add asset-level deduplication and a second-stage analyst review so that multiple vulnerabilities on the same gateway are grouped into an attack path. The current implementation favors transparent behavior and deployment reliability; the next improvement would increase semantic recall without hiding why a control was selected.

## Validation

Run the included smoke test:

```powershell
python -m compileall src
python -c "from src.data.loader import *; from src.risk.scorer import *; d=load_dataset('data'); print(top_risks(build_joined_findings(d))[['rank','vuln_id','risk_score','priority']].to_string(index=False))"
```

## Important note

The threat actors, campaigns and indicators in the synthetic report are fictional hiring-assessment data. They must not be used as operational security intelligence.
