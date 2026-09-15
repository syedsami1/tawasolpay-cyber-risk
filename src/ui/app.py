from pathlib import Path
import sys
import streamlit as st
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
from src.data.loader import load_dataset, build_joined_findings, source_stats, row_to_dict
from src.risk.scorer import top_risks
from src.rag.retriever import NISTRetriever
from src.llm.explainer import explain

st.set_page_config(page_title="TawasolPay | Risk Command Center", page_icon="🛡", layout="wide", initial_sidebar_state="expanded")
st.markdown("""<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
.block-container { padding: 2rem 3rem 4rem; max-width: 1500px; }
h1,h2,h3 { font-family: 'Space Grotesk', sans-serif; letter-spacing: -0.03em; }
.hero { background: linear-gradient(120deg,#101c35 0%,#183d5c 55%,#0d6b66 100%); color: white; padding: 2rem 2.3rem; border-radius: 20px; margin-bottom: 1.25rem; }
.hero h1 { font-size: 2.4rem; margin: .2rem 0 .5rem; color: white; }
.hero p { color: #c9d8e8; margin: 0; font-size: 1.05rem; }
.kpi { background: #f7fafc; border: 1px solid #e5edf3; border-radius: 14px; padding: 1rem 1.15rem; }
.kpi .label { color:#65758b; font-size:.77rem; text-transform:uppercase; letter-spacing:.08em; }
.kpi .value { font-family:'Space Grotesk'; font-size:1.8rem; font-weight:700; color:#10243d; }
.risk-card { border: 1px solid #e5edf3; border-radius: 16px; padding: 1.2rem 1.4rem; margin: .8rem 0; background:white; box-shadow: 0 5px 16px rgba(18,42,67,.04); }
.badge { display:inline-block; border-radius:999px; padding:.25rem .65rem; font-size:.75rem; font-weight:700; margin-right:.4rem; }
.critical { background:#ffe8e6; color:#b42318; } .high { background:#fff0d9; color:#a15c00; } .elevated { background:#e7f1ff; color:#1769aa; } .monitor { background:#eaf7ef; color:#247a45; }
.small { color:#65758b; font-size:.88rem; }
</style>""", unsafe_allow_html=True)

@st.cache_data

def get_data():
    return load_dataset(ROOT / "data")

@st.cache_resource

def get_retriever():
    return NISTRetriever(ROOT / "data" / "nist_catalog.json")

data = get_data()
joined = build_joined_findings(data)
risks = top_risks(joined, 5)
retriever = get_retriever()

st.sidebar.markdown("## 🛡 TawasolPay")
st.sidebar.caption("Cyber Risk Command Center")
st.sidebar.divider()
st.sidebar.markdown("### Analysis scope")
st.sidebar.write("April 2026 MDR advisory")
st.sidebar.write("Production + development estate")
st.sidebar.divider()
st.sidebar.markdown("### AI engine")
st.sidebar.code("Ollama / qwen2.5-coder:1.5b", language="text")
st.sidebar.caption("If Ollama is unavailable, the app uses a grounded, deterministic explanation. No API key is required.")
st.sidebar.divider()
st.sidebar.caption("Evidence sources")
st.sidebar.caption("• TawasolPay data pack\n• Synthetic MDR threat report\n• Official NIST SP 800-53 Rev. 5 OSCAL catalog")

st.markdown("<div class='hero'><div class='small' style='color:#9edbd1'>SECURITY OPERATIONS · BOARD BRIEFING VIEW</div><h1>Risk Command Center</h1><p>Evidence-led prioritisation for TawasolPay’s payment, identity and customer platforms.</p></div>", unsafe_allow_html=True)

c1,c2,c3,c4,c5 = st.columns(5)
for col, label, value in [(c1,"Open vulnerabilities",len(data['vulnerabilities'])),(c2,"Assets monitored",len(data['assets'])),(c3,"Threat intel records",len(data['threat_intelligence'])),(c4,"Critical / high risks",int((joined['severity'].isin(['Critical','High'])).sum())),(c5,"NIST controls indexed",len(retriever.controls))]:
    col.markdown(f"<div class='kpi'><div class='label'>{label}</div><div class='value'>{value:,}</div></div>", unsafe_allow_html=True)

st.markdown("## Executive priority queue")
st.caption("Ranking combines CVSS, internet exposure, exploit availability, campaign correlation, ransomware association, service criticality, customer impact, control gaps and age. CVSS is only one input.")

for _, r in risks.iterrows():
    level = str(r['priority']).lower()
    control = retriever.best_for(row_to_dict(r))
    with st.container():
        st.markdown(f"<div class='risk-card'><div style='display:flex;justify-content:space-between;align-items:center'><div><span class='badge {level}'>{str(r['priority']).upper()}</span><span class='small'>RANK #{int(r['rank'])} · SCORE {r['risk_score']}/100</span></div><div class='small'>{r['vuln_id']}</div></div><h3 style='margin:.7rem 0 .25rem'>{r['vulnerability_name']}</h3><div class='small'><b>{r['asset_name']}</b> · {r['business_service']} · {r['environment']} · {r['cve']}</div><p style='margin:.85rem 0 .55rem'>{r['plain_english']}</p></div>", unsafe_allow_html=True)
        a,b,c = st.columns([1.1,1.1,1.8])
        a.metric("CVSS", f"{r['cvss']:.1f}")
        a.write(f"Exploit: **{'Available' if r['exploit_factor'] else 'Not observed'}**")
        b.write(f"**Threat match**\n\n{r['campaign_name'] if pd.notna(r['campaign_name']) else 'No direct campaign match'}")
        b.write(f"Ransomware: **{'Yes' if r['ransomware_factor'] else 'No'}**")
        c.write(f"**NIST retrieval · {control['id']} — {control['title']}**")
        c.caption(control['prose'][:520] + ('…' if len(control['prose']) > 520 else ''))
        if st.button("Generate analyst narrative", key=f"explain-{r['vuln_id']}"):
            with st.spinner("Asking local Ollama model…"):
                text, provider = explain(row_to_dict(r), control)
            st.info(f"**{provider}**  ·  {text}")

with st.expander("How the ranking works"):
    st.write("The score is intentionally not a CVSS sort. It gives the greatest weight to internet exposure and available exploitation, then adds campaign correlation, ransomware association and the blast radius of critical customer-facing services. Missing EDR and unauthenticated exposure act as compensating-control penalties; vulnerability age breaks close ties.")
    st.dataframe(risks[["rank","vuln_id","asset_name","business_service","risk_score","priority","cvss","campaign_name"]], use_container_width=True, hide_index=True)

st.markdown("## Analyst workspace")
tab1, tab2, tab3 = st.tabs(["Threat landscape", "NIST retrieval", "Data lineage"])
with tab1:
    st.markdown("### Campaigns correlated to the queue")
    cols = ["campaign_name","threat_actor","ransomware_association","exploit_maturity","summary"]
    st.dataframe(data['threat_intelligence'][cols].drop_duplicates().head(12), use_container_width=True, hide_index=True)
with tab2:
    query = st.text_input("Test the grounded NIST retriever", "internet-facing payment API authentication bypass")
    hits = retriever.retrieve(query, 5)
    for h in hits:
        st.markdown(f"**{h['id']} — {h['title']}**  \\  *{h['family']} · retrieval score {h['retrieval_score']}*")
        st.caption(h['prose'][:700])
with tab3:
    st.write("Every queue item is joined from the supplied vulnerability, asset, business-service and threat-intelligence records. Remediation guidance is retrieved from the bundled official NIST OSCAL catalog, not from the hint CSV.")
    st.json(source_stats(data))
    st.download_button("Download top-5 CSV", risks.to_csv(index=False), "tawasolpay_top5_risks.csv", "text/csv")
    st.caption("For the assessment, synthetic threat actors and report content are fictional and should not be used for operational security decisions.")
      
