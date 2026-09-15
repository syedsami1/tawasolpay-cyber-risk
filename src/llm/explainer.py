import os
import requests


def _fallback(risk, control):
    return (f"{risk['plain_english']} The affected asset is {risk['asset_name']} ({risk['vendor_product']}) in {risk['environment']}. "
            f"The vulnerability is {risk['vulnerability_name']} ({risk['cve']}) with CVSS {risk['cvss']}. "
            f"Recommended control: {control['id']} — {control['title']}. "
            f"The retrieved NIST guidance emphasizes {control['prose'][:420].strip()}"
            )


def explain(risk, control, model=None, base_url=None):
    model = model or os.getenv("OLLAMA_MODEL", "qwen2.5-coder:1.5b")
    base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    prompt = f"""You are a cyber risk analyst. Write one concise executive-ready paragraph, grounded only in the evidence below. Do not invent facts. Include the risk driver, impacted service, threat campaign, and concrete NIST remediation guidance.
RISK: {risk['plain_english']}
ASSET: {risk['asset_name']} | SERVICE: {risk['business_service']} | VULNERABILITY: {risk['vulnerability_name']} | CVE: {risk['cve']} | CVSS: {risk['cvss']}
THREAT: {risk.get('campaign_name','No matched campaign')} | {risk.get('summary','No matched threat intelligence')}
NIST CONTROL: {control['id']} {control['title']} | {control['prose']}
"""
    try:
        r = requests.post(f"{base_url.rstrip('/')}/api/generate", json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.1}}, timeout=12)
        r.raise_for_status()
        text = r.json().get("response", "").strip()
        if text:
            return text, "Ollama"
    except Exception:
        pass
    return _fallback(risk, control), "Grounded fallback"
      
