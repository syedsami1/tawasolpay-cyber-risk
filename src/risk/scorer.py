import pandas as pd
from src.data.loader import clean_bool


def _norm(value, low=0.0, high=1.0):
    return max(low, min(high, float(value)))


def score_findings(joined: pd.DataFrame) -> pd.DataFrame:
    df = joined.copy()
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0)
    df["days_open"] = pd.to_numeric(df["days_open"], errors="coerce").fillna(0)
    df["internet_factor"] = df["internet_exposed"].map(lambda x: 1.0 if clean_bool(x) else 0.0)
    df["exploit_factor"] = df["exploit_available"].map(lambda x: 1.0 if clean_bool(x) else 0.0)
    df["ransomware_factor"] = df["ransomware_association"].map(lambda x: 1.0 if clean_bool(x) else 0.0)
    df["campaign_factor"] = df["intel_id"].notna().astype(float)
    df["kev_factor"] = df["cisa_kev"].fillna(False).astype(float)
    df["criticality_factor"] = df["criticality"].map({"Critical": 1.0, "High": .8, "Medium": .55, "Low": .25}).fillna(.25)
    df["customer_factor"] = df["customer_facing"].map(lambda x: 1.0 if clean_bool(x) else 0.0)
    df["control_gap_factor"] = ((df["edr_installed"].map(lambda x: 0.0 if clean_bool(x) else 1.0)) * .6 + (df["auth_required"].map(lambda x: 1.0 if str(x).lower() == "no" else 0.0)) * .4)
    df["age_factor"] = df["days_open"].map(lambda x: _norm(x / 120))
    # Weights reflect the MDR advisory: exposure and active exploitation precede raw severity.
    df["risk_score"] = (df["cvss"] / 10 * 18 + df["internet_factor"] * 18 + df["exploit_factor"] * 16 + df["kev_factor"] * 7 + df["campaign_factor"] * 9 + df["ransomware_factor"] * 12 + df["criticality_factor"] * 10 + df["customer_factor"] * 5 + df["control_gap_factor"] * 5 + df["age_factor"] * 2).round(1)
    df["priority"] = pd.cut(df["risk_score"], bins=[-1, 45, 65, 80, 200], labels=["Monitor", "Elevated", "High", "Critical"])
    df = df.sort_values(["risk_score", "cvss"], ascending=False).reset_index(drop=True)
    df["rank"] = df.index + 1
    return df


def explain_row(r) -> str:
    drivers = []
    if r["internet_factor"]: drivers.append("internet exposure")
    if r["exploit_factor"]: drivers.append("an available exploit")
    if r["kev_factor"]: drivers.append("a CISA Known Exploited Vulnerability listing")
    if r["campaign_factor"]: drivers.append(f"the {r['campaign_name']} campaign")
    if r["ransomware_factor"]: drivers.append("ransomware association")
    if r["criticality_factor"] >= .8: drivers.append(f"{r['criticality'].lower()} business criticality")
    if r["control_gap_factor"] >= .5: drivers.append("a compensating-control gap")
    if not drivers: drivers.append("the combination of severity and exposure context")
    return f"This ranks #{int(r['rank'])} because {', '.join(drivers[:-1])}{' and ' if len(drivers)>1 else ''}{drivers[-1]}, creating a {r['priority'].lower()} risk to {r['business_service']}."


def top_risks(joined: pd.DataFrame, n=5) -> pd.DataFrame:
    scored = score_findings(joined).head(n).copy()
    scored["plain_english"] = scored.apply(explain_row, axis=1)
    return scored
      
