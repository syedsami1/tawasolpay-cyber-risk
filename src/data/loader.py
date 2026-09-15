from pathlib import Path
import pandas as pd
import json


def load_dataset(data_dir: str | Path) -> dict[str, pd.DataFrame | str]:
    root = Path(data_dir)
    out = {}
    for name in ["assets", "vulnerabilities", "threat_intelligence", "business_services", "remediation_guidance"]:
        out[name] = pd.read_csv(root / f"{name}.csv")
    out["threat_report"] = (root / "synthetic_threat_report.md").read_text(encoding="utf-8")
    kev_path = root / "cisa_kev.json"
    out["cisa_kev"] = json.loads(kev_path.read_text(encoding="utf-8")) if kev_path.exists() else {"vulnerabilities": []}
    return out


def build_joined_findings(data: dict) -> pd.DataFrame:
    v = data["vulnerabilities"].copy()
    a = data["assets"].copy()
    s = data["business_services"].copy()
    t = data["threat_intelligence"].copy()
    joined = v.merge(a, on="asset_id", how="left", suffixes=("", "_asset"))
    joined = joined.merge(s, on="business_service", how="left", suffixes=("", "_service"))
    # One vulnerability can match more than one campaign. Keep the best evidence per finding.
    t2 = t.rename(columns={"matched_cve_or_control": "cve"})
    joined = joined.merge(t2, on="cve", how="left", suffixes=("", "_intel"))
    kev_cves = {x.get("cveID") for x in data.get("cisa_kev", {}).get("vulnerabilities", [])}
    joined["cisa_kev"] = joined["cve"].isin(kev_cves)
    return joined


def clean_bool(value) -> bool:
    return str(value).strip().lower() in {"yes", "true", "1"}


def normalize_text(value) -> str:
    return "" if pd.isna(value) else str(value)


def row_to_dict(row) -> dict:
    return {k: (None if pd.isna(v) else v) for k, v in row.to_dict().items()}


def source_stats(data: dict) -> dict[str, int]:
    return {k: len(v) for k, v in data.items() if hasattr(v, "__len__") and not isinstance(v, str)}


if __name__ == "__main__":
    print(source_stats(load_dataset(Path(__file__).parents[2] / "data")))
      
