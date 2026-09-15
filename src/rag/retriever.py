import json
import re
from pathlib import Path

class NISTRetriever:
    """Small dependency-free lexical RAG over the official OSCAL SP 800-53 Rev. 5 catalog."""
    def __init__(self, catalog_path: str | Path):
        raw = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
        self.controls = []
        for group in raw["catalog"].get("groups", []):
            family = group.get("title", "")
            for c in group.get("controls", []):
                prose = " ".join(p.get("prose", "") if isinstance(p, dict) else str(p) for p in c.get("parts", []))
                self.controls.append({"id": c.get("id", ""), "title": c.get("title", ""), "family": family, "prose": prose})

    def _tokens(self, text):
        return set(re.findall(r"[a-z0-9]{3,}", str(text).lower()))

    def retrieve(self, query: str, k=3):
        q = self._tokens(query)
        scored = []
        for c in self.controls:
            text = f"{c['id']} {c['title']} {c['family']} {c['prose']}"
            t = self._tokens(text)
            overlap = len(q & t)
            phrase = sum(1 for term in q if term in text.lower())
            score = overlap * 2 + phrase * .1
            if score:
                scored.append((score, c))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{**c, "retrieval_score": round(score, 2)} for score, c in scored[:k]]

    def best_for(self, finding: dict):
        query = " ".join(str(finding.get(k, "")) for k in ["vulnerability_name", "affected_component", "asset_type", "business_service", "exploit_available", "patch_available"])
        hits = self.retrieve(query, 3)
        return hits[0] if hits else {"id": "AC-2", "title": "Account Management", "family": "Access Control", "prose": "Manage system accounts and privileges."}
      
