"""Exports machine : JSON (intégration, historique) et CSV (tableur, devis)."""
from __future__ import annotations

import csv
import json

from .. import __version__


def export_json(ctx, path: str):
    data = {
        "tool": "SenseDrift", "version": __version__,
        "account_id": ctx.account_id, "account_alias": ctx.account_alias,
        "regions": ctx.regions,
        "started_at": ctx.started_at.isoformat(),
        "finished_at": ctx.finished_at.isoformat() if ctx.finished_at else None,
        "posture_score": ctx.posture_score(), "grade": ctx.grade(ctx.posture_score()),
        "estimated_monthly_saving_eur": ctx.total_monthly_saving,
        "cost_overview": ctx.cost.__dict__ if ctx.cost else None,
        "findings": [f.to_dict() for f in ctx.findings],
        "coverage_issues": [c.__dict__ for c in ctx.coverage],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, default=str)


def export_csv(ctx, path: str):
    cols = ["check_id", "severity", "category", "service", "title", "resource_id",
            "resource_detail", "region", "monthly_saving_eur", "saving_confidence",
            "effort", "remediation", "remediation_cli", "references"]
    # utf-8-sig : ouverture correcte des accents dans Excel
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, delimiter=";")
        w.writeheader()
        for f in ctx.findings:
            d = f.to_dict()
            d["references"] = ", ".join(d["references"])
            w.writerow({k: d.get(k, "") for k in cols})
