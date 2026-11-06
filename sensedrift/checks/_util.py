"""Utilitaires partagés par les contrôles."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional


def paginate(client, op: str, key: str, **kw) -> Iterable[dict]:
    for page in client.get_paginator(op).paginate(**kw):
        yield from page.get(key, [])


def tag(resource: dict, key: str = "Name", default: str = "") -> str:
    for t in resource.get("Tags", []) or []:
        if t.get("Key") == key:
            return t.get("Value", default)
    return default


def days_since(dt: Optional[datetime]) -> Optional[int]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def eur(v: float) -> str:
    """Format monétaire français : 1 234,50 €."""
    s = f"{v:,.0f}" if abs(v) >= 100 else f"{v:,.2f}"
    return s.replace(",", " ").replace(".", ",") + " €"


def metric_stats(ctx, region: str, namespace: str, metric: str,
                 dim_name: str, ids: List[str], stat: str = "Average",
                 period: int = 86400, extra_dims: Optional[List[dict]] = None
                 ) -> Dict[str, List[float]]:
    """Récupère une métrique CloudWatch pour plusieurs ressources en un appel.

    Renvoie {resource_id: [valeurs journalières]} sur ``ctx.lookback_days``.
    """
    if not ids:
        return {}
    cw = ctx.client("cloudwatch", region)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=ctx.lookback_days)
    out: Dict[str, List[float]] = {i: [] for i in ids}
    for chunk_start in range(0, len(ids), 400):
        chunk = ids[chunk_start:chunk_start + 400]
        queries = [{
            "Id": f"m{n}",
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric,
                           "Dimensions": [{"Name": dim_name, "Value": rid}] + (extra_dims or [])},
                "Period": period, "Stat": stat,
            },
            "ReturnData": True,
        } for n, rid in enumerate(chunk)]
        token = None
        while True:
            kw = {"MetricDataQueries": queries, "StartTime": start, "EndTime": end}
            if token:
                kw["NextToken"] = token
            resp = cw.get_metric_data(**kw)
            for r in resp["MetricDataResults"]:
                rid = chunk[int(r["Id"][1:])]
                out[rid].extend(r.get("Values", []))
            token = resp.get("NextToken")
            if not token:
                break
    return out


def short_list(items: List[str], n: int = 6) -> str:
    if len(items) <= n:
        return ", ".join(items)
    return ", ".join(items[:n]) + f" … (+{len(items) - n})"
