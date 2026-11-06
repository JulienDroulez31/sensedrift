"""Tarification : grille statique indicative + API AWS Price List pour EC2.

Les tarifs statiques sont ceux d'eu-west-1 (Irlande) en USD ; les régions
européennes principales sont à ±10 %. Ils servent uniquement à *estimer* des
économies : les montants exacts proviennent de Cost Explorer quand il est
disponible.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

log = logging.getLogger("sensedrift")

HOURS_PER_MONTH = 730

# USD / Go-mois
EBS_GB_MONTH = {
    "gp3": 0.088, "gp2": 0.11, "io1": 0.138, "io2": 0.138,
    "st1": 0.05, "sc1": 0.0168, "standard": 0.055,
}
EBS_SNAPSHOT_GB_MONTH = 0.05
PUBLIC_IPV4_HOUR = 0.005
NAT_GATEWAY_HOUR = 0.048
ALB_HOUR = 0.0252
NLB_HOUR = 0.0252
CLB_HOUR = 0.028
CW_LOGS_GB_MONTH = 0.03
S3_STANDARD_GB_MONTH = 0.023
RDS_EXTENDED_SUPPORT_VCPU_HOUR = 0.10   # années 1 et 2

# Familles d'instances de génération précédente → remplaçant conseillé
PREVIOUS_GEN = {
    "t1": "t3", "t2": "t3", "m1": "m7g", "m2": "r7g", "m3": "m7g", "m4": "m7g",
    "c1": "c7g", "c3": "c7g", "c4": "c7g", "r3": "r7g", "r4": "r7g",
    "i2": "i4i", "d2": "d3", "g2": "g5", "p2": "p3", "x1": "x2idn",
}


def ebs_monthly_usd(volume_type: str, size_gb: int) -> float:
    return EBS_GB_MONTH.get(volume_type, 0.10) * size_gb


def ec2_ondemand_hourly_usd(ctx, instance_type: str, region: str) -> Optional[float]:
    """Prix à la demande Linux via l'API Price List (endpoint us-east-1).

    Renvoie None si l'API n'est pas accessible ; le résultat est mis en cache.
    """
    key = f"ec2price:{region}:{instance_type}"
    if key in ctx.cache:
        return ctx.cache[key]
    price = None
    try:
        pricing = ctx.client("pricing", "us-east-1")
        resp = pricing.get_products(
            ServiceCode="AmazonEC2",
            Filters=[{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in (
                ("instanceType", instance_type), ("regionCode", region),
                ("operatingSystem", "Linux"), ("tenancy", "Shared"),
                ("preInstalledSw", "NA"), ("capacitystatus", "Used"),
            )],
            MaxResults=1,
        )
        for raw in resp.get("PriceList", []):
            item = json.loads(raw) if isinstance(raw, str) else raw
            for term in item.get("terms", {}).get("OnDemand", {}).values():
                for dim in term.get("priceDimensions", {}).values():
                    price = float(dim["pricePerUnit"]["USD"])
    except Exception as exc:  # noqa: BLE001
        log.debug("Pricing API indisponible pour %s : %s", instance_type, exc)
    ctx.cache[key] = price
    return price


def instance_family(instance_type: str) -> str:
    return instance_type.removeprefix("db.").split(".")[0] if instance_type else ""
