"""Données de facturation réelles : Cost Explorer et Compute Optimizer."""
from __future__ import annotations

import threading
from datetime import date, timedelta

from ..models import COST, GOVERNANCE, CONF_HIGH, CONF_MEDIUM, CostOverview, Severity

MONTHS_FR = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août",
             "sept.", "oct.", "nov.", "déc."]
_co_lock = threading.Lock()


def _to_eur(ctx, amount: float, unit: str) -> float:
    return round(amount, 2) if unit == "EUR" else ctx.usd(amount)


def check_cost_explorer(ctx):
    if not ctx.use_cost_explorer:
        return
    ce = ctx.client("ce", "us-east-1")
    today = date.today()
    first_this_month = today.replace(day=1)
    start = (first_this_month - timedelta(days=95)).replace(day=1)

    overview = CostOverview()
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": first_this_month.isoformat()},
        Granularity="MONTHLY", Metrics=["UnblendedCost"])
    for r in resp["ResultsByTime"]:
        d = date.fromisoformat(r["TimePeriod"]["Start"])
        amt = r["Total"]["UnblendedCost"]
        overview.months.append(f"{MONTHS_FR[d.month - 1]} {d.year}")
        overview.monthly_totals.append(_to_eur(ctx, float(amt["Amount"]), amt["Unit"]))

    last_start = (first_this_month - timedelta(days=1)).replace(day=1)
    resp = ce.get_cost_and_usage(
        TimePeriod={"Start": last_start.isoformat(), "End": first_this_month.isoformat()},
        Granularity="MONTHLY", Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    groups = resp["ResultsByTime"][0].get("Groups", []) if resp["ResultsByTime"] else []
    rows = [(g["Keys"][0], _to_eur(ctx, float(g["Metrics"]["UnblendedCost"]["Amount"]),
                                   g["Metrics"]["UnblendedCost"]["Unit"])) for g in groups]
    overview.by_service_last_month = sorted([r for r in rows if r[1] >= 0.01],
                                            key=lambda r: -r[1])

    next_month = (first_this_month + timedelta(days=32)).replace(day=1)
    if today + timedelta(days=1) < next_month:
        try:
            fc = ce.get_cost_forecast(
                TimePeriod={"Start": (today + timedelta(days=1)).isoformat(),
                            "End": next_month.isoformat()},
                Metric="UNBLENDED_COST", Granularity="MONTHLY")
            mtd = ce.get_cost_and_usage(
                TimePeriod={"Start": first_this_month.isoformat(),
                            "End": (today + timedelta(days=1)).isoformat()},
                Granularity="MONTHLY", Metrics=["UnblendedCost"])["ResultsByTime"]
            spent = sum(float(r["Total"]["UnblendedCost"]["Amount"]) for r in mtd)
            unit = fc["Total"]["Unit"]
            overview.forecast_current_month = _to_eur(ctx, spent + float(fc["Total"]["Amount"]), unit)
        except Exception as exc:  # noqa: BLE001 — pas assez d'historique pour une prévision
            ctx.record_error("Cost Explorer (prévision)", "global", exc)
    ctx.cost = overview

    # ── Savings Plans Compute
    try:
        rec = ce.get_savings_plans_purchase_recommendation(
            SavingsPlansType="COMPUTE_SP", TermInYears="ONE_YEAR", PaymentOption="NO_UPFRONT",
            LookbackPeriodInDays="THIRTY_DAYS")
        s = rec.get("SavingsPlansPurchaseRecommendation", {}) \
               .get("SavingsPlansPurchaseRecommendationSummary", {})
        saving = float(s.get("EstimatedMonthlySavingsAmount", 0) or 0)
        if saving >= 10:
            ctx.add("COST.SAVINGS_PLAN", Severity.MEDIUM, COST, "Savings Plans",
                    "Engagement Compute Savings Plan recommandé",
                    f"D'après l'usage des 30 derniers jours, AWS recommande un engagement de "
                    f"{float(s.get('HourlyCommitmentToPurchase', 0)):.2f} $/h sur 1 an sans "
                    f"paiement initial, soit environ {float(s.get('EstimatedSavingsPercentage', 0)):.0f} % "
                    "d'économie sur la part de calcul couverte (EC2, Fargate, Lambda).",
                    remediation="Appliquer d'abord le redimensionnement et le nettoyage, puis "
                                "souscrire un Savings Plan sur la consommation stable restante.",
                    resource_id="Compute Savings Plan · 1 an · sans avance",
                    monthly_saving_eur=ctx.usd(saving), saving_confidence=CONF_MEDIUM)
    except Exception as exc:  # noqa: BLE001
        ctx.record_error("Cost Explorer (Savings Plans)", "global", exc)

    # ── Instances réservées RDS
    try:
        rec = ce.get_reservation_purchase_recommendation(
            Service="Amazon Relational Database Service", TermInYears="ONE_YEAR",
            PaymentOption="NO_UPFRONT", LookbackPeriodInDays="THIRTY_DAYS")
        for r in rec.get("Recommendations", []):
            s = r.get("RecommendationSummary", {})
            saving = float(s.get("TotalEstimatedMonthlySavingsAmount", 0) or 0)
            if saving >= 10:
                ctx.add("COST.RDS_RI", Severity.MEDIUM, COST, "RDS",
                        "Instances réservées RDS recommandées",
                        "Des bases tournent en continu au tarif à la demande. Une réservation d'un "
                        "an sans paiement initial réduit leur coût.",
                        remediation="Réserver les instances RDS stables (production) après "
                                    "validation de leur dimensionnement.",
                        resource_id="RDS Reserved Instances · 1 an · sans avance",
                        monthly_saving_eur=_to_eur(ctx, saving, s.get("CurrencyCode", "USD")),
                        saving_confidence=CONF_MEDIUM)
    except Exception as exc:  # noqa: BLE001
        ctx.record_error("Cost Explorer (réservations RDS)", "global", exc)


def check_compute_optimizer(ctx, region: str):
    co = ctx.client("compute-optimizer", region)
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        with _co_lock:
            if ctx.cache.get("co_reported"):
                return
            ctx.cache["co_reported"] = True
        ctx.add("COMPUTEOPTIMIZER.DISABLED", Severity.LOW, GOVERNANCE, "Compute Optimizer",
                "AWS Compute Optimizer non activé",
                "Compute Optimizer (gratuit) analyse l'utilisation réelle des instances EC2, volumes "
                "EBS, fonctions Lambda et bases RDS pour recommander la bonne taille.",
                remediation="Activer Compute Optimizer pour le compte (les premières recommandations "
                            "arrivent sous 24 h).",
                remediation_cli="aws compute-optimizer update-enrollment-status --status Active")
        return

    ctx.cache[f"co_enabled:{region}"] = True
    token = None
    while True:
        kw = {"filters": [{"name": "Finding", "values": ["Overprovisioned"]}]}
        if token:
            kw["nextToken"] = token
        resp = co.get_ec2_instance_recommendations(**kw)
        for r in resp.get("instanceRecommendations", []):
            opts = sorted(r.get("recommendationOptions", []), key=lambda o: o.get("rank", 99))
            if not opts:
                continue
            best = opts[0]
            so = best.get("savingsOpportunity", {}).get("estimatedMonthlySavings", {})
            saving = float(so.get("value", 0) or 0)
            ctx.add("EC2.OVERPROVISIONED", Severity.MEDIUM, COST, "EC2",
                    "Instances surdimensionnées (Compute Optimizer)",
                    "D'après l'analyse de Compute Optimizer sur l'utilisation réelle (CPU, mémoire si "
                    "disponible, réseau), ces instances peuvent passer à une taille inférieure sans "
                    "dégrader les performances.",
                    remediation="Redimensionner l'instance vers le type recommandé lors d'une fenêtre "
                                "de maintenance (arrêt/démarrage nécessaire).",
                    resource_id=r.get("instanceArn", "").split("/")[-1],
                    resource_detail=f"{r.get('instanceName', '')} · {r.get('currentInstanceType')} → "
                                    f"{best.get('instanceType')}".strip(" ·"),
                    region=region,
                    monthly_saving_eur=_to_eur(ctx, saving, so.get("currency", "USD")) if saving else None,
                    saving_confidence=CONF_HIGH, effort="Moyen")
        token = resp.get("nextToken")
        if not token:
            break
