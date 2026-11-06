"""Traçabilité : CloudTrail (global), AWS Config, rétention CloudWatch Logs."""
from __future__ import annotations

from .. import pricing as px
from ..models import COMPLIANCE, COST, CONF_MEDIUM, Severity
from ._util import paginate


def check_cloudtrail(ctx):
    # includeShadowTrails=True : un trail multi-région créé dans une autre région
    # (ou un trail d'organisation) couvre aussi la région interrogée.
    ct = ctx.client("cloudtrail", ctx.regions[0])
    trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
    logging_trails = []
    for t in trails:
        try:
            home = ctx.client("cloudtrail", t.get("HomeRegion", ctx.regions[0]))
            if home.get_trail_status(Name=t["TrailARN"]).get("IsLogging"):
                logging_trails.append(t)
        except Exception as exc:  # noqa: BLE001
            ctx.record_error("CloudTrail", t.get("HomeRegion", ""), exc)

    multi = [t for t in logging_trails if t.get("IsMultiRegionTrail")]
    if not multi:
        ctx.add("CLOUDTRAIL.MISSING", Severity.CRITICAL, COMPLIANCE, "CloudTrail",
                "Aucun trail CloudTrail multi-région actif",
                "Les actions réalisées sur le compte ne sont pas archivées durablement. L'historique "
                "de la console ne conserve que 90 jours de gestion : en cas d'incident, l'enquête "
                "sera très limitée."
                + (" Des trails existent mais ne couvrent pas toutes les régions." if logging_trails else ""),
                remediation="Créer un trail multi-région vers un bucket S3 dédié, avec validation "
                            "d'intégrité. Le premier trail de gestion est gratuit (hors stockage S3).",
                remediation_cli="aws cloudtrail create-trail --name sensedrift-trail "
                                "--s3-bucket-name <bucket-logs> --is-multi-region-trail "
                                "--enable-log-file-validation && aws cloudtrail start-logging "
                                "--name sensedrift-trail",
                references=["CIS 3.1"])

    for t in logging_trails:
        name = t["Name"]
        if not t.get("LogFileValidationEnabled"):
            ctx.add("CLOUDTRAIL.VALIDATION", Severity.MEDIUM, COMPLIANCE, "CloudTrail",
                    "Validation d'intégrité des logs désactivée",
                    "Sans validation, une modification ou suppression des journaux par un attaquant "
                    "ne serait pas détectable.",
                    remediation="Activer la validation des fichiers de logs.",
                    remediation_cli=f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
                    resource_id=name, references=["CIS 3.2"])
        if not t.get("KmsKeyId"):
            ctx.add("CLOUDTRAIL.KMS", Severity.LOW, COMPLIANCE, "CloudTrail",
                    "Logs CloudTrail non chiffrés avec KMS",
                    "Les journaux sont chiffrés par défaut avec SSE-S3, mais une clé KMS permet de "
                    "contrôler et tracer qui peut les lire.",
                    remediation="Configurer une clé KMS gérée par le client sur le trail.",
                    resource_id=name, references=["CIS 3.5"])
        if not t.get("CloudWatchLogsLogGroupArn"):
            ctx.add("CLOUDTRAIL.ALERTING", Severity.LOW, COMPLIANCE, "CloudTrail",
                    "Aucune alerte temps réel sur les événements sensibles",
                    "Le trail n'est pas relié à CloudWatch Logs : impossible d'être alerté d'une "
                    "connexion root, d'un changement IAM ou d'une désactivation de CloudTrail.",
                    remediation="Envoyer le trail vers CloudWatch Logs et créer des alarmes sur les "
                                "événements critiques (ou utiliser EventBridge).",
                    resource_id=name, effort="Moyen")


def check_config(ctx, region: str):
    cfg = ctx.client("config", region)
    status = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    if not any(s.get("recording") for s in status):
        ctx.add("CONFIG.DISABLED", Severity.LOW, COMPLIANCE, "AWS Config",
                "AWS Config non activé",
                "AWS Config conserve l'historique de configuration de chaque ressource : "
                "indispensable pour savoir « qui a changé quoi, quand » et pour les audits "
                "de conformité (ISO 27001, SOC 2, HDS).",
                remediation="Activer l'enregistreur AWS Config (coût proportionnel au nombre de "
                            "changements enregistrés).",
                region=region, references=["CIS 3.3"])


def check_log_retention(ctx, region: str):
    logs = ctx.client("logs", region)
    for g in paginate(logs, "describe_log_groups", "logGroups"):
        if g.get("retentionInDays"):
            continue
        gb = g.get("storedBytes", 0) / 1024 ** 3
        if gb < 1:
            continue
        monthly = gb * px.CW_LOGS_GB_MONTH
        ctx.add("LOGS.NO_RETENTION", Severity.LOW, COST, "CloudWatch Logs",
                "Groupes de logs conservés indéfiniment",
                "Ces groupes de logs n'ont aucune durée de rétention : le volume stocké, et donc la "
                "facture, augmente chaque mois sans limite.",
                remediation="Définir une rétention adaptée (ex. 30 à 90 jours), et exporter vers S3 "
                            "Glacier ce qui doit être archivé plus longtemps.",
                remediation_cli=f"aws logs put-retention-policy --log-group-name {g['logGroupName']} "
                                f"--retention-in-days 90 --region {region}",
                resource_id=g["logGroupName"], resource_detail=f"{gb:,.1f} Go",
                region=region, monthly_saving_eur=ctx.usd(monthly * 0.7),
                saving_confidence=CONF_MEDIUM)
