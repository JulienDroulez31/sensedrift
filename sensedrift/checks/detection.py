"""Services de détection : GuardDuty, Security Hub, IAM Access Analyzer."""
from __future__ import annotations

import botocore.exceptions

from ..models import COMPLIANCE, SECURITY, Severity


def check_guardduty(ctx, region: str):
    gd = ctx.client("guardduty", region)
    detectors = gd.list_detectors()["DetectorIds"]
    if not detectors:
        ctx.add("GUARDDUTY.DISABLED", Severity.HIGH, SECURITY, "GuardDuty",
                "GuardDuty non activé",
                "GuardDuty analyse en continu CloudTrail, les flux réseau et les requêtes DNS pour "
                "détecter les identifiants volés, le minage de cryptomonnaie ou les accès depuis des "
                "IP malveillantes. Sans lui, une compromission peut passer inaperçue des semaines.",
                remediation="Activer GuardDuty dans chaque région utilisée (30 jours d'essai "
                            "gratuit, puis quelques euros par mois sur un petit compte).",
                remediation_cli=f"aws guardduty create-detector --enable --region {region}",
                region=region)
        return

    for det in detectors:
        if gd.get_detector(DetectorId=det).get("Status") != "ENABLED":
            ctx.add("GUARDDUTY.DISABLED", Severity.HIGH, SECURITY, "GuardDuty",
                    "GuardDuty suspendu",
                    "Le détecteur existe mais est suspendu : aucune menace n'est analysée.",
                    remediation="Réactiver le détecteur.",
                    resource_id=det, region=region)
            continue
        ids = gd.list_findings(DetectorId=det, FindingCriteria={"Criterion": {
            "severity": {"Gte": 7}, "service.archived": {"Eq": ["false"]}}},
            MaxResults=50)["FindingIds"]
        if ids:
            details = gd.get_findings(DetectorId=det, FindingIds=ids[:50])["Findings"]
            for f in details:
                ctx.add("GUARDDUTY.FINDING", Severity.CRITICAL, SECURITY, "GuardDuty",
                        "Alertes GuardDuty de haute sévérité non traitées",
                        "GuardDuty a détecté une activité suspecte ou malveillante qui n'a pas été "
                        "archivée. Chaque alerte doit être analysée sans délai.",
                        remediation="Analyser l'alerte dans la console GuardDuty, appliquer le plan "
                                    "de réponse, puis archiver.",
                        resource_id=f.get("Type", ""), resource_detail=f.get("Title", "")[:90],
                        region=region)


def check_securityhub(ctx, region: str):
    sh = ctx.client("securityhub", region)
    try:
        sh.describe_hub()
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] in ("InvalidAccessException", "ResourceNotFoundException"):
            ctx.add("SECURITYHUB.DISABLED", Severity.LOW, COMPLIANCE, "Security Hub",
                    "AWS Security Hub non activé",
                    "Security Hub centralise les alertes de sécurité et évalue en continu le compte "
                    "selon les référentiels CIS et AWS Foundational Security Best Practices.",
                    remediation="Activer Security Hub avec le standard AWS FSBP (coût proportionnel "
                                "au nombre de contrôles évalués).",
                    region=region, references=["CIS 4.16"])
            return
        raise


def check_access_analyzer(ctx, region: str):
    aa = ctx.client("accessanalyzer", region)
    analyzers = [a for a in aa.list_analyzers()["analyzers"] if a.get("status") == "ACTIVE"]
    if not analyzers:
        ctx.add("ACCESSANALYZER.DISABLED", Severity.LOW, SECURITY, "IAM Access Analyzer",
                "IAM Access Analyzer non activé",
                "Access Analyzer (gratuit pour l'analyse d'accès externe) détecte automatiquement les "
                "ressources partagées hors du compte : buckets, rôles, clés KMS, snapshots…",
                remediation="Créer un analyseur de type « compte » dans chaque région utilisée.",
                remediation_cli=f"aws accessanalyzer create-analyzer --analyzer-name sensedrift "
                                f"--type ACCOUNT --region {region}",
                region=region, references=["CIS 1.20"])
        return
    for a in analyzers:
        active = aa.list_findings(analyzerArn=a["arn"], filter={"status": {"eq": ["ACTIVE"]}},
                                  maxResults=50).get("findings", [])
        for f in active:
            if f.get("isPublic"):
                ctx.add("ACCESSANALYZER.PUBLIC", Severity.HIGH, SECURITY, "IAM Access Analyzer",
                        "Ressources accessibles publiquement (Access Analyzer)",
                        "Access Analyzer signale des ressources accessibles par n'importe qui.",
                        remediation="Vérifier chaque ressource et retirer l'accès public s'il n'est "
                                    "pas voulu, sinon archiver l'alerte.",
                        resource_id=f.get("resource", "").split(":")[-1],
                        resource_detail=f.get("resourceType", ""), region=region)
