"""Génère un rapport d'exemple anonymisé (données fictives), sans accès AWS.

Usage : python examples/demo_report.py  →  examples/exemple-rapport-sensedrift.pdf
Idéal pour le bouton « Voir un exemple de rapport » du site.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import boto3  # noqa: E402

from sensedrift.models import (COMPLIANCE, CONF_HIGH, CONF_LOW, CONF_MEDIUM, COST,  # noqa: E402
                               GOVERNANCE, RESILIENCE, SECURITY, AuditContext, CostOverview,
                               CoverageIssue, Severity)
from sensedrift.report import generate_pdf  # noqa: E402

ctx = AuditContext(boto3.Session(region_name="eu-west-3"), ["eu-west-3", "eu-west-1"])
ctx.account_id, ctx.account_alias = "123456789012", "exemple-prod"
ctx.finished_at = datetime.now(timezone.utc)
ctx.started_at = ctx.finished_at - timedelta(seconds=74)
ctx.checks_run = [f"{s} (x)" for s in ("EC2", "EBS", "S3", "IAM", "RDS", "Lambda", "VPC", "CloudTrail",
                                       "GuardDuty", "NAT Gateway", "Elastic Load Balancing",
                                       "CloudWatch Logs", "AWS Config", "Security Hub")]
ctx.cost = CostOverview(months=["août 2026", "sept. 2026", "oct. 2026"],
                        monthly_totals=[3912.40, 4105.85, 4287.10],
                        forecast_current_month=4350.00,
                        by_service_last_month=[
                            ("Amazon Elastic Compute Cloud - Compute", 1764.20),
                            ("Amazon Relational Database Service", 1038.55), ("EC2 - Other", 512.80),
                            ("Amazon Simple Storage Service", 288.10), ("Amazon CloudWatch", 214.75),
                            ("Amazon Virtual Private Cloud", 168.40), ("Elastic Load Balancing", 121.30),
                            ("AWS Lambda", 64.20), ("Amazon Route 53", 22.10), ("AWS KMS", 12.40),
                        ])
A = ctx.add
A("IAM.ROOT_MFA", Severity.CRITICAL, SECURITY, "IAM", "MFA non activé sur le compte root",
  "Le compte root a tous les droits, y compris fermer le compte ou modifier la facturation. "
  "Protégé par un simple mot de passe, il est la cible n°1.",
  remediation="Activer immédiatement un MFA (clé FIDO2 de préférence) sur le root, et réserver ce "
              "compte aux rares opérations qui l'exigent.", resource_id="root", references=["CIS 1.5"])
for sg, d in (("sg-0a41c9e2", "admin-bastion · TCP 22 — dont 22 (SSH)"),
              ("sg-07be11f0", "legacy-db · TCP 5432 — dont 5432 (PostgreSQL)")):
    A("EC2.SG_OPEN", Severity.CRITICAL, SECURITY, "EC2", "Security Groups ouverts sur Internet",
      "Ces règles autorisent des connexions entrantes depuis n'importe quelle adresse IP. Les ports "
      "d'administration et de bases de données exposés sont scannés en permanence par des robots.",
      remediation="Restreindre la source à des plages IP connues. Pour l'administration, utiliser AWS "
                  "Systems Manager Session Manager (aucun port à ouvrir).",
      resource_id=sg, resource_detail=d, region="eu-west-3", references=["CIS 5.2", "CIS 5.3"])
A("CLOUDTRAIL.MISSING", Severity.CRITICAL, COMPLIANCE, "CloudTrail",
  "Aucun trail CloudTrail multi-région actif",
  "Les actions réalisées sur le compte ne sont pas archivées durablement. En cas d'incident, "
  "l'enquête sera très limitée.",
  remediation="Créer un trail multi-région vers un bucket S3 dédié, avec validation d'intégrité.",
  remediation_cli="aws cloudtrail create-trail --name org-trail --s3-bucket-name <bucket-logs> "
                  "--is-multi-region-trail --enable-log-file-validation", references=["CIS 3.1"])
for i, n in enumerate(("api-1", "api-2", "worker-1", "worker-2", "cron")):
    A("EC2.IMDSV2", Severity.HIGH, SECURITY, "EC2", "IMDSv2 non imposé sur les instances",
      "Ces instances acceptent encore IMDSv1. Une vulnérabilité SSRF suffit à voler les identifiants "
      "IAM de l'instance.", remediation="Imposer IMDSv2 (aucun redémarrage nécessaire).",
      remediation_cli="aws ec2 modify-instance-metadata-options --instance-id i-0abc… "
                      "--http-tokens required", resource_id=f"i-0{i}4f2a9c1e7b3d5{i}",
      resource_detail=n, region="eu-west-3", references=["CIS 5.6"])
A("IAM.USER_MFA", Severity.HIGH, SECURITY, "IAM", "Utilisateurs console sans MFA",
  "Ces utilisateurs se connectent à la console avec un simple mot de passe.",
  remediation="Imposer le MFA, ou mieux : migrer vers IAM Identity Center (SSO).",
  resource_id="m.durand", references=["CIS 1.10"])
A("RDS.EXTENDED_SUPPORT", Severity.HIGH, COST, "RDS",
  "Moteurs de base en fin de support (RDS Extended Support facturé)",
  "Le support standard de postgres 12 a pris fin le 28/02/2025. AWS facture désormais un "
  "supplément Extended Support par vCPU et par heure.",
  remediation="Planifier la montée de version majeure (Blue/Green Deployments RDS).",
  resource_id="prod-postgres", resource_detail="postgres 12.19 · db.m6g.xlarge", region="eu-west-3",
  monthly_saving_eur=251.12, saving_confidence=CONF_HIGH, effort="Élevé")
A("RDS.NO_BACKUP", Severity.HIGH, RESILIENCE, "RDS", "Bases sans sauvegarde automatique",
  "Aucune sauvegarde automatique : une erreur humaine ou une corruption serait irréversible.",
  remediation="Activer les sauvegardes automatiques (7 jours minimum).",
  resource_id="analytics-mysql", resource_detail="mysql 8.4 · db.t4g.medium", region="eu-west-3")
A("EC2.OVERPROVISIONED", Severity.MEDIUM, COST, "EC2", "Instances surdimensionnées (Compute Optimizer)",
  "D'après l'utilisation réelle, ces instances peuvent passer à une taille inférieure.",
  remediation="Redimensionner l'instance vers le type recommandé.", resource_id="i-0f3e9b2c4a1d",
  resource_detail="worker-1 · m5.2xlarge → m6g.xlarge", region="eu-west-3",
  monthly_saving_eur=212.40, saving_confidence=CONF_HIGH, effort="Moyen")
A("EC2.OVERPROVISIONED", Severity.MEDIUM, COST, "EC2", "Instances surdimensionnées (Compute Optimizer)",
  "", resource_id="i-02a7c1e9f4b0", resource_detail="worker-2 · c5.2xlarge → c6g.large",
  region="eu-west-3", monthly_saving_eur=176.90, saving_confidence=CONF_HIGH, effort="Moyen")
A("COST.SAVINGS_PLAN", Severity.MEDIUM, COST, "Savings Plans", "Engagement Compute Savings Plan recommandé",
  "D'après l'usage des 30 derniers jours, AWS recommande un engagement de 1,42 $/h sur 1 an.",
  remediation="Appliquer d'abord le redimensionnement, puis souscrire un Savings Plan.",
  resource_id="Compute Savings Plan · 1 an · sans avance", monthly_saving_eur=318.00,
  saving_confidence=CONF_MEDIUM)
A("NAT.IDLE", Severity.MEDIUM, COST, "NAT Gateway", "NAT Gateways sans trafic",
  "Moins de 100 Mo transférés sur 14 jours.", remediation="Supprimer la NAT Gateway inutile.",
  resource_id="nat-0b7d2e4f19a3", resource_detail="12 Mo / 14 j", region="eu-west-1",
  monthly_saving_eur=30.13, saving_confidence=CONF_HIGH)
for v, gb in (("vol-0a1b2c3d", 500), ("vol-0e4f5a6b", 250), ("vol-09c8d7e6", 100)):
    A("EBS.UNATTACHED", Severity.MEDIUM, COST, "EBS", "Volumes EBS non attachés",
      "Ces volumes ne sont rattachés à aucune instance mais sont facturés chaque mois.",
      remediation="Créer un snapshot si nécessaire, puis supprimer le volume.",
      resource_id=v, resource_detail=f"gp2 · {gb} Go", region="eu-west-3",
      monthly_saving_eur=round(gb * 0.11 * 0.86, 2), saving_confidence=CONF_HIGH)
A("EBS.GP2", Severity.LOW, COST, "EBS", "Volumes gp2 à migrer vers gp3",
  "gp3 coûte 20 % de moins que gp2 avec de meilleures performances de base.",
  remediation="Modifier le type de volume en gp3 (à chaud).", resource_id="vol-0123abcd",
  resource_detail="api-1 · 1000 Go", region="eu-west-3", monthly_saving_eur=18.92,
  saving_confidence=CONF_HIGH)
A("LOGS.NO_RETENTION", Severity.LOW, COST, "CloudWatch Logs", "Groupes de logs conservés indéfiniment",
  "Ces groupes de logs n'ont aucune durée de rétention.",
  remediation="Définir une rétention adaptée (30 à 90 jours).", resource_id="/aws/lambda/ingest",
  resource_detail="1 840 Go", region="eu-west-3", monthly_saving_eur=33.24, saving_confidence=CONF_MEDIUM)
A("VPC.FLOW_LOGS", Severity.MEDIUM, COMPLIANCE, "VPC", "VPC Flow Logs désactivés",
  "Sans Flow Logs, aucune trace des connexions réseau.", remediation="Activer les Flow Logs vers S3.",
  resource_id="vpc-0d4e5f6a", resource_detail="prod", region="eu-west-3", references=["CIS 3.7"])
A("S3.VERSIONING", Severity.LOW, RESILIENCE, "S3", "Versioning désactivé",
  "Sans versioning, une suppression accidentelle détruit définitivement les objets.",
  remediation="Activer le versioning avec expiration des anciennes versions.",
  resource_id="exemple-uploads", region="eu-west-3")
A("EC2.UNTAGGED", Severity.LOW, GOVERNANCE, "EC2", "Instances sans aucun tag",
  "Sans tags, les coûts ne peuvent pas être attribués.", remediation="Définir une politique de tagging.",
  resource_id="i-0c1d2e3f4a5b", region="eu-west-3", effort="Moyen")
ctx.coverage.append(CoverageIssue("GuardDuty", "eu-west-1", "not_subscribed", ""))

out = os.path.join(os.path.dirname(__file__), "exemple-rapport-sensedrift.pdf")
generate_pdf(ctx, out, client="Exemple SAS")
print(out)
