"""Amazon RDS / Aurora."""
from __future__ import annotations

from datetime import date

from .. import pricing as px
from ..models import COST, RESILIENCE, SECURITY, CONF_HIGH, CONF_MEDIUM, Severity
from ._util import metric_stats, paginate

# Fin du support standard (au-delà : RDS Extended Support facturé par vCPU-heure).
# Source : calendriers de versions Amazon RDS. À tenir à jour.
END_OF_STANDARD_SUPPORT = {
    ("mysql", "5.7"): date(2024, 2, 29),
    ("mysql", "8.0"): date(2026, 7, 31),
    ("postgres", "11"): date(2024, 2, 29),
    ("postgres", "12"): date(2025, 2, 28),
    ("postgres", "13"): date(2026, 2, 28),
    ("aurora-mysql", "5.7"): date(2024, 10, 31),
    ("aurora-postgresql", "11"): date(2024, 2, 29),
    ("aurora-postgresql", "12"): date(2025, 2, 28),
    ("aurora-postgresql", "13"): date(2026, 2, 28),
}


def _major(engine: str, version: str) -> str:
    parts = version.split(".")
    if engine in ("mysql",):
        return ".".join(parts[:2])
    if engine == "aurora-mysql":
        # 5.7.mysql_aurora.2.x → 5.7 ; 8.0.mysql_aurora.3.x → 8.0
        return ".".join(parts[:2])
    return parts[0]


def _vcpus(ctx, region: str, db_class: str):
    key = f"vcpu:{db_class}"
    if key not in ctx.cache:
        try:
            it = ctx.client("ec2", region).describe_instance_types(
                InstanceTypes=[db_class.removeprefix("db.")])["InstanceTypes"]
            ctx.cache[key] = it[0]["VCpuInfo"]["DefaultVCpus"] if it else None
        except Exception:  # noqa: BLE001
            ctx.cache[key] = None
    return ctx.cache[key]


def check_rds(ctx, region: str):
    rds = ctx.client("rds", region)
    dbs = list(paginate(rds, "describe_db_instances", "DBInstances"))
    today = date.today()

    for db in dbs:
        dbid = db["DBInstanceIdentifier"]
        engine = db.get("Engine", "")
        klass = db.get("DBInstanceClass", "")
        aurora = engine.startswith("aurora")
        detail = f"{engine} {db.get('EngineVersion', '')} · {klass}"

        if db.get("PubliclyAccessible"):
            ctx.add("RDS.PUBLIC", Severity.HIGH, SECURITY, "RDS",
                    "Bases de données accessibles depuis Internet",
                    "L'option PubliclyAccessible attribue une adresse publique à la base. Seuls les "
                    "Security Groups la protègent alors des tentatives de connexion.",
                    remediation="Désactiver PubliclyAccessible et accéder à la base via un bastion "
                                "SSM, un VPN ou depuis le VPC.",
                    remediation_cli=f"aws rds modify-db-instance --db-instance-identifier {dbid} "
                                    f"--no-publicly-accessible --apply-immediately --region {region}",
                    resource_id=dbid, resource_detail=detail, region=region,
                    references=["CIS 2.3.3"])

        if not db.get("StorageEncrypted"):
            ctx.add("RDS.UNENCRYPTED", Severity.MEDIUM, SECURITY, "RDS",
                    "Stockage RDS non chiffré",
                    "Les données, sauvegardes et snapshots de ces bases ne sont pas chiffrés au repos.",
                    remediation="Le chiffrement ne s'active qu'à la création : copier un snapshot en "
                                "le chiffrant, puis restaurer une nouvelle instance.",
                    resource_id=dbid, resource_detail=detail, region=region, effort="Élevé",
                    references=["CIS 2.3.1"])

        if not aurora:
            if db.get("BackupRetentionPeriod", 0) == 0:
                ctx.add("RDS.NO_BACKUP", Severity.HIGH, RESILIENCE, "RDS",
                        "Bases sans sauvegarde automatique",
                        "Aucune sauvegarde automatique : une erreur humaine ou une corruption serait "
                        "irréversible.",
                        remediation="Activer les sauvegardes automatiques (7 jours minimum, 14 à 35 "
                                    "jours en production).",
                        resource_id=dbid, resource_detail=detail, region=region)
            if not db.get("MultiAZ"):
                ctx.add("RDS.SINGLE_AZ", Severity.LOW, RESILIENCE, "RDS",
                        "Bases sans Multi-AZ",
                        "Une panne de zone de disponibilité ou une maintenance rend la base "
                        "indisponible. Acceptable en développement, risqué en production.",
                        remediation="Activer Multi-AZ pour les bases de production.",
                        resource_id=dbid, resource_detail=detail, region=region)
            if db.get("StorageType") == "gp2":
                gb = db.get("AllocatedStorage", 0)
                ctx.add("RDS.GP2", Severity.LOW, COST, "RDS",
                        "Stockage RDS gp2 à migrer vers gp3",
                        "gp3 est moins cher que gp2 et offre 3 000 IOPS de base, quelle que soit "
                        "la taille.",
                        remediation="Modifier le type de stockage en gp3 (opération en ligne).",
                        resource_id=dbid, resource_detail=f"{gb} Go", region=region,
                        monthly_saving_eur=ctx.usd(gb * 0.02), saving_confidence=CONF_MEDIUM)

        if not db.get("DeletionProtection"):
            ctx.add("RDS.DELETION_PROTECTION", Severity.LOW, RESILIENCE, "RDS",
                    "Protection contre la suppression désactivée",
                    "Une fausse manipulation (console, Terraform) peut supprimer la base.",
                    remediation="Activer DeletionProtection sur les bases de production.",
                    resource_id=dbid, region=region)

        if not db.get("AutoMinorVersionUpgrade"):
            ctx.add("RDS.MINOR_UPGRADE", Severity.LOW, SECURITY, "RDS",
                    "Mises à jour mineures automatiques désactivées",
                    "Les correctifs de sécurité du moteur ne sont pas appliqués automatiquement.",
                    remediation="Activer AutoMinorVersionUpgrade et définir une fenêtre de maintenance.",
                    resource_id=dbid, region=region, references=["CIS 2.3.2"])

        if px.instance_family(klass) in ("t2", "m4", "r4", "m3", "r3"):
            ctx.add("RDS.PREVIOUS_GEN", Severity.LOW, COST, "RDS",
                    "Classes d'instances RDS de génération précédente",
                    "Les classes récentes (Graviton m7g, r7g, t4g) offrent un meilleur rapport "
                    "prix / performance.",
                    remediation="Modifier la classe d'instance lors d'une fenêtre de maintenance.",
                    resource_id=dbid, resource_detail=klass, region=region, effort="Moyen")

        # ── Extended Support (coût souvent invisible)
        key = (engine, _major(engine, db.get("EngineVersion", "")))
        eos = END_OF_STANDARD_SUPPORT.get(key)
        if eos and today > eos and db.get("EngineLifecycleSupport", "open-source-rds-extended-support") \
                == "open-source-rds-extended-support":
            vcpu = _vcpus(ctx, region, klass)
            cost = ctx.usd(vcpu * px.RDS_EXTENDED_SUPPORT_VCPU_HOUR * px.HOURS_PER_MONTH) if vcpu else None
            ctx.add("RDS.EXTENDED_SUPPORT", Severity.HIGH, COST, "RDS",
                    "Moteurs de base en fin de support (RDS Extended Support facturé)",
                    f"Le support standard de {engine} {key[1]} a pris fin le "
                    f"{eos.strftime('%d/%m/%Y')}. AWS facture désormais un supplément Extended "
                    "Support par vCPU et par heure, qui double à partir de la 3e année.",
                    remediation="Planifier la montée de version majeure (tester d'abord sur une copie "
                                "via les Blue/Green Deployments RDS).",
                    resource_id=dbid, resource_detail=detail, region=region,
                    monthly_saving_eur=cost, saving_confidence=CONF_HIGH, effort="Élevé")

    # ── Bases inactives (aucune connexion sur la période)
    ids = [d["DBInstanceIdentifier"] for d in dbs if d.get("DBInstanceStatus") == "available"]
    conns = metric_stats(ctx, region, "AWS/RDS", "DatabaseConnections",
                         "DBInstanceIdentifier", ids, stat="Maximum")
    for d in dbs:
        vals = conns.get(d["DBInstanceIdentifier"], [])
        if len(vals) >= min(7, ctx.lookback_days) and max(vals) == 0:
            ctx.add("RDS.IDLE", Severity.MEDIUM, COST, "RDS",
                    "Bases de données sans aucune connexion",
                    f"Aucune connexion n'a été enregistrée sur les {ctx.lookback_days} derniers jours.",
                    remediation="Confirmer l'inutilité, prendre un snapshot final puis supprimer "
                                "l'instance (ou l'arrêter, mais RDS la redémarre après 7 jours).",
                    resource_id=d["DBInstanceIdentifier"], resource_detail=d.get("DBInstanceClass", ""),
                    region=region)

    # ── Snapshots manuels publics
    for snap in paginate(rds, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        attrs = rds.describe_db_snapshot_attributes(
            DBSnapshotIdentifier=snap["DBSnapshotIdentifier"])["DBSnapshotAttributesResult"]
        for a in attrs.get("DBSnapshotAttributes", []):
            if a["AttributeName"] == "restore" and "all" in a.get("AttributeValues", []):
                ctx.add("RDS.PUBLIC_SNAPSHOT", Severity.CRITICAL, SECURITY, "RDS",
                        "Snapshots RDS publics",
                        "N'importe quel compte AWS peut restaurer ces snapshots et lire la base.",
                        remediation="Retirer immédiatement le partage public.",
                        remediation_cli=f"aws rds modify-db-snapshot-attribute --db-snapshot-identifier "
                                        f"{snap['DBSnapshotIdentifier']} --attribute-name restore "
                                        f"--values-to-remove all --region {region}",
                        resource_id=snap["DBSnapshotIdentifier"], region=region)
