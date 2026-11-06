"""EC2, EBS, Elastic IP et Security Groups."""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .. import pricing as px
from ..models import COST, GOVERNANCE, SECURITY, CONF_HIGH, CONF_LOW, CONF_MEDIUM, Severity
from ._util import days_since, metric_stats, paginate, tag

IDLE_CPU_THRESHOLD = 3.0       # % CPU moyen journalier maximal
SNAPSHOT_AGE_DAYS = 90
STOPPED_DAYS = 30

SENSITIVE_PORTS = {
    20: "FTP", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "RPC", 139: "NetBIOS",
    445: "SMB", 1433: "SQL Server", 1521: "Oracle", 2375: "Docker API", 2376: "Docker API",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}
WEB_PORTS = {80, 443}


def _stopped_since(instance: dict):
    m = re.search(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", instance.get("StateTransitionReason", ""))
    if m:
        return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return None


def check_instances(ctx, region: str):
    ec2 = ctx.client("ec2", region)
    instances = [i for r in paginate(ec2, "describe_instances", "Reservations")
                 for i in r["Instances"] if i["State"]["Name"] != "terminated"]
    volumes = {v["VolumeId"]: v for v in paginate(ec2, "describe_volumes", "Volumes")}
    running = [i for i in instances if i["State"]["Name"] == "running"]

    # ── IMDSv2
    for i in running:
        if i.get("MetadataOptions", {}).get("HttpTokens") != "required":
            iid = i["InstanceId"]
            ctx.add("EC2.IMDSV2", Severity.HIGH, SECURITY, "EC2",
                    "IMDSv2 non imposé sur les instances",
                    "Ces instances acceptent encore IMDSv1. Une simple vulnérabilité SSRF dans une "
                    "application suffit alors à voler les identifiants IAM de l'instance.",
                    remediation="Imposer IMDSv2 (aucun redémarrage nécessaire). Vérifier au préalable "
                                "que les SDK utilisés sont récents.",
                    remediation_cli=f"aws ec2 modify-instance-metadata-options --instance-id {iid} "
                                    f"--http-tokens required --region {region}",
                    resource_id=iid, resource_detail=tag(i, "Name"), region=region,
                    references=["CIS 5.6"])

    # ── Gouvernance : tags
    for i in running:
        if not i.get("Tags"):
            ctx.add("EC2.UNTAGGED", Severity.LOW, GOVERNANCE, "EC2",
                    "Instances sans aucun tag",
                    "Sans tags, les coûts ne peuvent pas être attribués à un projet, un environnement "
                    "ou une équipe, ce qui empêche tout pilotage FinOps.",
                    remediation="Définir une politique de tagging (Name, Environment, Project, Owner, "
                                "CostCenter) et l'imposer avec les Tag Policies d'AWS Organizations.",
                    resource_id=i["InstanceId"], region=region, effort="Moyen")

    # ── Instances arrêtées depuis longtemps : volumes facturés
    for i in instances:
        if i["State"]["Name"] != "stopped":
            continue
        since = _stopped_since(i)
        age = days_since(since)
        if age is not None and age < STOPPED_DAYS:
            continue
        vol_ids = [b["Ebs"]["VolumeId"] for b in i.get("BlockDeviceMappings", []) if "Ebs" in b]
        cost = sum(px.ebs_monthly_usd(volumes[v]["VolumeType"], volumes[v]["Size"])
                   for v in vol_ids if v in volumes)
        gb = sum(volumes[v]["Size"] for v in vol_ids if v in volumes)
        ctx.add("EC2.STOPPED", Severity.LOW, COST, "EC2",
                "Instances arrêtées depuis plus de 30 jours",
                "Une instance arrêtée ne coûte plus en calcul, mais ses volumes EBS restent facturés "
                "en totalité.",
                remediation="Si l'instance n'est plus utile : créer une AMI de sauvegarde puis la "
                            "résilier. Sinon, documenter la raison de l'arrêt dans un tag.",
                resource_id=i["InstanceId"],
                resource_detail=f"{tag(i, 'Name') or i['InstanceType']} · {gb} Go"
                                + (f" · arrêtée depuis {age} j" if age is not None else ""),
                region=region, monthly_saving_eur=ctx.usd(cost), saving_confidence=CONF_HIGH)

    # ── Génération précédente
    for i in running:
        fam = px.instance_family(i["InstanceType"])
        if fam in px.PREVIOUS_GEN:
            hourly = px.ec2_ondemand_hourly_usd(ctx, i["InstanceType"], region)
            saving = ctx.usd(hourly * px.HOURS_PER_MONTH * 0.15) if hourly else None
            ctx.add("EC2.PREVIOUS_GEN", Severity.LOW, COST, "EC2",
                    "Instances de génération précédente",
                    "Ces familles d'instances sont plus chères et moins performantes que les "
                    "générations actuelles (Graviton notamment : jusqu'à 20 % moins cher à "
                    "performance égale).",
                    remediation=f"Migrer vers une famille actuelle (ex. {fam} → "
                                f"{px.PREVIOUS_GEN[fam]}) après test de compatibilité.",
                    resource_id=i["InstanceId"],
                    resource_detail=f"{tag(i, 'Name')} · {i['InstanceType']}".strip(" ·"),
                    region=region, monthly_saving_eur=saving, saving_confidence=CONF_MEDIUM,
                    effort="Moyen")

    # ── Instances inactives (CPU)
    # Ignorées si Compute Optimizer est actif : ses recommandations sont plus fines.
    if ctx.cache.get(f"co_enabled:{region}"):
        return
    ids = [i["InstanceId"] for i in running]
    cpu = metric_stats(ctx, region, "AWS/EC2", "CPUUtilization", "InstanceId", ids)
    for i in running:
        vals = cpu.get(i["InstanceId"], [])
        if len(vals) < min(7, ctx.lookback_days) or max(vals) >= IDLE_CPU_THRESHOLD:
            continue
        hourly = px.ec2_ondemand_hourly_usd(ctx, i["InstanceType"], region)
        ctx.add("EC2.IDLE", Severity.MEDIUM, COST, "EC2",
                "Instances quasi inactives",
                f"Sur les {ctx.lookback_days} derniers jours, l'utilisation CPU moyenne journalière "
                f"n'a jamais dépassé {IDLE_CPU_THRESHOLD:.0f} %. Ces instances sont probablement "
                "surdimensionnées ou inutiles.",
                remediation="Confirmer avec le propriétaire, puis arrêter, résilier ou réduire la "
                            "taille de l'instance (ex. passage à une taille inférieure ou en "
                            "instance burstable t4g).",
                resource_id=i["InstanceId"],
                resource_detail=f"{tag(i, 'Name')} · {i['InstanceType']} · CPU max {max(vals):.1f} %".strip(" ·"),
                region=region,
                monthly_saving_eur=ctx.usd(hourly * px.HOURS_PER_MONTH * 0.5) if hourly else None,
                saving_confidence=CONF_LOW, effort="Moyen")


def check_ebs(ctx, region: str):
    ec2 = ctx.client("ec2", region)

    # ── Chiffrement par défaut
    if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
        ctx.add("EBS.DEFAULT_ENCRYPTION", Severity.MEDIUM, SECURITY, "EBS",
                "Chiffrement EBS par défaut désactivé",
                "Les nouveaux volumes et snapshots ne sont pas chiffrés automatiquement dans cette "
                "région. Activer l'option est gratuit et sans impact de performance.",
                remediation="Activer le chiffrement par défaut dans EC2 → Paramètres du compte.",
                remediation_cli=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                region=region, references=["CIS 2.2.1"])

    volumes = list(paginate(ec2, "describe_volumes", "Volumes"))
    for v in volumes:
        vid, size, vtype = v["VolumeId"], v["Size"], v["VolumeType"]
        name = tag(v, "Name")

        if v["State"] == "available":
            ctx.add("EBS.UNATTACHED", Severity.MEDIUM, COST, "EBS",
                    "Volumes EBS non attachés",
                    "Ces volumes ne sont rattachés à aucune instance mais sont facturés chaque mois.",
                    remediation="Créer un snapshot si les données doivent être conservées, puis "
                                "supprimer le volume.",
                    remediation_cli=f"aws ec2 delete-volume --volume-id {vid} --region {region}",
                    resource_id=vid, resource_detail=f"{name} · {vtype} · {size} Go".strip(" ·"),
                    region=region, monthly_saving_eur=ctx.usd(px.ebs_monthly_usd(vtype, size)),
                    saving_confidence=CONF_HIGH)
        elif vtype == "gp2":
            ctx.add("EBS.GP2", Severity.LOW, COST, "EBS",
                    "Volumes gp2 à migrer vers gp3",
                    "gp3 coûte 20 % de moins que gp2 avec des performances de base supérieures "
                    "(3 000 IOPS, 125 Mo/s). La migration se fait à chaud, sans interruption.",
                    remediation="Modifier le type de volume en gp3.",
                    remediation_cli=f"aws ec2 modify-volume --volume-id {vid} --volume-type gp3 "
                                    f"--region {region}",
                    resource_id=vid, resource_detail=f"{name} · {size} Go".strip(" ·"),
                    region=region,
                    monthly_saving_eur=ctx.usd(size * (px.EBS_GB_MONTH["gp2"] - px.EBS_GB_MONTH["gp3"])),
                    saving_confidence=CONF_HIGH)

        if not v.get("Encrypted"):
            ctx.add("EBS.UNENCRYPTED", Severity.MEDIUM, SECURITY, "EBS",
                    "Volumes EBS non chiffrés",
                    "Les données au repos de ces volumes ne sont pas chiffrées.",
                    remediation="Créer un snapshot, le copier avec chiffrement, puis restaurer un "
                                "volume chiffré à partir de cette copie.",
                    resource_id=vid, resource_detail=f"{name} · {size} Go".strip(" ·"),
                    region=region, effort="Moyen")

    # ── Elastic IP non associées
    for a in ec2.describe_addresses()["Addresses"]:
        if not (a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId")):
            ctx.add("EC2.EIP_UNUSED", Severity.LOW, COST, "EC2",
                    "Adresses Elastic IP non utilisées",
                    "Depuis février 2024, toute adresse IPv4 publique est facturée, qu'elle soit "
                    "utilisée ou non.",
                    remediation="Libérer les adresses inutiles.",
                    remediation_cli=f"aws ec2 release-address --allocation-id {a.get('AllocationId', '')} "
                                    f"--region {region}",
                    resource_id=a.get("PublicIp", ""), region=region,
                    monthly_saving_eur=ctx.usd(px.PUBLIC_IPV4_HOUR * px.HOURS_PER_MONTH),
                    saving_confidence=CONF_HIGH)

    # ── Snapshots
    ami_snapshots = set()
    for img in paginate(ec2, "describe_images", "Images", Owners=["self"]):
        for b in img.get("BlockDeviceMappings", []):
            if b.get("Ebs", {}).get("SnapshotId"):
                ami_snapshots.add(b["Ebs"]["SnapshotId"])
        if img.get("Public"):
            ctx.add("EC2.PUBLIC_AMI", Severity.CRITICAL, SECURITY, "EC2",
                    "AMI partagées publiquement",
                    "Ces images sont accessibles à tous les comptes AWS. Elles peuvent contenir "
                    "du code, des configurations ou des secrets.",
                    remediation="Retirer le partage public de l'AMI.",
                    remediation_cli=f"aws ec2 modify-image-attribute --image-id {img['ImageId']} "
                                    f"--launch-permission \"Remove=[{{Group=all}}]\" --region {region}",
                    resource_id=img["ImageId"], resource_detail=img.get("Name", ""), region=region)

    for s in paginate(ec2, "describe_snapshots", "Snapshots",
                      OwnerIds=["self"], RestorableByUserIds=["all"]):
        perms = ec2.describe_snapshot_attribute(
            SnapshotId=s["SnapshotId"], Attribute="createVolumePermission").get("CreateVolumePermissions", [])
        if not any(p.get("Group") == "all" for p in perms):
            continue
        ctx.add("EBS.PUBLIC_SNAPSHOT", Severity.CRITICAL, SECURITY, "EBS",
                "Snapshots EBS publics",
                "N'importe quel compte AWS peut restaurer ces snapshots et lire l'intégralité des "
                "données du disque.",
                remediation="Retirer immédiatement le partage public du snapshot.",
                remediation_cli=f"aws ec2 modify-snapshot-attribute --snapshot-id {s['SnapshotId']} "
                                f"--attribute createVolumePermission --operation-type remove "
                                f"--group-names all --region {region}",
                resource_id=s["SnapshotId"], region=region, references=["CIS 2.2"])

    for s in paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
        age = days_since(s["StartTime"])
        if age is None or age <= SNAPSHOT_AGE_DAYS or s["SnapshotId"] in ami_snapshots:
            continue
        full = s.get("FullSnapshotSizeInBytes")
        # Les snapshots sont incrémentaux : sans taille réelle, on estime 50 % de la taille du volume.
        gb = full / 1024 ** 3 if full else s.get("VolumeSize", 0) * 0.5
        ctx.add("EBS.OLD_SNAPSHOT", Severity.LOW, COST, "EBS",
                f"Snapshots EBS de plus de {SNAPSHOT_AGE_DAYS} jours",
                "Ces snapshots ne sont liés à aucune AMI et ont dépassé la durée de rétention "
                "habituelle. Ils s'accumulent souvent sans politique de nettoyage.",
                remediation="Mettre en place Amazon Data Lifecycle Manager ou AWS Backup avec une "
                            "durée de rétention, et supprimer les snapshots obsolètes.",
                resource_id=s["SnapshotId"],
                resource_detail=f"{s.get('VolumeSize', 0)} Go · {age} j",
                region=region,
                monthly_saving_eur=ctx.usd(gb * px.EBS_SNAPSHOT_GB_MONTH),
                saving_confidence=CONF_HIGH if full else CONF_LOW)


def _port_label(perm: dict) -> tuple:
    """Renvoie (sévérité, libellé) pour une règle ouverte sur Internet."""
    proto = perm.get("IpProtocol")
    if proto == "-1":
        return Severity.CRITICAL, "tout le trafic"
    lo, hi = perm.get("FromPort", 0), perm.get("ToPort", 65535)
    if proto in ("icmp", "icmpv6", "1", "58"):
        return Severity.LOW, "ICMP"
    exposed = [f"{p} ({n})" for p, n in SENSITIVE_PORTS.items() if lo <= p <= hi]
    rng = f"{proto.upper()} {lo}" if lo == hi else f"{proto.upper()} {lo}-{hi}"
    if exposed:
        return Severity.CRITICAL, f"{rng} — dont {', '.join(exposed[:4])}"
    if lo == hi and lo in WEB_PORTS:
        return None, rng
    if hi - lo > 100:
        return Severity.HIGH, rng
    return Severity.MEDIUM, rng


def check_security_groups(ctx, region: str):
    ec2 = ctx.client("ec2", region)
    in_use = {g["GroupId"] for eni in paginate(ec2, "describe_network_interfaces", "NetworkInterfaces")
              for g in eni.get("Groups", [])}

    for sg in paginate(ec2, "describe_security_groups", "SecurityGroups"):
        gid = sg["GroupId"]
        for perm in sg.get("IpPermissions", []):
            open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
            open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not (open_v4 or open_v6):
                continue
            sev, label = _port_label(perm)
            if sev is None:
                continue
            attached = gid in in_use
            if not attached:
                sev = Severity.LOW
            ctx.add("EC2.SG_OPEN" if attached else "EC2.SG_OPEN_UNUSED", sev, SECURITY, "EC2",
                    "Security Groups ouverts sur Internet" if attached
                    else "Security Groups inutilisés ouverts sur Internet",
                    "Ces règles autorisent des connexions entrantes depuis n'importe quelle adresse "
                    "IP. Les ports d'administration et de bases de données exposés sont scannés en "
                    "permanence par des robots."
                    if attached else
                    "Ces groupes ne sont attachés à aucune ressource aujourd'hui, mais seraient "
                    "immédiatement exposés s'ils étaient réutilisés.",
                    remediation="Restreindre la source à des plages IP connues. Pour l'administration, "
                                "utiliser AWS Systems Manager Session Manager (aucun port à ouvrir)."
                    if attached else "Supprimer les Security Groups inutilisés.",
                    resource_id=gid, resource_detail=f"{sg.get('GroupName', '')} · {label}"
                    + (" · IPv6" if open_v6 and not open_v4 else ""),
                    region=region, references=["CIS 5.2", "CIS 5.3"] if attached else [])

        # Security Group par défaut (CIS 5.4)
        if sg.get("GroupName") == "default" and (sg.get("IpPermissions") or sg.get("IpPermissionsEgress")) \
                and gid in in_use:
            ctx.add("EC2.DEFAULT_SG", Severity.LOW, SECURITY, "EC2",
                    "Security Group par défaut utilisé et non restreint",
                    "Le Security Group « default » autorise le trafic entre toutes les ressources qui "
                    "l'utilisent. Il est assigné automatiquement si aucun groupe n'est précisé.",
                    remediation="Créer des Security Groups dédiés par rôle applicatif, puis vider les "
                                "règles du groupe par défaut.",
                    resource_id=gid, resource_detail=sg.get("VpcId", ""), region=region,
                    references=["CIS 5.4"], effort="Moyen")
