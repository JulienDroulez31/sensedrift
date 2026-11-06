"""Amazon S3 (contrôle global : exécuté une seule fois, quelle que soit la région)."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import botocore.exceptions

from .. import pricing as px
from ..models import COST, GOVERNANCE, RESILIENCE, SECURITY, CONF_LOW, Severity

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = ("http://acs.amazonaws.com/groups/global/AllUsers",
                   "http://acs.amazonaws.com/groups/global/AuthenticatedUsers")
LIFECYCLE_MIN_GB = 100


def _code(e: botocore.exceptions.ClientError) -> str:
    return e.response.get("Error", {}).get("Code", "")


def _bucket_region(s3, name: str) -> str:
    loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
    return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)


def _enforces_tls(policy: dict) -> bool:
    for st in policy.get("Statement", []):
        cond = json.dumps(st.get("Condition", {}))
        if st.get("Effect") == "Deny" and "aws:SecureTransport" in cond and "false" in cond.lower():
            return True
    return False


def _bucket_size_gb(ctx, region: str, name: str):
    try:
        cw = ctx.client("cloudwatch", region)
        end = datetime.now(timezone.utc)
        resp = cw.get_metric_statistics(
            Namespace="AWS/S3", MetricName="BucketSizeBytes",
            Dimensions=[{"Name": "BucketName", "Value": name},
                        {"Name": "StorageType", "Value": "StandardStorage"}],
            StartTime=end - timedelta(days=3), EndTime=end, Period=86400, Statistics=["Average"])
        pts = resp.get("Datapoints", [])
        return max(p["Average"] for p in pts) / 1024 ** 3 if pts else None
    except Exception:  # noqa: BLE001
        return None


def check_s3(ctx):
    s3 = ctx.client("s3")

    # ── Blocage d'accès public au niveau du compte
    account_pab = False
    try:
        cfg = ctx.client("s3control").get_public_access_block(
            AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
        account_pab = all(cfg.get(k) for k in PAB_KEYS)
    except botocore.exceptions.ClientError as e:
        if _code(e) not in ("NoSuchPublicAccessBlockConfiguration",):
            raise
    if not account_pab:
        ctx.add("S3.ACCOUNT_PAB", Severity.MEDIUM, SECURITY, "S3",
                "Blocage d'accès public S3 non activé au niveau du compte",
                "Le « Block Public Access » de compte est le garde-fou qui empêche qu'un bucket "
                "soit rendu public par erreur, quel que soit le réglage individuel des buckets.",
                remediation="Activer les 4 options au niveau du compte. Si un site statique doit "
                            "rester public, le servir via CloudFront avec Origin Access Control "
                            "(le bucket reste alors privé).",
                remediation_cli=f"aws s3control put-public-access-block --account-id {ctx.account_id} "
                                "--public-access-block-configuration BlockPublicAcls=true,"
                                "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                references=["CIS 2.1.4"])

    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        try:
            region = _bucket_region(s3, name)
        except botocore.exceptions.ClientError as e:
            ctx.record_error("S3", name, e)
            continue
        rs3 = ctx.client("s3", region)

        # ── Exposition publique réelle
        is_public = False
        try:
            is_public = rs3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]["IsPublic"]
        except botocore.exceptions.ClientError as e:
            if _code(e) not in ("NoSuchBucketPolicy",):
                ctx.record_error("S3", region, e)
        try:
            acl = rs3.get_bucket_acl(Bucket=name)
            if any(g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES for g in acl.get("Grants", [])):
                is_public = True
        except botocore.exceptions.ClientError:
            pass

        bucket_pab = False
        try:
            cfg = rs3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            bucket_pab = all(cfg.get(k) for k in PAB_KEYS)
        except botocore.exceptions.ClientError as e:
            if _code(e) != "NoSuchPublicAccessBlockConfiguration":
                ctx.record_error("S3", region, e)

        if is_public and not account_pab:
            website = True
            try:
                rs3.get_bucket_website(Bucket=name)
            except botocore.exceptions.ClientError:
                website = False
            if website:
                ctx.add("S3.PUBLIC_WEBSITE", Severity.MEDIUM, SECURITY, "S3",
                        "Sites statiques servis directement depuis un bucket public",
                        "Le bucket est public pour héberger un site. C'est fonctionnel, mais le site "
                        "est servi en HTTP uniquement (pas de HTTPS natif), sans cache ni protection, "
                        "et tout objet déposé par erreur devient public.",
                        remediation="Placer CloudFront devant le bucket (certificat ACM gratuit, HTTPS, "
                                    "cache, en-têtes de sécurité) avec Origin Access Control, puis "
                                    "rendre le bucket privé.",
                        resource_id=name, region=region, effort="Moyen")
            else:
                ctx.add("S3.PUBLIC", Severity.CRITICAL, SECURITY, "S3",
                        "Buckets S3 accessibles publiquement",
                        "La politique ou les ACL de ces buckets autorisent un accès anonyme depuis "
                        "Internet. C'est la première cause de fuites de données sur AWS.",
                        remediation="Vérifier le contenu, retirer la politique ou l'ACL publique, puis "
                                    "activer le Block Public Access.",
                        remediation_cli=f"aws s3api put-public-access-block --bucket {name} "
                                        "--public-access-block-configuration BlockPublicAcls=true,"
                                        "IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        resource_id=name, region=region, references=["CIS 2.1.4"])
        elif not account_pab and not bucket_pab:
            ctx.add("S3.BUCKET_PAB", Severity.LOW, SECURITY, "S3",
                    "Buckets sans blocage d'accès public",
                    "Ces buckets ne sont pas publics aujourd'hui, mais rien n'empêche qu'une politique "
                    "ou une ACL les rende publics à l'avenir.",
                    remediation="Activer le Block Public Access (idéalement au niveau du compte).",
                    resource_id=name, region=region, references=["CIS 2.1.4"])

        # ── TLS obligatoire
        try:
            pol = json.loads(rs3.get_bucket_policy(Bucket=name)["Policy"])
        except botocore.exceptions.ClientError:
            pol = {}
        if not _enforces_tls(pol):
            ctx.add("S3.TLS", Severity.LOW, SECURITY, "S3",
                    "HTTPS non imposé sur les buckets",
                    "La politique du bucket n'interdit pas les requêtes en HTTP non chiffré.",
                    remediation="Ajouter une instruction Deny conditionnée par "
                                "aws:SecureTransport = false.",
                    resource_id=name, region=region, references=["CIS 2.1.1"])

        # ── Versioning
        try:
            ver = rs3.get_bucket_versioning(Bucket=name).get("Status")
            if ver != "Enabled":
                ctx.add("S3.VERSIONING", Severity.LOW, RESILIENCE, "S3",
                        "Versioning désactivé",
                        "Sans versioning, une suppression accidentelle ou un rançongiciel détruit "
                        "définitivement les objets.",
                        remediation="Activer le versioning, associé à une règle de cycle de vie qui "
                                    "expire les anciennes versions pour maîtriser les coûts.",
                        resource_id=name, region=region)
        except botocore.exceptions.ClientError as e:
            ctx.record_error("S3", region, e)

        # ── Cycle de vie (uniquement si le volume justifie l'effort)
        try:
            rs3.get_bucket_lifecycle_configuration(Bucket=name)
        except botocore.exceptions.ClientError as e:
            if _code(e) == "NoSuchLifecycleConfiguration":
                gb = _bucket_size_gb(ctx, region, name)
                if gb is not None and gb >= LIFECYCLE_MIN_GB:
                    monthly = gb * px.S3_STANDARD_GB_MONTH
                    ctx.add("S3.LIFECYCLE", Severity.LOW, COST, "S3",
                            "Gros buckets sans politique de cycle de vie",
                            "Tout le volume est stocké en classe Standard. Les objets rarement lus "
                            "pourraient basculer automatiquement vers des classes moins chères.",
                            remediation="Activer S3 Intelligent-Tiering ou des règles de transition, "
                                        "et une règle d'expiration des envois multipart incomplets.",
                            resource_id=name, resource_detail=f"{gb:,.0f} Go en Standard",
                            region=region, monthly_saving_eur=ctx.usd(monthly * 0.3),
                            saving_confidence=CONF_LOW)
            else:
                ctx.record_error("S3", region, e)

        # ── Journalisation d'accès (signalée uniquement pour les buckets publics)
        if is_public:
            try:
                if "LoggingEnabled" not in rs3.get_bucket_logging(Bucket=name):
                    ctx.add("S3.LOGGING", Severity.LOW, GOVERNANCE, "S3",
                            "Journalisation d'accès désactivée sur des buckets publics",
                            "Impossible de savoir qui a téléchargé quoi en cas d'incident.",
                            remediation="Activer Server Access Logging vers un bucket de logs dédié.",
                            resource_id=name, region=region)
            except botocore.exceptions.ClientError:
                pass
