"""Interface en ligne de commande SenseDrift."""
from __future__ import annotations

import argparse
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import boto3
import botocore.exceptions

from . import __version__
from .checks import GLOBAL_CHECKS, REGIONAL_CHECKS
from .models import SEVERITY_ORDER, AuditContext
from .report import export_csv, export_json, generate_pdf
from .checks._util import eur

log = logging.getLogger("sensedrift")


def build_session(args) -> boto3.Session:
    base = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    if not args.role_arn:
        return base
    kw = {"RoleArn": args.role_arn, "RoleSessionName": "SenseDriftAudit", "DurationSeconds": 3600}
    if args.external_id:
        kw["ExternalId"] = args.external_id
    creds = base.client("sts").assume_role(**kw)["Credentials"]
    return boto3.Session(aws_access_key_id=creds["AccessKeyId"],
                         aws_secret_access_key=creds["SecretAccessKey"],
                         aws_session_token=creds["SessionToken"])


def resolve_regions(session: boto3.Session, args) -> list:
    if not args.all_regions:
        return args.regions
    ec2 = session.client("ec2", region_name=args.regions[0])
    regions = [r["RegionName"] for r in ec2.describe_regions(
        Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])["Regions"]]
    return sorted(regions)


def run_audit(ctx: AuditContext, workers: int = 4):
    sts = ctx.client("sts")
    ctx.account_id = sts.get_caller_identity()["Account"]
    try:
        aliases = ctx.client("iam").list_account_aliases()["AccountAliases"]
        ctx.account_alias = aliases[0] if aliases else ""
    except botocore.exceptions.ClientError:
        pass

    def regional(region):
        log.info("  [%s] analyse en cours…", region)
        for name, fn in REGIONAL_CHECKS:
            ctx.run(name, region, fn, region)
        log.info("  [%s] terminé", region)

    log.info("  [global] IAM, S3, CloudTrail, facturation…")
    for name, fn in GLOBAL_CHECKS:
        ctx.run(name, "global", fn)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(regional, ctx.regions))
    ctx.finished_at = datetime.now(timezone.utc)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="sensedrift",
        description="SenseDrift — audit de sécurité et d'optimisation des coûts AWS (lecture seule).")
    p.add_argument("--profile", help="Profil AWS CLI à utiliser")
    p.add_argument("--role-arn", help="Rôle IAM du client à assumer")
    p.add_argument("--external-id", help="ExternalId exigé par la relation de confiance du rôle")
    p.add_argument("--regions", nargs="+", default=["eu-west-1", "eu-west-3"],
                   help="Régions à auditer (défaut : eu-west-1 eu-west-3)")
    p.add_argument("--all-regions", action="store_true", help="Auditer toutes les régions activées")
    p.add_argument("--client", default="", help="Nom du client affiché dans le rapport")
    p.add_argument("--prepared-by", default="SenseDrift", help="Auteur du rapport")
    p.add_argument("--contact", default="contact@sensedrift.fr · sensedrift.fr")
    p.add_argument("--output-dir", default="rapports", help="Dossier de sortie")
    p.add_argument("--lookback-days", type=int, default=14,
                   help="Fenêtre d'observation des métriques d'utilisation (défaut : 14)")
    p.add_argument("--usd-eur", type=float, default=0.86, help="Taux de conversion USD→EUR")
    p.add_argument("--no-cost-explorer", action="store_true",
                   help="Ne pas interroger Cost Explorer (0,01 $ par requête, ~8 requêtes)")
    p.add_argument("--workers", type=int, default=4, help="Régions analysées en parallèle")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"SenseDrift {__version__}")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(message)s")
    for noisy in ("botocore", "boto3", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    log.info("SenseDrift %s — audit AWS en lecture seule\n", __version__)
    try:
        session = build_session(args)
        regions = resolve_regions(session, args)
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError,
            botocore.exceptions.ProfileNotFound) as e:
        log.error("Impossible d'obtenir des identifiants AWS : %s", e)
        return 2

    ctx = AuditContext(session, regions, usd_eur=args.usd_eur,
                       use_cost_explorer=not args.no_cost_explorer,
                       lookback_days=args.lookback_days)
    try:
        run_audit(ctx, args.workers)
    except botocore.exceptions.ClientError as e:
        log.error("Échec de l'audit : %s", e)
        return 2

    score = ctx.posture_score()
    log.info("\n" + "─" * 56)
    log.info("  Compte        : %s %s", ctx.account_id,
             f"({ctx.account_alias})" if ctx.account_alias else "")
    log.info("  Score         : %s/100 (note %s)", score, ctx.grade(score))
    for s in SEVERITY_ORDER:
        log.info("  %-14s: %d", s.label, sum(1 for f in ctx.findings if f.severity == s))
    log.info("  Économies     : %s / mois", eur(ctx.total_monthly_saving))
    if ctx.coverage:
        log.info("  Non vérifiés  : %d contrôle(s) (voir annexe du rapport)",
                 len({(c.service, c.region) for c in ctx.coverage}))
    log.info("─" * 56)

    os.makedirs(args.output_dir, exist_ok=True)
    stem = os.path.join(args.output_dir,
                        f"sensedrift_{ctx.account_id}_{datetime.now().strftime('%Y%m%d_%H%M')}")
    generate_pdf(ctx, stem + ".pdf", client=args.client, prepared_by=args.prepared_by,
                 contact=args.contact)
    export_json(ctx, stem + ".json")
    export_csv(ctx, stem + ".csv")
    log.info("\nRapport : %s.pdf\nDonnées : %s.json · %s.csv", stem, stem, stem)
    return 0


if __name__ == "__main__":
    sys.exit(main())
