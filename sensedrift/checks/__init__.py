"""Contrôles d'audit.

Chaque contrôle a la signature ``check(ctx, region)`` (régional) ou
``check(ctx)`` (global) et enregistre ses constats via ``ctx.add``.
"""
from . import ec2, s3, iam, rds, detection, logging_checks, lambda_, network, costs

# Compute Optimizer d'abord : s'il est actif, ses recommandations remplacent
# l'heuristique CPU du contrôle EC2.
REGIONAL_CHECKS = [
    ("Compute Optimizer", costs.check_compute_optimizer),
    ("EC2", ec2.check_instances),
    ("EBS", ec2.check_ebs),
    ("Security Groups", ec2.check_security_groups),
    ("RDS", rds.check_rds),
    ("Lambda", lambda_.check_lambda),
    ("VPC", network.check_vpc),
    ("NAT Gateway", network.check_nat_gateways),
    ("Load Balancers", network.check_load_balancers),
    ("GuardDuty", detection.check_guardduty),
    ("Security Hub", detection.check_securityhub),
    ("IAM Access Analyzer", detection.check_access_analyzer),
    ("AWS Config", logging_checks.check_config),
    ("CloudWatch Logs", logging_checks.check_log_retention),
]

GLOBAL_CHECKS = [
    ("IAM", iam.check_iam),
    ("S3", s3.check_s3),
    ("CloudTrail", logging_checks.check_cloudtrail),
    ("Cost Explorer", costs.check_cost_explorer),
]
