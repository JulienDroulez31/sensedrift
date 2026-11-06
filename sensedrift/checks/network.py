"""Réseau : VPC Flow Logs, NAT Gateways inactives, Load Balancers vides."""
from __future__ import annotations

from .. import pricing as px
from ..models import COMPLIANCE, COST, GOVERNANCE, CONF_HIGH, CONF_MEDIUM, Severity
from ._util import metric_stats, paginate, tag


def check_vpc(ctx, region: str):
    ec2 = ctx.client("ec2", region)
    flow = {fl["ResourceId"] for fl in paginate(ec2, "describe_flow_logs", "FlowLogs")
            if fl.get("FlowLogStatus") == "ACTIVE"}
    instances_by_vpc = {}
    for r in paginate(ec2, "describe_instances", "Reservations",
                      Filters=[{"Name": "instance-state-name", "Values": ["running"]}]):
        for i in r["Instances"]:
            instances_by_vpc[i.get("VpcId")] = instances_by_vpc.get(i.get("VpcId"), 0) + 1

    for vpc in paginate(ec2, "describe_vpcs", "Vpcs"):
        vid = vpc["VpcId"]
        n = instances_by_vpc.get(vid, 0)
        if vid not in flow and (n or not vpc.get("IsDefault")):
            ctx.add("VPC.FLOW_LOGS", Severity.MEDIUM, COMPLIANCE, "VPC",
                    "VPC Flow Logs désactivés",
                    "Sans Flow Logs, aucune trace des connexions réseau : impossible d'enquêter sur "
                    "une exfiltration ou un mouvement latéral.",
                    remediation="Activer les Flow Logs vers S3 (option la moins chère), "
                                "au minimum pour le trafic rejeté.",
                    remediation_cli=f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vid} "
                                    f"--traffic-type REJECT --log-destination-type s3 "
                                    f"--log-destination arn:aws:s3:::<bucket-logs> --region {region}",
                    resource_id=vid, resource_detail=tag(vpc, "Name"), region=region,
                    references=["CIS 3.7"])
        if vpc.get("IsDefault") and n:
            ctx.add("VPC.DEFAULT_IN_USE", Severity.LOW, GOVERNANCE, "VPC",
                    "Ressources déployées dans le VPC par défaut",
                    "Le VPC par défaut n'a que des sous-réseaux publics : il n'est pas conçu pour "
                    "héberger de la production.",
                    remediation="Créer un VPC dédié (sous-réseaux publics / privés / bases de "
                                "données) et y migrer progressivement les charges.",
                    resource_id=vid, resource_detail=f"{n} instance(s)", region=region, effort="Élevé")


def check_nat_gateways(ctx, region: str):
    ec2 = ctx.client("ec2", region)
    nats = [n for n in paginate(ec2, "describe_nat_gateways", "NatGateways",
                                Filters=[{"Name": "state", "Values": ["available"]}])]
    ids = [n["NatGatewayId"] for n in nats]
    traffic = metric_stats(ctx, region, "AWS/NATGateway", "BytesOutToDestination",
                           "NatGatewayId", ids, stat="Sum")
    for n in nats:
        vals = traffic.get(n["NatGatewayId"], [])
        total_mb = sum(vals) / 1024 ** 2
        if len(vals) >= min(7, ctx.lookback_days) and total_mb < 100:
            ctx.add("NAT.IDLE", Severity.MEDIUM, COST, "NAT Gateway",
                    "NAT Gateways sans trafic",
                    f"Moins de 100 Mo transférés sur {ctx.lookback_days} jours. Une NAT Gateway est "
                    "facturée à l'heure, même sans trafic.",
                    remediation="Supprimer la NAT Gateway si aucune ressource privée n'a besoin "
                                "d'Internet, ou utiliser des VPC Endpoints pour les services AWS.",
                    resource_id=n["NatGatewayId"], resource_detail=f"{total_mb:.0f} Mo / {ctx.lookback_days} j",
                    region=region,
                    monthly_saving_eur=ctx.usd(px.NAT_GATEWAY_HOUR * px.HOURS_PER_MONTH),
                    saving_confidence=CONF_HIGH)


def check_load_balancers(ctx, region: str):
    elbv2 = ctx.client("elbv2", region)
    for lb in paginate(elbv2, "describe_load_balancers", "LoadBalancers"):
        if lb.get("Type") not in ("application", "network"):
            continue
        tgs = list(paginate(elbv2, "describe_target_groups", "TargetGroups",
                            LoadBalancerArn=lb["LoadBalancerArn"]))
        healthy = 0
        for tg in tgs:
            th = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
            healthy += sum(1 for t in th["TargetHealthDescriptions"]
                           if t["TargetHealth"]["State"] in ("healthy", "unused", "initial"))
        if healthy == 0:
            hourly = px.ALB_HOUR if lb["Type"] == "application" else px.NLB_HOUR
            ctx.add("ELB.EMPTY", Severity.MEDIUM, COST, "Elastic Load Balancing",
                    "Load Balancers sans cible active",
                    "Ces load balancers n'ont aucune cible enregistrée en bonne santé : ils sont "
                    "facturés sans servir de trafic utile.",
                    remediation="Supprimer le load balancer s'il n'est plus utilisé.",
                    resource_id=lb["LoadBalancerName"], resource_detail="ALB" if lb["Type"] == "application" else "NLB",
                    region=region,
                    monthly_saving_eur=ctx.usd(hourly * px.HOURS_PER_MONTH),
                    saving_confidence=CONF_MEDIUM)

    try:
        elb = ctx.client("elb", region)
        for lb in elb.describe_load_balancers().get("LoadBalancerDescriptions", []):
            if not lb.get("Instances"):
                ctx.add("ELB.EMPTY", Severity.MEDIUM, COST, "Elastic Load Balancing",
                        "Load Balancers sans cible active",
                        "Ces load balancers n'ont aucune cible enregistrée : ils sont facturés sans "
                        "servir de trafic utile.",
                        remediation="Supprimer le load balancer s'il n'est plus utilisé.",
                        resource_id=lb["LoadBalancerName"], resource_detail="Classic LB",
                        region=region,
                        monthly_saving_eur=ctx.usd(px.CLB_HOUR * px.HOURS_PER_MONTH),
                        saving_confidence=CONF_HIGH)
    except Exception as exc:  # noqa: BLE001
        ctx.record_error("Classic Load Balancer", region, exc)
