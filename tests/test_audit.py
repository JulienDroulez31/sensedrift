"""Tests de bout en bout sur un compte AWS simulé (moto)."""
import json
import os

import boto3
import pytest
from moto import mock_aws

from sensedrift.cli import run_audit
from sensedrift.models import AuditContext, Severity
from sensedrift.report import export_csv, export_json, generate_pdf

REGION = "eu-west-1"


@pytest.fixture
def aws(monkeypatch):
    for k, v in {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
                 "AWS_DEFAULT_REGION": REGION, "MOTO_IAM_LOAD_MANAGED_POLICIES": "true"}.items():
        monkeypatch.setenv(k, v)
    with mock_aws():
        yield


def _seed():
    ec2 = boto3.client("ec2", REGION)
    ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="t2.micro")
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=200, VolumeType="gp2")
    ec2.allocate_address(Domain="vpc")
    sg = ec2.create_security_group(GroupName="open-ssh", Description="x")["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])

    s3 = boto3.client("s3", REGION)
    s3.create_bucket(Bucket="client-data-bucket",
                     CreateBucketConfiguration={"LocationConstraint": REGION})
    s3.put_bucket_policy(Bucket="client-data-bucket", Policy=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::client-data-bucket/*"}]}))

    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Password123!")
    iam.attach_user_policy(UserName="alice",
                           PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_role(RoleName="open-role", AssumeRolePolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}))

    rds = boto3.client("rds", REGION)
    rds.create_db_instance(DBInstanceIdentifier="prod-db", DBInstanceClass="db.t3.micro",
                           Engine="postgres", EngineVersion="12.15", MasterUsername="admin",
                           MasterUserPassword="password123", AllocatedStorage=20,
                           PubliclyAccessible=True, BackupRetentionPeriod=0)


def test_full_audit_generates_reports(aws, tmp_path):
    _seed()
    ctx = AuditContext(boto3.Session(region_name=REGION), [REGION])
    run_audit(ctx, workers=1)

    ids = {f.check_id for f in ctx.findings}
    for expected in ("EC2.IMDSV2", "EBS.UNATTACHED", "EC2.EIP_UNUSED", "S3.PUBLIC",
                     "IAM.ROLE_PUBLIC_TRUST", "IAM.USER_ADMIN", "RDS.PUBLIC",
                     "CLOUDTRAIL.MISSING", "EC2.PREVIOUS_GEN"):
        assert expected in ids, f"{expected} manquant : {sorted(ids)}"

    # Pas de doublon S3 / IAM quand plusieurs régions sont auditées
    assert sum(1 for f in ctx.findings if f.check_id == "S3.PUBLIC") == 1
    assert ctx.total_monthly_saving > 0
    assert 0 <= ctx.posture_score() < 100
    assert any(f.severity is Severity.CRITICAL for f in ctx.findings)

    pdf = tmp_path / "r.pdf"
    generate_pdf(ctx, str(pdf), client="ACME SAS")
    export_json(ctx, str(tmp_path / "r.json"))
    export_csv(ctx, str(tmp_path / "r.csv"))
    assert pdf.stat().st_size > 20_000
    assert json.loads((tmp_path / "r.json").read_text())["account_id"] == ctx.account_id


def test_sg_port_ranges():
    from sensedrift.checks.ec2 import _port_label
    assert _port_label({"IpProtocol": "-1"})[0] is Severity.CRITICAL
    assert _port_label({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535})[0] is Severity.CRITICAL
    assert _port_label({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443})[0] is None
    assert _port_label({"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080})[0] is Severity.MEDIUM


def test_score_counts_checks_not_resources():
    ctx = AuditContext(boto3.Session(region_name=REGION), [REGION])
    for i in range(40):
        ctx.add("EC2.UNTAGGED", Severity.LOW, "Gouvernance", "EC2", "t", "d", resource_id=str(i))
    assert ctx.posture_score() == 99
