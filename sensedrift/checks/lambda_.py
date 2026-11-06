"""AWS Lambda."""
from __future__ import annotations

import json
import re
from datetime import date, timedelta

import botocore.exceptions

from ..models import GOVERNANCE, SECURITY, Severity
from ._util import paginate

# Date de dépréciation (fin des correctifs de sécurité). Source : documentation
# « Lambda runtimes ». À tenir à jour.
RUNTIME_DEPRECATION = {
    "python2.7": date(2021, 7, 15), "python3.6": date(2022, 7, 18),
    "python3.7": date(2023, 12, 4), "python3.8": date(2024, 10, 14),
    "python3.9": date(2025, 12, 15), "python3.10": date(2026, 10, 31),
    "nodejs10.x": date(2021, 7, 30), "nodejs12.x": date(2023, 3, 31),
    "nodejs14.x": date(2023, 12, 4), "nodejs16.x": date(2024, 6, 12),
    "nodejs18.x": date(2025, 9, 1), "nodejs20.x": date(2026, 4, 30),
    "ruby2.7": date(2023, 12, 7), "ruby3.2": date(2026, 3, 31),
    "java8": date(2024, 1, 8), "go1.x": date(2024, 1, 8), "provided": date(2024, 1, 8),
    "dotnetcore3.1": date(2023, 4, 3), "dotnet6": date(2024, 12, 20), "dotnet7": date(2024, 5, 14),
}
UPCOMING_DAYS = 180

SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL|ACCESS_?KEY)",
                         re.I)
NOT_A_SECRET = re.compile(r"(_ARN|_ID|_NAME|_PATH|_URL|_REGION|_PARAM|_SSM)$", re.I)


def check_lambda(ctx, region: str):
    lm = ctx.client("lambda", region)
    today = date.today()

    for fn in paginate(lm, "list_functions", "Functions"):
        name = fn["FunctionName"]
        runtime = fn.get("Runtime")
        dep = RUNTIME_DEPRECATION.get(runtime or "")
        if dep and dep <= today:
            ctx.add("LAMBDA.DEPRECATED_RUNTIME", Severity.HIGH, SECURITY, "Lambda",
                    "Fonctions sur un runtime déprécié",
                    "Ces runtimes ne reçoivent plus de correctifs de sécurité. AWS bloque ensuite la "
                    "création, puis la mise à jour des fonctions concernées.",
                    remediation="Migrer vers un runtime supporté (ex. python3.13, nodejs22.x) après "
                                "tests en préproduction.",
                    resource_id=name, resource_detail=f"{runtime} · déprécié le {dep.strftime('%d/%m/%Y')}",
                    region=region, effort="Moyen")
        elif dep and dep - today <= timedelta(days=UPCOMING_DAYS):
            ctx.add("LAMBDA.RUNTIME_EOL_SOON", Severity.LOW, GOVERNANCE, "Lambda",
                    "Runtimes Lambda dépréciés dans moins de 6 mois",
                    "Ces fonctions devront être migrées prochainement.",
                    remediation="Planifier la migration vers un runtime plus récent.",
                    resource_id=name, resource_detail=f"{runtime} · fin le {dep.strftime('%d/%m/%Y')}",
                    region=region, effort="Moyen")

        env = (fn.get("Environment") or {}).get("Variables", {}) or {}
        suspicious = [k for k, v in env.items()
                      if SECRET_NAME.search(k) and not NOT_A_SECRET.search(k)
                      and not str(v).startswith(("arn:", "{{resolve:", "/"))]
        if suspicious:
            ctx.add("LAMBDA.ENV_SECRETS", Severity.MEDIUM, SECURITY, "Lambda",
                    "Secrets probables dans les variables d'environnement",
                    "Les variables d'environnement sont visibles par toute personne ayant un accès en "
                    "lecture à la fonction, et se retrouvent souvent dans le code d'infrastructure.",
                    remediation="Stocker les secrets dans AWS Secrets Manager ou SSM Parameter Store "
                                "(SecureString) et les lire à l'exécution.",
                    resource_id=name, resource_detail=", ".join(suspicious[:4]), region=region,
                    effort="Moyen")

        # Politique de ressource publique / URL sans authentification
        try:
            pol = json.loads(lm.get_policy(FunctionName=name)["Policy"])
            for st in pol.get("Statement", []):
                p = st.get("Principal")
                public = p == "*" or (isinstance(p, dict) and p.get("AWS") == "*")
                if st.get("Effect") == "Allow" and public and not st.get("Condition"):
                    ctx.add("LAMBDA.PUBLIC", Severity.HIGH, SECURITY, "Lambda",
                            "Fonctions invocables par n'importe qui",
                            "La politique de ressource autorise le principal « * » sans condition.",
                            remediation="Restreindre la politique au service ou au compte appelant "
                                        "(avec condition aws:SourceArn / aws:SourceAccount).",
                            resource_id=name, region=region)
                    break
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

        try:
            for u in lm.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", []):
                if u.get("AuthType") == "NONE":
                    ctx.add("LAMBDA.URL_NO_AUTH", Severity.LOW, SECURITY, "Lambda",
                            "URL de fonction Lambda sans authentification",
                            "La fonction est exposée sur Internet sans authentification IAM. C'est "
                            "parfois voulu (webhook), mais l'authentification doit alors être faite "
                            "dans le code.",
                            remediation="Passer en AuthType AWS_IAM, ou placer la fonction derrière "
                                        "API Gateway / CloudFront avec contrôle d'accès.",
                            resource_id=name, region=region)
        except botocore.exceptions.ClientError:
            pass
