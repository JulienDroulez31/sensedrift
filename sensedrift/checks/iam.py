"""IAM (global). S'appuie sur le credential report, plus fiable et plus rapide
que d'interroger chaque utilisateur un par un."""
from __future__ import annotations

import csv
import io
import time
from datetime import datetime

import botocore.exceptions

from ..models import GOVERNANCE, SECURITY, Severity
from ._util import days_since, paginate

KEY_MAX_AGE = 90
UNUSED_DAYS = 45   # CIS v3.0 : identifiants inutilisés depuis 45 jours


def _parse_date(v: str):
    if not v or v in ("N/A", "no_information", "not_supported"):
        return None
    return datetime.fromisoformat(v.replace("Z", "+00:00"))


def _credential_report(iam) -> list:
    for _ in range(20):
        if iam.generate_credential_report()["State"] == "COMPLETE":
            break
        time.sleep(1)
    content = iam.get_credential_report()["Content"]
    if isinstance(content, bytes):
        content = content.decode()
    return list(csv.DictReader(io.StringIO(content)))


def _principal_is_public(principal) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for v in principal.values():
            vals = v if isinstance(v, list) else [v]
            if "*" in vals:
                return True
    return False


def check_iam(ctx):
    iam = ctx.client("iam")
    rows = _credential_report(iam)
    root = next((r for r in rows if r["user"] == "<root_account>"), None)
    users = [r for r in rows if r["user"] != "<root_account>"]

    # ── Compte root
    if root:
        if root.get("mfa_active") != "true":
            ctx.add("IAM.ROOT_MFA", Severity.CRITICAL, SECURITY, "IAM",
                    "MFA non activé sur le compte root",
                    "Le compte root a tous les droits, y compris fermer le compte ou modifier la "
                    "facturation. Protégé par un simple mot de passe, il est la cible n°1.",
                    remediation="Activer immédiatement un MFA (clé FIDO2 de préférence) sur le root, "
                                "et réserver ce compte aux rares opérations qui l'exigent.",
                    resource_id="root", references=["CIS 1.5"])
        if "true" in (root.get("access_key_1_active"), root.get("access_key_2_active")):
            ctx.add("IAM.ROOT_KEYS", Severity.CRITICAL, SECURITY, "IAM",
                    "Clés d'accès actives sur le compte root",
                    "Une clé d'accès root qui fuite (dépôt Git, poste compromis) donne un contrôle "
                    "total et irrévocable du compte.",
                    remediation="Supprimer les clés root et utiliser des rôles IAM à la place.",
                    resource_id="root", references=["CIS 1.4"])
        last = _parse_date(root.get("password_last_used", ""))
        if last and days_since(last) is not None and days_since(last) < 30:
            ctx.add("IAM.ROOT_USAGE", Severity.MEDIUM, SECURITY, "IAM",
                    "Compte root utilisé récemment",
                    f"Le compte root a été utilisé il y a {days_since(last)} jour(s). Il ne devrait "
                    "pas servir aux opérations courantes.",
                    remediation="Créer des utilisateurs nominatifs via IAM Identity Center et "
                                "surveiller toute connexion root avec une alerte.",
                    resource_id="root", references=["CIS 1.7"])

    console_users = [u for u in users if u.get("password_enabled") == "true"]

    # ── Politique de mots de passe (pertinente seulement s'il existe des utilisateurs console)
    try:
        p = iam.get_account_password_policy()["PasswordPolicy"]
        issues = []
        if p.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"longueur minimale {p.get('MinimumPasswordLength', 0)} (< 14)")
        if p.get("PasswordReusePrevention", 0) < 24:
            issues.append("historique de mots de passe < 24")
        if issues and console_users:
            ctx.add("IAM.PASSWORD_POLICY", Severity.MEDIUM, SECURITY, "IAM",
                    "Politique de mots de passe insuffisante",
                    f"Faiblesses relevées : {', '.join(issues)}.",
                    remediation="Exiger au moins 14 caractères et empêcher la réutilisation des 24 "
                                "derniers mots de passe.",
                    references=["CIS 1.8", "CIS 1.9"])
    except botocore.exceptions.ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
        if console_users:
            ctx.add("IAM.PASSWORD_POLICY", Severity.MEDIUM, SECURITY, "IAM",
                    "Aucune politique de mots de passe IAM",
                    f"{len(console_users)} utilisateur(s) peuvent se connecter à la console avec un "
                    "mot de passe, sans aucune exigence de robustesse.",
                    remediation="Définir une politique : 14 caractères minimum, historique de 24.",
                    remediation_cli="aws iam update-account-password-policy --minimum-password-length 14 "
                                    "--password-reuse-prevention 24",
                    references=["CIS 1.8", "CIS 1.9"])

    # ── Utilisateurs
    for u in users:
        name = u["user"]
        if u.get("password_enabled") == "true" and u.get("mfa_active") != "true":
            ctx.add("IAM.USER_MFA", Severity.HIGH, SECURITY, "IAM",
                    "Utilisateurs console sans MFA",
                    "Ces utilisateurs se connectent à la console avec un simple mot de passe. Un "
                    "hameçonnage ou une fuite suffit à compromettre le compte.",
                    remediation="Imposer le MFA, ou mieux : migrer vers IAM Identity Center (SSO).",
                    resource_id=name, references=["CIS 1.10"])

        last_activity = [d for d in (
            _parse_date(u.get("password_last_used", "")),
            _parse_date(u.get("access_key_1_last_used_date", "")),
            _parse_date(u.get("access_key_2_last_used_date", "")),
        ) if d]
        created = _parse_date(u.get("user_creation_time", ""))
        idle = days_since(max(last_activity)) if last_activity else days_since(created)
        has_creds = u.get("password_enabled") == "true" or "true" in (
            u.get("access_key_1_active"), u.get("access_key_2_active"))
        if has_creds and idle is not None and idle > UNUSED_DAYS:
            ctx.add("IAM.INACTIVE_USER", Severity.MEDIUM, SECURITY, "IAM",
                    f"Utilisateurs inactifs depuis plus de {UNUSED_DAYS} jours",
                    "Ces identifiants ne servent plus mais restent valides : c'est une surface "
                    "d'attaque inutile (ancien salarié, prestataire, script abandonné).",
                    remediation="Désactiver les identifiants, puis supprimer l'utilisateur après "
                                "confirmation.",
                    resource_id=name, resource_detail=f"inactif depuis {idle} j",
                    references=["CIS 1.12"])

        for n in ("1", "2"):
            if u.get(f"access_key_{n}_active") != "true":
                continue
            age = days_since(_parse_date(u.get(f"access_key_{n}_last_rotated", "")))
            if age is not None and age > KEY_MAX_AGE:
                ctx.add("IAM.KEY_ROTATION", Severity.MEDIUM, SECURITY, "IAM",
                        f"Clés d'accès de plus de {KEY_MAX_AGE} jours",
                        "Plus une clé est ancienne, plus elle a de chances d'avoir été copiée "
                        "quelque part (poste, CI, dépôt Git).",
                        remediation="Faire tourner la clé, ou mieux : remplacer les clés longue durée "
                                    "par des rôles IAM (OIDC pour la CI, rôles d'instance, SSO).",
                        resource_id=name, resource_detail=f"clé {n} · {age} j",
                        references=["CIS 1.14"])

    # ── Politiques attachées directement & droits administrateur
    for user in paginate(iam, "list_users", "Users"):
        uname = user["UserName"]
        attached = [p["PolicyName"] for p in paginate(
            iam, "list_attached_user_policies", "AttachedPolicies", UserName=uname)]
        if "AdministratorAccess" in attached:
            ctx.add("IAM.USER_ADMIN", Severity.MEDIUM, SECURITY, "IAM",
                    "Utilisateurs IAM avec AdministratorAccess direct",
                    "Des droits administrateur permanents sur un utilisateur IAM : la compromission "
                    "de ses identifiants donne le contrôle total du compte.",
                    remediation="Attribuer les droits via des groupes ou des rôles assumés "
                                "temporairement, avec MFA obligatoire.",
                    resource_id=uname, references=["CIS 1.15"])
        if list(paginate(iam, "list_user_policies", "PolicyNames", UserName=uname)):
            ctx.add("IAM.INLINE_POLICY", Severity.LOW, GOVERNANCE, "IAM",
                    "Politiques inline sur des utilisateurs",
                    "Les politiques inline sont invisibles dans la liste des politiques et "
                    "difficiles à auditer.",
                    remediation="Les remplacer par des politiques gérées attachées à des groupes.",
                    resource_id=uname, references=["CIS 1.15"])

    # ── Rôles assumables par n'importe qui
    for role in paginate(iam, "list_roles", "Roles"):
        doc = role.get("AssumeRolePolicyDocument", {})
        for st in doc.get("Statement", []) if isinstance(doc, dict) else []:
            if st.get("Effect") != "Allow" or not _principal_is_public(st.get("Principal")):
                continue
            conditioned = bool(st.get("Condition"))
            ctx.add("IAM.ROLE_PUBLIC_TRUST", Severity.MEDIUM if conditioned else Severity.CRITICAL,
                    SECURITY, "IAM",
                    "Rôles IAM assumables par n'importe quel principal",
                    "La politique de confiance autorise le principal « * »"
                    + (", restreint par une condition à vérifier." if conditioned else
                       " sans condition : n'importe quel compte AWS peut assumer ce rôle."),
                    remediation="Limiter le principal aux comptes, services ou rôles explicitement "
                                "autorisés (et exiger un ExternalId pour les tiers).",
                    resource_id=role["RoleName"])
            break
