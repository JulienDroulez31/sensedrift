# SenseDrift — audit AWS sécurité & coûts

Outil en ligne de commande qui analyse un compte AWS **en lecture seule** et produit :

- un **rapport PDF client** (synthèse exécutive, score de posture, dépenses réelles, économies chiffrées, plan d'action priorisé, détail par contrôle, annexe méthodologique) ;
- un **export CSV** (ouvrable dans Excel, pratique pour chiffrer un devis) ;
- un **export JSON** (historique, intégrations, futur tableau de bord).

50 contrôles couvrent EC2, EBS, Security Groups, S3, IAM, RDS/Aurora, Lambda, VPC, NAT Gateway, Load Balancers, CloudTrail, GuardDuty, Security Hub, IAM Access Analyzer, AWS Config, CloudWatch Logs, Cost Explorer et Compute Optimizer. Ils sont alignés sur le CIS AWS Foundations Benchmark v3.0 quand c'est pertinent.

## Prérequis

- **Python 3.9 ou plus récent** : vérifiez avec `python3 --version`.
- **AWS CLI v2**, avec des identifiants configurés pour le compte à auditer.

### Installer Python

Ubuntu, Debian ou WSL :

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
```

macOS (avec [Homebrew](https://brew.sh)) :

```bash
brew install python
```

Windows : installer Python depuis [python.org](https://www.python.org/downloads/) en cochant « Add python.exe to PATH », ou utiliser WSL.

### Configurer l'accès AWS

Si `aws sts get-caller-identity` affiche votre compte, c'est déjà fait. Sinon :

```bash
aws configure
```

Pour un audit, des droits en lecture seule suffisent : `SecurityAudit` et `ViewOnlyAccess`, plus les droits listés dans `deploy/sensedrift-audit-role.yaml`.

## Installation

Depuis le dossier du projet :

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

```bash
pip install -e ".[dev]"
```

Sous Windows (PowerShell), activez l'environnement avec `.venv\Scripts\Activate.ps1`. À chaque nouveau terminal, réactivez-le avec `source .venv/bin/activate` avant d'utiliser `sensedrift`.

## Utilisation

Sur votre propre compte, avec vos identifiants AWS par défaut :

```bash
sensedrift --regions eu-west-3 eu-west-1
```

Si vous utilisez plusieurs profils AWS (listez-les avec `aws configure list-profiles`), précisez lequel :

```bash
sensedrift --profile <nom-du-profil> --regions eu-west-3 eu-west-1
```

Sur le compte d'un client (après déploiement du rôle, voir plus bas) :

```bash
sensedrift --role-arn arn:aws:iam::111122223333:role/SenseDriftAuditRole \
           --external-id <id-unique-du-client> \
           --client "ACME SAS" --all-regions
```

Les fichiers sont écrits dans `rapports/`. Options utiles :

| Option | Rôle |
|---|---|
| `--all-regions` | Audite toutes les régions activées du compte |
| `--lookback-days 14` | Fenêtre d'analyse des métriques (instances inactives, NAT, RDS) |
| `--no-cost-explorer` | N'interroge pas Cost Explorer (0,01 $ par requête, environ 6 requêtes par audit) |
| `--usd-eur 0.86` | Taux de conversion utilisé pour les estimations |
| `-v` | Mode verbeux |

Rapport d'exemple sans compte AWS (données fictives) :

```bash
python3 examples/demo_report.py
```

## Onboarding d'un client (rôle IAM avec ExternalId)

1. Générez un ExternalId unique par client (par ex. `python -c "import secrets;print(secrets.token_urlsafe(24))"`) et conservez-le dans votre CRM.
2. Envoyez au client le modèle `deploy/sensedrift-audit-role.yaml`. Il crée en 2 minutes un rôle :
   - **lecture seule** (`SecurityAudit` + `ViewOnlyAccess` + droits de facturation) ;
   - qui **interdit explicitement** la lecture du contenu des données (objets S3, secrets, tables, logs) ;
   - que seul votre compte peut assumer, et uniquement avec le bon ExternalId.
3. Le client vous transmet l'ARN du rôle (sortie `RoleArn` de la stack). Il révoque l'accès en supprimant la stack.

Pour un onboarding en un clic, hébergez le modèle sur S3 et envoyez un lien « quick-create » :

```
https://console.aws.amazon.com/cloudformation/home#/stacks/quickcreate?templateURL=https://<bucket>.s3.eu-west-3.amazonaws.com/sensedrift-audit-role.yaml&stackName=SenseDriftAudit&param_SenseDriftAccountId=<VOTRE_COMPTE>&param_ExternalId=<ID_CLIENT>
```

Le compte qui exécute SenseDrift a seulement besoin de `sts:AssumeRole` sur `arn:aws:iam::*:role/SenseDriftAuditRole`.

## Déploiement du site (GitHub Actions)

Le workflow `.github/workflows/deploy-site.yml` publie le dossier `site/` dans le bucket S3 `sensedrift-landing` à chaque modification de `site/` sur `main` (ou à la demande depuis l'onglet **Actions**). L'authentification passe par OIDC : aucune clé AWS n'est stockée dans GitHub.

Mise en place, une seule fois :

1. Dans la console AWS → CloudFormation → *Créer une stack*, importer `deploy/github-deploy-role.yaml` (nom de stack conseillé : `github-deploy-site`). Si le fournisseur d'identité `token.actions.githubusercontent.com` existe déjà dans IAM, mettre `CreateOIDCProvider` à `false`.
2. Dans GitHub → *Settings → Secrets and variables → Actions → Variables*, définir :
   - `AWS_DEPLOY_ROLE_ARN` = sortie `RoleArn` de la stack ;
   - `AWS_REGION` = région du bucket, si différente de `eu-west-1` ;
   - `CLOUDFRONT_DISTRIBUTION_ID` (optionnel, une fois CloudFront en place).
3. Lancer le workflow depuis *Actions → Déployer le site → Run workflow*.

Le rôle ne peut écrire que dans ce bucket, et seulement depuis la branche `main` de ce dépôt. Les fichiers `*.md` du dossier `site/` ne sont jamais publiés.

## Tests

```bash
pytest -q
```

Les tests simulent un compte AWS complet avec moto (aucun appel réel).

## Architecture

```
sensedrift/
  cli.py             # options, assume-role, exécution parallèle par région
  models.py          # Finding, Severity, AuditContext (score, erreurs, cache)
  pricing.py         # tarifs indicatifs + API AWS Price List
  checks/            # un module par domaine ; chaque check appelle ctx.add(...)
  report/pdf.py      # rapport client (polices DejaVu embarquées)
  report/export.py   # JSON / CSV
deploy/              # rôle d'audit CloudFormation pour les clients
examples/            # rapport de démonstration
tests/
```

Ajouter un contrôle : écrire une fonction `check_xxx(ctx, region)` qui appelle `ctx.add("SERVICE.ID", Severity.X, catégorie, service, titre, description, remediation=..., resource_id=..., monthly_saving_eur=...)`, puis l'enregistrer dans `checks/__init__.py`. Les erreurs (permissions, service non activé) sont capturées automatiquement et apparaissent dans l'annexe « Couverture et limites » au lieu d'être comptées comme des constats.

## Maintenance

Deux tables datées sont à revoir chaque trimestre :
- `checks/lambda_.py` → `RUNTIME_DEPRECATION` (runtimes Lambda dépréciés) ;
- `checks/rds.py` → `END_OF_STANDARD_SUPPORT` (versions RDS en Extended Support payant).
