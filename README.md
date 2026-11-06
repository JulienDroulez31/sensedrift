# SenseDrift — audit AWS sécurité & coûts

Outil en ligne de commande qui analyse un compte AWS **en lecture seule** et produit :

- un **rapport PDF client** (synthèse exécutive, score de posture, dépenses réelles, économies chiffrées, plan d'action priorisé, détail par contrôle, annexe méthodologique) ;
- un **export CSV** (ouvrable dans Excel, pratique pour chiffrer un devis) ;
- un **export JSON** (historique, intégrations, futur tableau de bord).

50 contrôles couvrent EC2, EBS, Security Groups, S3, IAM, RDS/Aurora, Lambda, VPC, NAT Gateway, Load Balancers, CloudTrail, GuardDuty, Security Hub, IAM Access Analyzer, AWS Config, CloudWatch Logs, Cost Explorer et Compute Optimizer. Ils sont alignés sur le CIS AWS Foundations Benchmark v3.0 quand c'est pertinent.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Utilisation

Sur votre propre compte (profil AWS CLI) :

```bash
sensedrift --profile perso --regions eu-west-3 eu-west-1
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
python examples/demo_report.py
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
