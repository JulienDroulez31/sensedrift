# Mise en ligne du site sensedrift.fr

Ton propre audit classe aujourd'hui le bucket `sensedrift-landing` comme **public**. C'est normal pour un hébergement « S3 static website », mais cela pose trois problèmes :

- S3 ne sert pas le site en **HTTPS** (seul CloudFront le peut) ;
- tout fichier déposé par erreur dans le bucket devient public ;
- un prospect qui lance un audit sur ton propre site trouverait un bucket public. Mauvais signal pour un vendeur d'audits de sécurité.

**Architecture cible** : bucket privé → CloudFront (Origin Access Control) → certificat ACM gratuit → domaine OVH.

## 1. Certificat HTTPS (ACM, obligatoirement en us-east-1)

```bash
aws acm request-certificate --region us-east-1 \
  --domain-name sensedrift.fr --subject-alternative-names www.sensedrift.fr \
  --validation-method DNS
```

Ajoute ensuite dans la zone DNS OVH les enregistrements CNAME de validation affichés dans la console ACM, et attends le statut « Émis ».

## 2. Distribution CloudFront (console, 5 minutes)

CloudFront → Créer une distribution :
- **Origine** : le bucket `sensedrift-landing` (le point de terminaison REST, *pas* l'URL « website ») ;
- **Accès à l'origine** : « Origin access control » → créer un OAC → accepter la mise à jour de la politique du bucket ;
- **Protocole viewer** : « Redirect HTTP to HTTPS » ;
- **Response headers policy** : `Managed-SecurityHeadersPolicy` (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy) ;
- **Noms alternatifs** : `sensedrift.fr`, `www.sensedrift.fr`, avec le certificat de l'étape 1 ;
- **Objet racine par défaut** : `index.html`.

## 3. Rendre le bucket privé

```bash
aws s3api delete-bucket-website --bucket sensedrift-landing
aws s3api put-public-access-block --bucket sensedrift-landing \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

Ne garde dans la politique du bucket que l'instruction ajoutée par CloudFront (principal `cloudfront.amazonaws.com`).

## 4. DNS chez OVH

- `www` → CNAME vers `dxxxx.cloudfront.net` ;
- domaine nu `sensedrift.fr` : OVH n'accepte pas de CNAME à la racine. Deux options :
  - **(a)** rediriger le domaine nu vers `https://www.sensedrift.fr` (redirection visible OVH) ;
  - **(b)** déléguer le DNS à Route 53 (0,50 $/mois) et créer un enregistrement ALIAS vers CloudFront. C'est la solution la plus propre.

## 5. Publier une mise à jour

```bash
aws s3 sync site/ s3://sensedrift-landing/ --delete --exclude "DEPLOIEMENT.md"
aws cloudfront create-invalidation --distribution-id <ID> --paths "/*"
```

## 6. Sécuriser ton propre compte

Ton rapport du 1er septembre signalait aussi :
- **aucun CloudTrail** : crée un trail multi-région (gratuit hors stockage) ;
- **GuardDuty indisponible** (`SubscriptionRequiredException`) : ton compte est probablement sur le plan gratuit AWS. Passe-le en plan payant pour activer GuardDuty.

Relance ensuite `sensedrift --profile <toi>` : vise la note A sur ton propre compte. C'est un excellent argument commercial.
