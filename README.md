# RECON_ &nbsp;·&nbsp; *enumerate. exploit. report.*

**Recon** — application web **dockerisée** pour gérer, **par projet**, la
checklist des vulnérabilités à vérifier lors d'un audit de sécurité web.
Direction artistique « terminal » (vert phosphore, thèmes clair/sombre).

- Authentification (cookie de session signé JWT, mots de passe hachés bcrypt)
- Gestion des audits **par projet**, chacun avec sa propre checklist
- **Cloisonnement par projet** : un projet n'est visible que de son
  propriétaire et des collaborateurs qu'il a invités (par e-mail, parmi les
  utilisateurs de l'application) ; les admins voient tous les projets. Seul le
  propriétaire (ou un admin) invite, retire et supprime ; un collaborateur
  peut quitter le projet. Les autres utilisateurs reçoivent un 404, y compris
  via le lien `/p/<slug>`
- **Collaboration temps réel** (WebSocket / Socket.IO) : plusieurs auditeurs sur
  un même projet voient les changements en direct (cases, vuln/non-vuln,
  variables, notes) et qui est en ligne / en train d'éditer quoi
- **Profil personnalisable** (page `/profile`) : couleur et **photo de
  profil** (JPEG/PNG uniquement, ≤ 2 Mo, ≤ 8192 px de côté). La structure
  complète du fichier est vérifiée (chunks/CRC et flux de pixels PNG, segments
  JPEG) et l'image est reconstruite sans métadonnées (EXIF/GPS, commentaires,
  données après la fin du fichier) avant d'être stockée en base et servie en
  `nosniff` + CSP `sandbox`. Reflétées dans la présence
- **Aucun contenu applicatif avant authentification** : pages et scripts de
  l'application (`frontend/private/`) ne sont servis qu'à une session valide
  (`admin.js` / `/admin` aux seuls admins) ; seuls la page de connexion, la
  réinitialisation de mot de passe et leurs ressources sont publiques
- Référentiel de vulnérabilités basé sur l'**OWASP WSTG** (modifiable)
- Espace **`/admin`** : gestion du référentiel (créer / modifier / supprimer),
  **import / export JSON** en masse, et gestion des **utilisateurs**
- Base de données **PostgreSQL** (données variées : projets, checklists, users)
- Entièrement conteneurisé et **portable** d'un serveur à l'autre

## Architecture

```
┌──────────────────────────┐      ┌──────────────────┐
│  app  (Node/Express)     │ ───► │  db (PostgreSQL) │
│  API REST + frontend     │      │  volume persistant│
│  conteneur "pentest_app" │      │ "pentest_db"      │
└──────────────────────────┘      └──────────────────┘
        port 3000                  réseau interne only
```

Deux conteneurs orchestrés par Docker Compose. Le frontend (HTML/CSS/JS) est
servi directement par le backend — un seul port à exposer.

```
cheatsheet/
├── docker-compose.yml      # orchestration des 2 services
├── .env.example            # variables à copier vers .env
├── .dockerignore
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── server.js           # point d'entrée Express
│       ├── seed.js             # admin + référentiel initial
│       ├── config/db.js        # connexion PostgreSQL (Sequelize, avec retry)
│       ├── models/             # User, Project, VulnItem (Sequelize)
│       ├── middleware/         # auth (JWT) + admin
│       ├── routes/             # auth, projects, admin
│       └── data/wstgTemplate.js# checklist OWASP WSTG par défaut
└── frontend/
    ├── public/             # servi à tous : connexion, reset, CSS, polices
    │   ├── login.html, reset.html
    │   └── js/             # base.js (fetch + CSRF, thème), login.js, reset.js
    └── private/            # servi uniquement après authentification
        ├── app.html        # app principale (projets + checklists)
        ├── profile.html    # profil utilisateur
        ├── admin.html      # espace administration (admins)
        └── js/             # app.js, profile.js, profile-page.js, admin.js
```

## Démarrage rapide

Pré-requis : Docker + Docker Compose.

```bash
cp .env.example .env
# éditez .env : changez impérativement les mots de passe et JWT_SECRET
#   openssl rand -hex 32   # pour générer un JWT_SECRET
# JWT_SECRET est obligatoire (≥ 32 caractères) : l'application refuse de
# démarrer en production avec une valeur courte ou celle de l'exemple.
# Derrière un reverse proxy HTTPS : COOKIE_SECURE=true et TRUST_PROXY=1.

docker compose up -d --build
```

Application disponible sur **http://localhost:3000**

Connexion initiale avec le compte admin défini dans `.env`
(`ADMIN_EMAIL` / `ADMIN_PASSWORD`, par défaut `admin@local` / `admin1234`).

> ⚠️ Changez ces identifiants avant toute mise en service.

## Utilisation

1. **Connexion** avec le compte admin.
2. **Projets** → *Nouveau projet* : une checklist complète est générée
   automatiquement à partir du référentiel.
3. Sur un projet, traitez chaque vérification rapidement : cochez
   **Vérifiée**, puis indiquez **Vulnérable / Non vulnérable**. Les éléments
   vérifiés non vulnérables sont rayés (vert) et renvoyés en bas de liste ; les
   vulnérabilités (rouge) et les éléments non encore traités restent en tête.
   Le chevron *(▾)* ouvre **Plus de détails** : l'aperçu (coloration syntaxique)
   de la **commande de vérification** définie en admin, avec bouton **Copier**,
   et un encart **notes** facultatif. L'avancement et le nombre de
   vulnérabilités sont calculés en direct.
   - **Variables** : en haut du projet, définissez des variables (ex. `SCOPE` =
     `https://mon.scope.fr`). Toute commande contenant `$SCOPE` / `${SCOPE}` est
     remplie dynamiquement dans l'aperçu et à la copie.
   - **Thème** : bouton ☀️/🌙 dans l'en-tête pour basculer clair / sombre
     (mémorisé dans le navigateur).
4. **Administration** (`/admin`, admins uniquement) :
   - **Référentiel** : créer / modifier / supprimer des vulnérabilités, et
     définir pour chacune une **commande de vérification** et des **notes** par
     défaut (reprises dans chaque nouveau projet). Une **zone de danger** permet
     de *tout supprimer* (confirmation par saisie du mot « supprimer » et rappel
     d'export JSON au préalable).
   - **Import / Export JSON** : sauvegarder ou charger un référentiel complet
     (mode *fusion* ou *remplacement*).
   - **Utilisateurs** : créer des comptes, changer les rôles (**admin** /
     **auditeur** — un admin ne peut pas se retirer son propre rôle), et
     **générer un lien de réinitialisation** sécurisé (token à durée limitée,
     24 h) à transmettre à l'utilisateur, qui définit lui-même son mot de passe.

## SSO (OIDC / Keycloak auto-hébergé)

- **Fournisseur sur réseau privé ou en http** : le serveur n'appelle que des
  URLs SSO en https pointant vers une adresse publique (anti-SSRF). Un Keycloak
  sur le LAN, un nom de service Docker (`keycloak`) ou un domaine qui résout
  vers une IP interne est refusé tant que son hôte n'est pas listé dans `.env` :

  ```bash
  SSO_ALLOWED_HOSTS=keycloak.mondomaine.lan,keycloak:8080,192.168.1.20
  ```

  Puis `docker compose up -d`. Sans cela, la connexion échoue au retour du
  fournisseur (« Fournisseur SSO injoignable … ») et l'enregistrement de la
  configuration SSO est refusé.
- **Compte administrateur** : il n'est jamais lié automatiquement par e-mail.
  Connectez-vous une fois avec le mot de passe local, puis *Profil* →
  *Lier le SSO* ; les connexions suivantes passent par le SSO. À défaut, la
  liaison peut être écrite en base (ID de l'utilisateur dans Keycloak = `sub`) :

  ```sql
  UPDATE users
  SET "ssoSubject" = (SELECT split_part("authorizationUrl", '?', 1) FROM sso_config LIMIT 1)
                     || '|' || '<ID-utilisateur-Keycloak>'
  WHERE email = 'admin@exemple.fr';
  ```

  (`docker compose exec db sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"'`)

## Portabilité

Tout l'état persistant vit dans le volume Docker `db_data`.

```bash
# Sauvegarde de la base
docker compose exec -T db pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" \
  | gzip > backup.sql.gz

# Restauration sur un autre serveur
gunzip -c backup.sql.gz \
  | docker compose exec -T db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"
```

Pour déplacer l'application : copiez le dépôt + votre `.env` sur le nouveau
serveur, restaurez la base, puis `docker compose up -d --build`.

## API (résumé)

| Méthode | Route | Description |
|---|---|---|
| POST | `/api/auth/login` | Connexion |
| POST | `/api/auth/logout` | Déconnexion |
| GET | `/api/auth/me` | Session courante |
| GET/POST | `/api/projects` | Lister / créer un projet |
| GET/PATCH/DELETE | `/api/projects/:id` | Détail / modifier / supprimer |
| PATCH | `/api/projects/:id/checklist/:itemId` | Mettre à jour une vérification |
| POST | `/api/projects/:id/resync` | Importer les nouveaux items du référentiel |
| GET/POST | `/api/projects/:id/members` | Lister / inviter un collaborateur (propriétaire) |
| DELETE | `/api/projects/:id/members/:userId` | Retirer un collaborateur / quitter le projet |
| GET | `/api/users` | Annuaire (e-mails) pour inviter des collaborateurs |
| GET | `/api/admin/audit` | Journal d'audit (admin ; `q`, `action`, `before`, `limit`) |
| GET/POST | `/api/admin/vulns` | Lister / créer une vulnérabilité (admin) |
| PATCH/DELETE | `/api/admin/vulns/:id` | Modifier / supprimer (admin) |
| GET | `/api/admin/vulns/export` | Export JSON (admin) |
| POST | `/api/admin/vulns/import` | Import JSON en masse (admin) |
| GET/POST | `/api/admin/users` | Lister / créer un utilisateur (admin) |
| PATCH/DELETE | `/api/admin/users/:id` | Modifier / supprimer (admin) |

## Sécurité

- Mots de passe hachés (bcrypt), jamais renvoyés par l'API.
- SSO : un compte est lié à l'identité du fournisseur (émetteur + `sub`), qui
  prime ensuite sur l'e-mail. La première liaison par e-mail exige un e-mail
  **vérifié** par le fournisseur (option admin pour les fournisseurs qui ne
  l'indiquent pas), n'est jamais faite automatiquement pour un compte admin
  (lien depuis le profil, une fois connecté) et les comptes créés via SSO sont
  toujours auditeurs.
- Anti-SSRF : les URLs SSO appelées par le serveur doivent être en https et
  pointer vers une adresse publique (vérifiée à la connexion, sans suivre de
  redirection). Un fournisseur sur réseau privé s'autorise explicitement via
  `SSO_ALLOWED_HOSTS`.
- **Journal d'audit** (onglet *Journal* de `/admin`) : connexions et échecs,
  blocages anti-bruteforce, comptes (création, rôle, mot de passe, liens de
  réinitialisation, suppression), SSO, projets (création, modification,
  partage, suppression, accès refusés) et référentiel. En ajout seul (un
  trigger PostgreSQL refuse UPDATE/DELETE) ; ni secret, ni mot de passe, ni
  contenu de projet n'y est écrit.
- Temps réel : l'accès au projet est vérifié à chaque `join` ; les connexions
  WebSocket d'un utilisateur sont fermées dès que ses sessions sont révoquées
  (déconnexion, changement/réinitialisation de mot de passe, changement de
  rôle, suppression du compte), à l'expiration du jeton, et il est retiré de
  la room d'un projet dès que son accès lui est retiré.
- Cookie de session `HttpOnly`, `SameSite=Lax`, `Secure` en production.
- PostgreSQL non exposé sur l'hôte par défaut (réseau Docker interne).
- En-têtes `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

> Derrière un reverse proxy en HTTPS pour la production (le flag `Secure` du
> cookie suppose une connexion TLS).
