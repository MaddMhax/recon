# RECON_ &nbsp;·&nbsp; *enumerate. exploit. report.*

**Recon** — application web **dockerisée** pour gérer, **par projet**, la
checklist des vulnérabilités à vérifier lors d'un audit de sécurité web.
Direction artistique « terminal » (vert phosphore, thèmes clair/sombre).

- Authentification (cookie de session signé JWT, mots de passe hachés bcrypt)
- Gestion des audits **par projet**, chacun avec sa propre checklist
- **Collaboration temps réel** (WebSocket / Socket.IO) : plusieurs auditeurs sur
  un même projet voient les changements en direct (cases, vuln/non-vuln,
  variables, notes) et qui est en ligne / en train d'éditer quoi
- **Profil personnalisable** (menu « Personnaliser ») : couleur et **photo de
  profil** (JPEG/PNG uniquement, validée par magic bytes, ≤ 2 Mo, stockée en
  base et servie en `nosniff` + CSP `sandbox`), reflétées dans la présence
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
    ├── index.html          # app principale (projets + checklists)
    ├── admin.html          # espace administration
    ├── css/style.css
    └── js/                 # api.js, app.js, admin.js
```

## Démarrage rapide

Pré-requis : Docker + Docker Compose.

```bash
cp .env.example .env
# éditez .env : changez impérativement les mots de passe et JWT_SECRET
#   openssl rand -hex 32   # pour générer un JWT_SECRET

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
| GET/POST | `/api/admin/vulns` | Lister / créer une vulnérabilité (admin) |
| PATCH/DELETE | `/api/admin/vulns/:id` | Modifier / supprimer (admin) |
| GET | `/api/admin/vulns/export` | Export JSON (admin) |
| POST | `/api/admin/vulns/import` | Import JSON en masse (admin) |
| GET/POST | `/api/admin/users` | Lister / créer un utilisateur (admin) |
| PATCH/DELETE | `/api/admin/users/:id` | Modifier / supprimer (admin) |

## Sécurité

- Mots de passe hachés (bcrypt), jamais renvoyés par l'API.
- Cookie de session `HttpOnly`, `SameSite=Lax`, `Secure` en production.
- PostgreSQL non exposé sur l'hôte par défaut (réseau Docker interne).
- En-têtes `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`.

> Derrière un reverse proxy en HTTPS pour la production (le flag `Secure` du
> cookie suppose une connexion TLS).
