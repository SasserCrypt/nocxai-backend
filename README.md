# NoCxAI Backend – Render + MongoDB Atlas (Frankfurt)

Dieses Projekt ist fertig vorbereitet, um als Web Service bei Render
(`nocxai-backend.onrender.com`) zu laufen und deine NoCxAI-Frontend-Auth
( Login / Register / Profil / Passwort / Avatar ) zu bedienen.

## Endpunkte

- POST  /api/auth/register
- POST  /api/auth/login
- GET   /api/user/me
- PUT   /api/user/update
- PUT   /api/user/password
- POST  /api/user/avatar

## 1. MongoDB Atlas einrichten (Region: Frankfurt – eu-central-1)

1. Gehe zu https://cloud.mongodb.com und registriere dich.
2. Erstelle ein **Free Tier Cluster**:
   - Cloud Provider: AWS
   - Region: eu-central-1 (Frankfurt)
3. Erstelle einen DB-User (z.B. `nocxai_user`) mit starkem Passwort.
4. Erlaube Zugriffe:
   - IP Whitelist: `0.0.0.0/0` (oder restriktiver, wenn du möchtest).
5. Unter "Connect" -> "Drivers" bekommst du eine URI, z.B.:

   `mongodb+srv://nocxai_user:PASSWORT@cluster0.xxxxxx.mongodb.net/nocxai?retryWrites=true&w=majority`

6. Trage diese URI später bei Render in `MONGO_URI` ein.

## 2. Repo zu GitHub hochladen

1. Entpacke diese ZIP lokal oder direkt im Browser (GitHub Web-Upload).
2. Lege ein neues Repository an, z.B. `nocxai-backend`.
3. Lade alle Dateien hoch:
   - server.js
   - package.json
   - render.yaml
   - .env.example
   - uploads/avatars (Ordner, kann leer bleiben)
   - README.md

## 3. Render Web Service erstellen

1. Gehe zu https://render.com
2. "New" -> "Web Service"
3. Verbinde dein GitHub-Repo (`nocxai-backend`).
4. Render erkennt dank `render.yaml` automatisch:
   - Node
   - buildCommand: `npm install`
   - startCommand: `npm start`
   - Region: `frankfurt`
5. Erstelle den Service.

## 4. Environment Variables bei Render setzen

Unter "Environment" deines Services:

- `MONGO_URI`  -> deine Atlas-URI (siehe `.env.example`)
- `JWT_SECRET` -> ein langer, geheimer String (z.B. via Passwort-Generator)
- `BASE_URL`   -> `https://nocxai-backend.onrender.com`

`PORT` muss nicht gesetzt werden, Render übergibt den Port automatisch.

## 5. Frontend anbinden

In deinem NoCxAI-Frontend (auth.js) wird verwendet:

```js
const API_BASE = "https://nocxai-backend.onrender.com";
```

Damit sprechen:

- login.html
- register.html
- profile.html
- dashboard.html

direkt mit diesem Backend.

Sobald der Render-Service "Live" ist, funktionieren Login, Registrierung,
Profil-Update, Passwort-Änderung und Avatar-Upload ohne weitere Änderungen.
