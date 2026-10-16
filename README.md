# FM System Pro

Facilities management app with a browser interface and a Node.js server for authentication and shared data storage.

## Run locally

1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env` and set a unique administrator email, a strong password, and a random `SESSION_SECRET` of at least 32 characters.
3. Run `npm ci` and then `npm start`.
4. Open `http://localhost:8080`.

The server stores application data in `data/state.json` by default. Keep `.env` and `data/` private; neither belongs in source control. Configure email, Microsoft Graph, WhatsApp, or AI integrations only with server-side secrets in the host environment.

## Repository contents

- `index.html` — app interface
- `server.js` — authentication, API, and persistence
- `search-utils.js` — shared search helpers
- `.env.example` — environment variable names with placeholders

This repository contains the source code. Configure a hosting workflow separately for the target environment before enabling automated deployment.
