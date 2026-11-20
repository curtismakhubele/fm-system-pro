# FM System Pro

Facilities management app with a browser interface and a Node.js server for authentication and shared data storage.

## Run locally

1. Install Node.js 20 or newer.
2. Copy `.env.example` to `.env` and set a unique administrator email, a strong password, and a random `SESSION_SECRET` of at least 32 characters.
3. Run `npm ci` and then `npm start`.
4. Open `http://localhost:8080`.

The server stores application data in `data/state.json` by default. Keep `.env` and `data/` private; neither belongs in source control. Configure email, Microsoft Graph, WhatsApp, or AI integrations only with server-side secrets in the host environment.

## WhatsApp inbox

The WhatsApp page includes a shared inbound inbox and reply thread. To enable it, configure these server-side values in the hosting environment (never in the browser): `WHATSAPP_PHONE_NUMBER_ID`, `WHATSAPP_ACCESS_TOKEN`, `WHATSAPP_GRAPH_VERSION`, `WHATSAPP_VERIFY_TOKEN`, and `WHATSAPP_APP_SECRET`.

In Meta for Developers, configure the webhook callback as `https://YOUR_HOST/webhooks/whatsapp`, use the same verification token, and subscribe to the WhatsApp `messages` field. The webhook verifies Meta's request signature before it stores inbound messages. Inbox access uses the app's existing sign-in and is limited to Admin, HQ, and Centre roles. Free-form replies are blocked after the 24-hour customer-service window; use an approved Meta template for messages outside that window.



- `index.html` — app interface
- `server.js` — authentication, API, and persistence
- `search-utils.js` — shared search helpers
- `.env.example` — environment variable names with placeholders

This repository contains the source code. Configure a hosting workflow separately for the target environment before enabling automated deployment.
