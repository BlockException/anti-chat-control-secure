# Anti Chat Control Secure

<p align="center">
  <a href="https://github.com/blockexception/anti-chat-control-secure/actions/workflows/ci.yml">
    <img src="https://github.com/blockexception/anti-chat-control-secure/actions/workflows/ci.yml/badge.svg" alt="GitHub Actions status" />
  </a>
  <img src="https://img.shields.io/badge/Node.js-20.x-brightgreen?logo=node.js&style=flat-square" alt="Node.js" />
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="MIT License" />
</p>

## Übersicht

Anti Chat Control Secure ist ein produktionsorientierter Prototyp für einen sicheren Browser-basierten Chat mit clientseitiger Ende-zu-Ende-Verschlüsselung.

## Architektur

- `server.js` — Express-Server mit WebSocket-Relay, persistenter Warteschlange und Replay-Schutz.
- `public/index.html` — Browser-basierte Benutzeroberfläche für Anmeldung und Chat.
- `public/app.js` — Client-seitige Kryptografie mit ECDH, AES-GCM, HKDF und Sitzungstoken.
- `public/bundle.js` — kompakter Browser-Build.
- `.github/workflows/ci.yml` — GitHub Actions CI-Pipeline.

## Sicherheitsprinzipien

- Ende-zu-Ende-Verschlüsselung auf dem Client.
- Server speichert keine Klartextnachrichten.
- Authentifizierung via gehashte Passwörter.
- Multi-Faktor-Authentifizierung (MFA) optional unterstützbar.
- Replay-Schutz mit eindeutigen Nachrichten-IDs.
- Offline-Zustellung mit persistenter Warteschlange.
- Sichere Asset-Signaturprüfung per Build.

## Nutzung

```bash
npm install
npm start
```

Öffne anschließend `http://localhost:3000`.

## CI / Validierung

Die GitHub Actions Pipeline führt folgende Schritte aus:

- Checkout
- Node.js Setup
- npm Cache
- `npm ci`
- `npm run lint`
- `npm test`
- `npm run build`

## Produktionsreife

Diese Lösung ist für GitHub Actions ausgelegt und verwendet:

- `esbuild` zur schnellen Paketierung und Minimierung
- `jest` zur Ausführung von Unit-Tests
- `eslint` zur statischen Code-Analyse
- `npm ci` für deterministische CI-Installationen

## Lizenz

MIT

