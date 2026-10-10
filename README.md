# SENTINEL // Network & Privacy Audit

A modern, professional **Browser Security, Privacy & Network Leak Audit Tool**
built with React, TypeScript and Tailwind CSS v4. SENTINEL runs entirely in the
browser and exposes the network identity a website can silently extract from
your browser — most notably via the **WebRTC** API, which can reveal your real
public and local IP addresses even when you are behind a VPN or proxy.

> **Why this matters:** WebRTC's ICE negotiation is designed to discover the
> best network path between peers. To do that it enumerates every network
> interface and shares those addresses with the remote endpoint. A malicious
> page can abuse this to unmask a visitor's true IP address (a "WebRTC leak").

---

## Purpose

SENTINEL gives security-conscious users an immediate, client-side verdict on
whether their browser is leaking identifying network information. It is
**not** a full firewall or VPN; it is an *audit* tool that surfaces the raw
data a remote peer could collect.

## Key Security Pillars Audited

| Pillar | Description | Status |
| --- | --- | --- |
| **WebRTC IP Leak** | Detects public + local IPs exposed during ICE candidate gathering. | ✅ Implemented |
| **Local Network Enumeration** | Surfaces `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, link-local and loopback addresses. | ✅ Implemented |
| **mDNS Obfuscation** | Flags `.local` hostnames the browser uses to mask local addresses. | ✅ Implemented |
| **Canvas Fingerprinting** | SHA-256 of an off-screen canvas render to estimate device uniqueness. | ✅ Implemented |
| **Web Audio Fingerprinting** | SHA-256 of an offline oscillator/compressor render. | ✅ Implemented |
| **DNS & Security Headers** | Edge-side IP/geo/ASN reflection + target security-header audit. | ✅ Implemented |
| **Theme / Privacy hygiene** | Class-based dark mode with persisted user preference and system fallback. | ✅ Implemented |

Future modules may add DNS leak resolution, hardware/WebGL fingerprinting, and
battery/performance-based tracking signals.

---

## Tech Stack

- **[React 19](https://react.dev/)** — component UI layer.
- **[TypeScript](https://www.typescriptlang.org/)** — strict, fully-typed code.
- **[Tailwind CSS v4](https://tailwindcss.com/)** — utility-first styling with
  class-based dark mode (via the `@tailwindcss/vite` plugin).
- **[Vite](https://vite.dev/)** — dev server + production bundler.
- **[Cloudflare Pages](https://pages.cloudflare.com/)** — static hosting &
  deployment target.
- **[Cloudflare Pages Functions](https://developers.cloudflare.com/pages/functions/)** —
  edge probe endpoint (`functions/api/probe.ts`) for IP/geo/header reflection.
- **WebRTC / STUN** — `RTCPeerConnection` against public STUN servers
  (`stun.l.google.com:19302`, `stun.cloudflare.com:3478`).

---

## Local Development Setup

### Prerequisites

- [Node.js](https://nodejs.org/) **18+** (Node 20+ recommended).
- `npm` (bundled with Node).

### 1. Install dependencies

```bash
npm install
```

> Tailwind CSS v4 is **already installed and configured** in this project — do
> **not** reinstall it manually.

### 2. Start the development server

```bash
npm run dev
```

Vite will print a local URL (usually `http://localhost:5173`). Open it in a
modern browser.

> ⚠️ **WebRTC requires a secure context.** `localhost` is treated as secure, so
> the leak scan works in local development. For remote testing you must serve
> the app over HTTPS (Cloudflare Pages does this automatically).

> ℹ️ **Network Probe needs the Pages Function.** `NetworkProbeCard` fetches
> `/api/probe`, which is served by the Pages Function in `functions/api/probe.ts`.
> It is **not** available under the plain Vite dev server. To test it locally,
> run `npx wrangler pages dev dist` (after `npm run build`) — Wrangler serves
> both the static site and the function.

### 3. Available scripts

| Command | Description |
| --- | --- |
| `npm run dev` | Start the Vite dev server with hot module reload. |
| `npm run build` | Type-check (`tsc -b`) and produce a production bundle. |
| `npm run preview` | Serve the production build locally. |
| `npm run lint` | Run ESLint over the project. |

---

## Environment & Cloudflare Deployment

SENTINEL is a static single-page application (SPA). It has **no server-side
secrets**, so there are no required environment variables. If you later add
features (e.g. an edge worker to enrich audit results), expose them via
[Cloudflare Pages environment variables](https://developers.cloudflare.com/pages/configuration/environment-variables/).

### Option A — Cloudflare Pages (Git integration, recommended)

1. Push this repository to GitHub/GitLab.
2. In the [Cloudflare dashboard](https://dash.cloudflare.com/), create a new
   **Pages** project and connect your repository.
3. Configure the build settings:
   - **Framework preset:** `Vite`
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
4. Deploy. Cloudflare serves the site over HTTPS automatically (required for
   the WebRTC leak scan).

### Option B — Wrangler CLI (direct upload)

1. Install Wrangler: `npm install -g wrangler`
2. Log in: `wrangler login`
3. Deploy the built assets:
   ```bash
   npm run build
   wrangler pages deploy dist --project-name sentinel
   ```

### Optional — Cloudflare Workers

The app can be fronted by a Cloudflare Worker for headers/edge logic. A minimal
worker simply proxies the static site; see the Cloudflare Workers docs for the
latest template.

---

## Project Structure

```
security-check/
├── index.html                 # HTML shell + pre-hydration theme script
├── package.json               # Scripts + dependencies
├── tsconfig.json              # TS project references (app + node)
├── tsconfig.app.json          # App/browser TS config (strict)
├── tsconfig.node.json         # Vite config TS config
├── vite.config.ts             # Vite + React + Tailwind v4 plugin
├── eslint.config.js           # ESLint (TS + React hooks)
├── .gitignore
├── README.md
├── public/
│   ├── favicon.svg
│   └── icons.svg
├── functions/
│   └── api/
│       └── probe.ts           # Pages Function: IP/geo/header probe
└── src/
    ├── main.tsx               # React root + StrictMode bootstrap
    ├── App.tsx                # App shell (nav + three audit cards)
    ├── index.css              # Tailwind v4 entry + class-based dark mode
    ├── hooks/
    │   ├── useTheme.ts        # Persistent dark/light mode (system fallback)
    │   ├── useWebRTCLeaks.ts  # WebRTC leak scanner (ICE/SDP parsing)
    │   ├── useFingerprint.ts  # Canvas + Web Audio fingerprinting
    │   └── useNetworkProbe.ts # Fetches /api/probe telemetry
    └── components/
        ├── TopNavBar.tsx      # Sticky nav + theme toggle button
        ├── WebRTCAuditCard.tsx     # WebRTC diagnostic panel + IP tables
        ├── FingerprintAuditCard.tsx# Canvas/Audio hash + entropy score
        └── NetworkProbeCard.tsx    # Identity/geo + security headers
```

---

## How the WebRTC scan works

1. `useWebRTCLeaks.startScan()` creates an `RTCPeerConnection` pointed at
   public STUN servers.
2. A dummy data channel is opened to trigger ICE candidate gathering (no
   microphone/camera access is requested).
3. Each `icecandidate` event is parsed — both the raw SDP candidate line (via
   regex) and the structured `address` / `relatedAddress` fields.
4. Addresses are classified into **public IPs**, **local IPs** (RFC 1918,
   loopback, link-local, CGNAT) and **mDNS `.local` hostnames**.
5. Results are deduplicated, sorted, and rendered into sharp, bordered tables.

## How the fingerprint & probe modules work

- **Fingerprinting** (`useFingerprint`) renders an off-screen 200×50 canvas and
  an offline audio graph (triangle oscillator → dynamics compressor), then
  SHA-256-hashes both payloads via Web Crypto and estimates an entropy score.
- **Network probe** (`useNetworkProbe` + `functions/api/probe.ts`) reflects the
  client IP, geo/ASN data and identifying headers from Cloudflare's edge, and
  optionally scans a target URL for missing security headers.

## Privacy & Disclaimer

SENTINEL performs **client-side-only** diagnostics. The only network traffic it
generates are standard STUN binding requests to public STUN servers. No IP
addresses or results are uploaded anywhere. Use responsibly and only on devices
you own or are authorised to test.


