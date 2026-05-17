# Dashboard Install

## Prerequisites

- Node.js/npm compatible with the dashboard package.
- A running Hub for API calls.

## Development Server

```powershell
cd dashboard
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173/dashboard/
```

Vite proxies `/api` and `/healthz` to:

```text
http://127.0.0.1:8787
```

## Build

```powershell
cd dashboard
npm run build
```

Serve the built dashboard from the Hub:

```powershell
cd ..\hub
go run ./cmd/hub serve --dashboard-dir ..\dashboard\dist
```

## Verification

```powershell
cd dashboard
npm run build
```
