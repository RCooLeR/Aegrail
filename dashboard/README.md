# Aegrail Dashboard

TypeScript, React, and Bootstrap dashboard for the Hub HTTP APIs.

## Development

```powershell
cd dashboard
npm install
npm run dev
```

Open `http://127.0.0.1:5173/dashboard/`. During development, Vite proxies `/api` and `/healthz` to `http://127.0.0.1:8787`.

## Build

```powershell
npm run build
cd ..\app
go run ./cmd/aegrail hub serve --dashboard-dir ..\dashboard\dist
```

The built dashboard is served under `/dashboard/` when `--dashboard-dir` points at the build output.

Use Settings to choose a Hub inventory scope. The picker is populated from `GET /api/v1/inventory/scopes` and only includes organization, project, environment, and app records.
