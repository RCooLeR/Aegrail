# Aegrail Dashboard

React and TypeScript dashboard for the Hub HTTP APIs.

The dashboard should stay operator-focused: show company/site/node health, active issues, evidence, and simple triage actions. Detection logic belongs in the Hub, not in browser code.

Development:

```powershell
npm install
npm run dev
```

Open `http://127.0.0.1:5173/dashboard/`. Vite proxies `/api` and `/healthz` to `http://127.0.0.1:8787`.

Build and serve from the Hub:

```powershell
npm run build
cd ..\app
go run ./cmd/aegrail hub serve --dashboard-dir ..\dashboard\dist
```

Current app structure:

```text
src/App.tsx                  composition root
src/dashboard/controllers/   data loading and actions
src/dashboard/model/         view models and sorting
src/dashboard/pages/         dashboard pages
src/dashboard/components/    shared UI pieces
src/dashboard/utils/         formatting, reports, metadata helpers
```

See [../docs/README.md](../docs/README.md) for dashboard behavior and tracker status.
