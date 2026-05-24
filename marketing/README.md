# Aegrail Marketing Site

Static pages for `aegrail.com`. This folder is the public marketing and lightweight docs site for Aegrail: what it does, how the Hub and agents fit together, what data is collected, and how to deploy the system.

## Stack

- Static HTML
- Bootstrap 5.3.6 bundled locally in `assets/vendor/bootstrap/`
- Custom Aegrail CSS in `assets/css/aegrail-docs.css`
- Small vanilla JS search helper in `assets/js/aegrail-docs.js`
- Aegrail PNG logo/icon/favicon assets from the dashboard brand set
- No build step
- No CDN dependency for Bootstrap
- Google Fonts are referenced from the pages

## Structure

```text
.
|-- index.html
|-- 404.html
|-- robots.txt
|-- sitemap.xml
|-- site.webmanifest
|-- assets/
|   |-- css/aegrail-docs.css
|   |-- js/aegrail-docs.js
|   |-- vendor/bootstrap/bootstrap.min.css
|   |-- vendor/bootstrap/bootstrap.bundle.min.js
|   |-- img/*.svg
|   `-- favicon/*
`-- docs/
    |-- getting-started.html
    |-- installation.html
    |-- configuration.html
    |-- cli-reference.html
    |-- agents-and-collectors.html
    |-- evidence-model.html
    |-- incident-timeline.html
    |-- reports.html
    `-- deployment.html
```

## Local preview

Any static file server works:

```bash
cd marketing
python3 -m http.server 8080
```

Open `http://localhost:8080`.

## Deploy to Nginx

```bash
rsync -av ./marketing/ user@server:/var/www/aegrail.com/
```

Minimal server block:

```nginx
server {
  listen 443 ssl http2;
  server_name aegrail.com www.aegrail.com;
  root /var/www/aegrail.com;
  index index.html;

  location / {
    try_files $uri $uri/ /404.html;
  }
}
```

## Content scope

The site intentionally stays practical and short. It explains:

- Hub and Agent roles
- company, site, environment, app, service, and node inventory
- what collectors watch for WordPress, PrestaShop, Mautic, Laravel, Yii2 RBAC, static, React, and Node.js profiles
- encrypted agent ingest and local redaction
- initial safe-state workflow, ignores, deployments, issue details, LLM analysis, and reports
- production deployment split across `aegrail.com`, `dash.aegrail.com`, and `api.aegrail.com`
