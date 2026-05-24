const AEGRAIL_SEARCH_INDEX = [
  {
    title: "Getting started",
    url: "docs/getting-started.html",
    section: "First run",
    text: "Hub Agent first owner user 2FA TOTP inventory company site environment app service node generated config app slug matches Hub inventory paths URLs database DSN environment variables logs run once continuous initial safe state baseline first scan known good findings collector status files database logs browser config"
  },
  {
    title: "Installation",
    url: "docs/installation.html",
    section: "Install",
    text: "Docker Hub PostgreSQL Redis queues notifications rate limits migrations aegrail-hub db migrate serve AEGRAIL_HTTP_ADDR AEGRAIL_DATABASE_URL AEGRAIL_REDIS_URL user secret wire private key agent read access site root config files logs state directory database credentials environment variables browser rendering Chrome optional NAS server rendered false AEGRAIL_BROWSER_CHROME_PATH"
  },
  {
    title: "Configuration",
    url: "docs/configuration.html",
    section: "Agent YAML",
    text: "agent yaml identity org project environment host agent_id site slug kind app service root app value must match Hub app slug files profiles excludes coverage browser crawl rendered database dsn_env profile wordpress prestashop mautic laravel yii2 static react nodejs table prefix schedule secrets DSN password API keys cookies tokens ignore paths disabled collectors"
  },
  {
    title: "Command reference",
    url: "docs/cli-reference.html",
    section: "Commands",
    text: "aegrail-hub serve db migrate version aegrail-agent run config once validate docker compose profile tools hub migrate logs debug 404 ingest identity mismatch Hub inventory browser rendered crawl Chrome unavailable pending queue files Hub rejected event"
  },
  {
    title: "Agents and collectors",
    url: "docs/agents-and-collectors.html",
    section: "Collectors",
    text: "agent model node collectors file database logs browser config files collector hashes ctime mtime size path metadata caches uploads backups queue large files module plugin grouping database profiles WordPress users roles active plugins siteurl home admin email registration default role PrestaShop employees modules Mautic Laravel Yii2 RBAC static React Node.js access logs admin login password reset Tor IP static assets email redirects rendered crawl scripts headers icons links Nginx Apache config coverage"
  },
  {
    title: "Evidence model",
    url: "docs/evidence-model.html",
    section: "Security model",
    text: "signals findings evidence model wire protocol encrypted agent ingest node public key private key X25519 HKDF AES-256-GCM associated data timestamp replay checks JSON redaction API keys authorization headers cookies passwords tokens sessions DSNs credential assignments file metadata hashes no file contents LLM evidence bundles timestamps filesystem database baseline local queue sent retention failed pending PostgreSQL storage"
  },
  {
    title: "Dashboard workflow",
    url: "docs/incident-timeline.html",
    section: "Dashboard",
    text: "overview company cards sorted severity sites nodes agent status open issues company site node drilldown collector health missing collectors issue detail page overview evidence timeline comments related issues LLM analysis mark safe ignore path rule cache uploads generated logs deployment release window report signals readable event log badges row backgrounds site favicons filters"
  },
  {
    title: "Reports",
    url: "docs/reports.html",
    section: "Reports",
    text: "reports LLM analysis deterministic findings rules correlation source of truth issue type application profile WordPress admin login PrestaShop module change Mautic user Laravel auth Yii2 RBAC prompt formatted HTML escaped rendering advisory output executive summary affected company site environment app service node timeline linked signals evidence table hashes timestamps paths users IPs redacted metadata comments ignored paths deployments notifications email SMTP browser notifications"
  },
  {
    title: "Deployment",
    url: "docs/deployment.html",
    section: "Production",
    text: "production deployment aegrail.com static marketing docs dash.aegrail.com dashboard authenticated password TOTP api.aegrail.com Hub API encrypted agent ingest PostgreSQL Redis Ollama optional SMTP email browser notifications reverse proxy HTTPS Nginx Caddy Traefik trusted proxy CIDRs Host X-Forwarded-Proto Docker systemd agents read only mounts site roots logs config files state queue"
  }
];

function normalizePath(url) {
  const base = document.body.dataset.basePath || "";
  if (base === "docs") return url.replace(/^docs\//, "");
  return url;
}

function escapeHTML(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  })[char]);
}

function tokenize(query) {
  return query
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

function scoreItem(item, terms) {
  const title = item.title.toLowerCase();
  const section = item.section.toLowerCase();
  const text = item.text.toLowerCase();
  let score = 0;

  for (const term of terms) {
    if (title.includes(term)) score += 12;
    if (section.includes(term)) score += 5;
    if (text.includes(term)) score += 2;
    if (!title.includes(term) && !section.includes(term) && !text.includes(term)) return 0;
  }

  return score;
}

function excerptFor(item, terms) {
  const text = item.text.replace(/\s+/g, " ").trim();
  const lower = text.toLowerCase();
  const firstHit = terms
    .map(term => lower.indexOf(term))
    .filter(index => index >= 0)
    .sort((a, b) => a - b)[0] ?? 0;
  const start = Math.max(0, firstHit - 44);
  const end = Math.min(text.length, firstHit + 118);
  const prefix = start > 0 ? "..." : "";
  const suffix = end < text.length ? "..." : "";
  return `${prefix}${text.slice(start, end)}${suffix}`;
}

function searchDocs(query) {
  const terms = tokenize(query);
  if (!terms.length) return [];
  return AEGRAIL_SEARCH_INDEX
    .map(item => ({ item, score: scoreItem(item, terms) }))
    .filter(result => result.score > 0)
    .sort((a, b) => b.score - a.score || a.item.title.localeCompare(b.item.title))
    .slice(0, 8);
}

function initSearch() {
  const input = document.querySelector("#docsSearch");
  const box = document.querySelector("#docsSearchResults");
  if (!input || !box) return;

  input.addEventListener("input", () => {
    const q = input.value.trim();
    if (!q) {
      box.style.display = "none";
      box.innerHTML = "";
      return;
    }

    const terms = tokenize(q);
    const results = searchDocs(q);
    if (!results.length) {
      box.innerHTML = `<div class="p-3 text-soft">No docs matched "${escapeHTML(q)}".</div>`;
      box.style.display = "block";
      return;
    }

    box.innerHTML = results
      .map(({ item }) => {
        const href = normalizePath(item.url);
        const excerpt = excerptFor(item, terms);
        return `<a href="${href}"><strong>${escapeHTML(item.title)}</strong><small>${escapeHTML(item.section)} - ${escapeHTML(excerpt)}</small></a>`;
      })
      .join("");
    box.style.display = "block";
  });

  input.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    const first = box.querySelector("a");
    if (first) {
      event.preventDefault();
      first.click();
    }
  });

  document.addEventListener("click", (event) => {
    if (!event.target.closest(".search-box")) box.style.display = "none";
  });
}

function markActiveNav() {
  const current = location.pathname.split("/").pop() || "index.html";
  document.querySelectorAll("[data-doc-link]").forEach(link => {
    const href = link.getAttribute("href") || "";
    if (href.endsWith(current)) link.classList.add("active");
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initSearch();
  markActiveNav();
});
