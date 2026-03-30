javascript: (function () {
  console.clear();
  console.log("%c⚡ ArCHie's Miners v3", "color: orange; font-weight: bold; font-size: 1.1em;");

  // --- Shannon entropy (bits per char) — filters low-randomness false positives ---
  function entropy(str) {
    const freq = {};
    for (const c of str) freq[c] = (freq[c] || 0) + 1;
    const len = str.length;
    return Object.values(freq).reduce((s, f) => {
      const p = f / len;
      return s - p * Math.log2(p);
    }, 0);
  }

  // --- Placeholder / dummy value filter ---
  const PLACEHOLDERS = [
    "example", "placeholder", "your_", "yourkey", "yoursecret",
    "test_", "sample_", "replace", "changeme", "dummy", "fakekey",
    "xxxxxxxx", "aaaaaa", "123456", "password123", "abc123",
    "enter_", "insert_", "put_your", "my_key", "my_secret",
    "undefined", "null", "true", "false", "none", "n/a", "todo",
    "default_", "mock_", "fixture", "stub_", "XXXX",
  ];
  function isPlaceholder(val) {
    const v = val.toLowerCase();
    return PLACEHOLDERS.some((p) => v.includes(p));
  }

  // ===================================================================
  //  HIGH-CONFIDENCE — fixed-format patterns, no entropy check needed
  // ===================================================================
  const HIGH_CONF = [
    { name: "AWS Access Key",       pattern: /AKIA[0-9A-Z]{16}/g },
    { name: "AWS Secret",           pattern: /(aws_secret_access_key|aws_access_key_id)[\s:=]{1,3}["'`]?([a-zA-Z0-9/+]{40})["'`]?/gi },
    { name: "Stripe Live SK",       pattern: /sk_live_[0-9a-zA-Z]{24,99}/g },
    { name: "Stripe Live PK",       pattern: /pk_live_[0-9a-zA-Z]{24,99}/g },
    { name: "Google API Key",       pattern: /AIza[0-9A-Za-z\-_]{35}/g },
    { name: "GitHub Token",         pattern: /gh[pousr]_[A-Za-z0-9_]{36,255}/g },
    { name: "GitHub Fine-Grained",  pattern: /github_pat_[A-Za-z0-9_]{22,255}/g },
    { name: "Slack Token",          pattern: /xox[baprs]-[0-9A-Za-z\-]{10,48}/g },
    { name: "Slack Webhook",        pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[a-zA-Z0-9]{24}/g },
    { name: "Twilio SID",           pattern: /AC[a-f0-9]{32}/g },
    { name: "SendGrid Key",         pattern: /SG\.[a-zA-Z0-9_\-]{22,}\.[a-zA-Z0-9_\-]{22,}/g },
    { name: "Mailgun Key",          pattern: /key-[0-9a-zA-Z]{32}/g },
    { name: "Firebase Cloud Msg",   pattern: /AAAA[a-zA-Z0-9_\-]{7,}:[a-zA-Z0-9_\-]{140,}/g },
    { name: "Square Access Token",  pattern: /sq0atp-[0-9A-Za-z\-_]{22}/g },
    { name: "Square OAuth Secret",  pattern: /sq0csp-[0-9A-Za-z\-_]{43}/g },
    { name: "Shopify Access Token", pattern: /shpat_[a-fA-F0-9]{32}/g },
    { name: "Shopify Shared Secret",pattern: /shpss_[a-fA-F0-9]{32}/g },
    { name: "Heroku API Key",       pattern: /heroku[_\s:="']{1,5}[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/gi },
    { name: "JWT",                  pattern: /eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}/g, validate: function(v) { try { const h = JSON.parse(atob(v.split(".")[0].replace(/-/g,"+").replace(/_/g,"/"))); return !!(h.alg || h.typ); } catch(e) { return false; } } },
    { name: "Bearer Token",         pattern: /Authorization[\s:=]+["'`]?(Bearer\s[a-zA-Z0-9_\-\.]{30,})["'`]?/gi },
    { name: "Private Key",          pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  ];

  // ===================================================================
  //  LOW-CONFIDENCE — entropy + placeholder check required
  // ===================================================================
  const LOW_CONF = [
    {
      name: "Generic Secret",
      pattern:
        /(api_key|apikey|api_secret|secret_key|secret|token|auth_token|access_token|client_secret|app_secret|private_key|encryption_key|password|passwd|pwd)[\s:=]{1,3}["'`]([a-zA-Z0-9_\-\.\/+]{16,})["'`]/gi,
      captureGroup: 2,
      minEntropy: 3.5,
    },
  ];

  // --- Informational: env variable references ---
  const ENV_PATTERN = /(?:process\.env|import\.meta\.env)\.([a-zA-Z0-9_]+)/g;

  // --- URL / path extraction pattern ---
  const URL_PATTERN =
    /(?:"|'|`)(((?:[a-zA-Z]{1,10}:\/\/|\/)[^"'/]{1,}\/[a-zA-Z0-9_.\-/?=&%#]+)|((?:\/|\.\.\/)[a-zA-Z0-9_.\-]+\.[a-z]{2,4}))(?:"|'|`)/gi;

  const DATA = {
    jsFiles: new Set(),
    endpoints: new Set(),
    assets: new Set(),
    secrets: new Set(),
    envRefs: new Set(),
    errors: [],
  };

  const seenUrls = new Set();

  function scanContent(code, source, fullUrl) {
    if (!code) return;

    // --- URL / endpoint extraction ---
    let m;
    for (URL_PATTERN.lastIndex = 0; null !== (m = URL_PATTERN.exec(code)); ) {
      let a = m[1];
      if (
        a.length > 200 || a.length < 4 ||
        /[ <>{}[\]()|^\\*$;]/.test(a) ||
        a.startsWith("//") || a.startsWith("@") ||
        a.includes("node_modules") ||
        /^(application|text|image|audio|video|font|multipart|model|x-|vnd\.)\//i.test(a) ||
        /^[\d.\/\-]+$/.test(a) ||
        /^\d{1,4}[\/\-]\d{1,2}[\/\-]\d{1,4}/.test(a) ||
        /^data:/i.test(a) || /^blob:/i.test(a) ||
        /webpack/i.test(a) || /\.hot-update\./i.test(a)
      ) continue;

      const norm = a.replace(/[?#].*$/, "").replace(/\/+$/, "").toLowerCase();
      if (seenUrls.has(norm)) continue;
      seenUrls.add(norm);

      if (/\.(js|jsx|ts|tsx|vue|mjs)$/i.test(a)) {
        if (a.startsWith("/")) a = window.location.origin + a;
        DATA.jsFiles.add(a);
        continue;
      }
      if (a.startsWith("/")) a = window.location.origin + a;
      if (/\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ttf|eot|ico|mp4|mp3|webm|webp|avif|pdf|xml|json|map)$/i.test(a)) {
        DATA.assets.add(JSON.stringify({ url: a, source }));
      } else {
        DATA.endpoints.add(JSON.stringify({ url: a, source }));
      }
    }

    // --- High-confidence secrets ---
    for (const def of HIGH_CONF) {
      def.pattern.lastIndex = 0;
      let t;
      while (null !== (t = def.pattern.exec(code))) {
        const val = t[2] || t[1] || t[0];
        if (isPlaceholder(val)) continue;
        if (def.validate && !def.validate(val)) continue;
        DATA.secrets.add(JSON.stringify({
          type: def.name, content: val, confidence: "HIGH", source, fullUrl,
        }));
      }
    }

    // --- Low-confidence secrets (entropy + placeholder filtered) ---
    for (const def of LOW_CONF) {
      def.pattern.lastIndex = 0;
      let t;
      while (null !== (t = def.pattern.exec(code))) {
        const val = t[def.captureGroup] || t[0];
        if (isPlaceholder(val)) continue;
        if (/^[a-f0-9]+$/i.test(val) && val.length < 32) continue;
        const ent = entropy(val);
        if (ent < def.minEntropy) continue;
        DATA.secrets.add(JSON.stringify({
          type: def.name,
          content: val,
          confidence: ent >= 4.0 ? "HIGH" : "LOW",
          source,
          fullUrl,
        }));
      }
    }

    // --- Env references ---
    ENV_PATTERN.lastIndex = 0;
    let e;
    while (null !== (e = ENV_PATTERN.exec(code))) {
      DATA.envRefs.add(e[1]);
    }
  }

  // --- Collect scripts from DOM ---
  document.querySelectorAll("script[src]").forEach((el) => el.src && DATA.jsFiles.add(el.src));
  document.querySelectorAll("script:not([src])").forEach((el) =>
    scanContent(el.innerText, "Inline Script", window.location.href)
  );

  console.log(`[+] Found ${DATA.jsFiles.size} external scripts. Fetching...`);

  // Open report window NOW (synchronous = user-gesture context, avoids popup blocker)
  const reportWin = window.open('', '_blank');
  if (reportWin) {
    reportWin.document.write('<html><head><title>JS Miner — Loading...</title></head><body style="background:#111;color:#ddd;font-family:monospace;padding:40px;text-align:center"><h2 style="color:orange">⚡ ArCHie\'s Miners v3</h2><p>Scanning scripts... please wait.</p></body></html>');
  }

  const initialJs = new Set(DATA.jsFiles);
  const fetchOne = (url) => fetch(url).then(r => r.text()).then(code => scanContent(code, url.split("/").pop(), url)).catch(() => DATA.errors.push(url));

  Promise.all(Array.from(initialJs).map(fetchOne)).then(() => {
    // --- 2nd pass: fetch JS files discovered inside external scripts ---
    const newJs = Array.from(DATA.jsFiles).filter(u => !initialJs.has(u));
    if (newJs.length) console.log(`[+] Pass 2: ${newJs.length} new scripts discovered.`);
    return Promise.all(newJs.map(fetchOne));
  }).then(() => {
    const secrets   = Array.from(DATA.secrets).map(JSON.parse);
    const endpoints = Array.from(DATA.endpoints).map(JSON.parse);
    const assets    = Array.from(DATA.assets).map(JSON.parse);
    const scripts   = Array.from(DATA.jsFiles);
    const envRefs   = Array.from(DATA.envRefs);

    secrets.sort((a, b) => (a.confidence === "HIGH" ? -1 : 1));

    const rawJSON = JSON.stringify({
      target: window.location.hostname,
      timestamp: new Date().toISOString(),
      secrets, endpoints, assets, scripts, envRefs,
    }, null, 2);

    const highCount = secrets.filter(s => s.confidence === "HIGH").length;

    const secretRows = secrets.map((s) => {
      const enc = encodeURIComponent(s.content);
      const link = s.fullUrl ? `${s.fullUrl}#:~:text=${enc}` : "#";
      const isHigh = s.confidence === "HIGH";
      const tagBg = isHigh ? "#c0392b" : "#e67e22";
      return `<tr style="${isHigh ? "" : "opacity:0.8;"}">
        <td><span class="tag" style="background:${tagBg};color:white">${s.type}</span></td>
        <td style="color:${isHigh ? "#e74c3c" : "#e67e22"};font-weight:bold;word-break:break-all;">${s.content}</td>
        <td><span class="badge" style="background:${tagBg};color:white;">${s.confidence}</span></td>
        <td><a href="${link}" target="_blank" class="btn-link">↗ Highlight</a></td>
        <td class="source">${s.source}</td></tr>`;
    }).join("");

    const envRows = envRefs.map((name) =>
      `<tr><td style="color:#9b59b6;font-family:monospace;">process.env.${name}</td></tr>`
    ).join("");

    const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>JS Miner — ${window.location.hostname}</title>
<style>
body{background:#111;color:#ddd;font-family:'Segoe UI',monospace;padding:20px}
h2{border-bottom:2px solid #e67e22;padding-bottom:5px;color:#e67e22;margin-top:30px}
.stats{font-size:0.9em;color:#888;margin-bottom:10px}
.summary{display:flex;gap:15px;flex-wrap:wrap;margin:15px 0}
.summary-card{background:#222;border:1px solid #444;border-radius:6px;padding:12px 18px;text-align:center}
.summary-card .num{font-size:1.6em;font-weight:bold}
.summary-card .lbl{font-size:0.75em;color:#888;margin-top:2px}
.box{background:#222;padding:15px;border-radius:5px;margin-bottom:20px;border:1px solid #444}
textarea{width:100%;height:150px;background:#000;color:#2ecc71;border:1px solid #444;padding:10px;font-family:monospace;font-size:11px}
table{width:100%;border-collapse:collapse;margin-top:10px;background:#222}
th,td{padding:10px;border:1px solid #444;text-align:left;font-size:0.9em;word-break:break-all}
th{background:#333;color:#fff}
tr:hover{background:#2a2a2a}
.tag,.badge{padding:2px 6px;border-radius:4px;font-weight:bold;font-size:0.8em}
.source{color:#888;font-size:0.85em;font-style:italic}
.btn-link{font-size:0.8em;text-decoration:none;background:#333;color:#fff;padding:2px 5px;border-radius:3px}
</style></head><body>
<h1>⚡ ArCHie's Miners v3</h1>
<div class="stats">Target: <strong>${window.location.hostname}</strong> &nbsp;|&nbsp; ${new Date().toISOString()}${DATA.errors.length ? ` &nbsp;|&nbsp; <span style="color:#e74c3c;">${DATA.errors.length} fetch errors</span>` : ""}</div>
<div class="summary">
  <div class="summary-card"><div class="num" style="color:#e74c3c">${highCount}</div><div class="lbl">HIGH Secrets</div></div>
  <div class="summary-card"><div class="num" style="color:#e67e22">${secrets.length - highCount}</div><div class="lbl">LOW Secrets</div></div>
  <div class="summary-card"><div class="num" style="color:#2ecc71">${endpoints.length}</div><div class="lbl">Endpoints</div></div>
  <div class="summary-card"><div class="num" style="color:#f1c40f">${scripts.length}</div><div class="lbl">JS Files</div></div>
  <div class="summary-card"><div class="num" style="color:#3498db">${assets.length}</div><div class="lbl">Assets</div></div>
  <div class="summary-card"><div class="num" style="color:#9b59b6">${envRefs.length}</div><div class="lbl">ENV Refs</div></div>
</div>
<div class="box"><h3>📄 Raw JSON</h3><textarea id="jsonArea">${rawJSON}</textarea></div>

<h2>🔐 Secrets (${secrets.length}) <span style="font-size:0.7em;color:#888;">— HIGH = red, LOW = orange (verify manually)</span></h2>
<table><thead><tr><th>Type</th><th>Value</th><th>Confidence</th><th>Action</th><th>Source</th></tr></thead>
<tbody>${secretRows || '<tr><td colspan="5" style="color:#27ae60;">No secrets found.</td></tr>'}</tbody></table>

<h2>🌿 ENV References (${envRefs.length}) <span style="font-size:0.7em;color:#888;">— variable names only, not values</span></h2>
<table><thead><tr><th>Reference</th></tr></thead>
<tbody>${envRows || '<tr><td style="color:#27ae60;">None found.</td></tr>'}</tbody></table>

<h2>🔗 Endpoints (${endpoints.length})</h2>
<table><thead><tr><th>URL/Path</th><th>Found In</th></tr></thead>
<tbody>${endpoints.map((e) => `<tr><td><a href="${e.url}" target="_blank" style="color:#2ecc71;text-decoration:none;">${e.url}</a></td><td class="source">${e.source}</td></tr>`).join("") || '<tr><td colspan="2" style="color:#888;">None found.</td></tr>'}</tbody></table>

<h2>📜 JS Files (${scripts.length})</h2>
<table><thead><tr><th>File URL</th></tr></thead>
<tbody>${scripts.map((u) => `<tr><td><a href="${u}" target="_blank" style="color:#f1c40f;">${u}</a></td></tr>`).join("")}</tbody></table>

<h2>🖼️ Static Assets (${assets.length})</h2>
<table><thead><tr><th>Asset URL</th><th>Found In</th></tr></thead>
<tbody>${assets.map((a) => `<tr><td><a href="${a.url}" target="_blank" style="color:#3498db;">${a.url}</a></td><td class="source">${a.source}</td></tr>`).join("") || '<tr><td colspan="2" style="color:#888;">None found.</td></tr>'}</tbody></table>

<script>const ta=document.getElementById("jsonArea");ta.focus();ta.select();<\/script>
</body></html>`;

    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const blobUrl = URL.createObjectURL(blob);
    if (reportWin) {
      try {
        reportWin.document.open();
        reportWin.document.write(html);
        reportWin.document.close();
      } catch(e) {
        // CSP blocked document.write — fall back to blob URL navigation
        reportWin.location.href = blobUrl;
      }
    } else {
      // Popup was blocked — copy JSON to clipboard as fallback
      navigator.clipboard.writeText(rawJSON).then(() => {
        console.log("%c[!] Popup blocked — JSON copied to clipboard!", "color:#e74c3c;font-weight:bold;");
        alert("⚠️ Popup blocked! Results JSON copied to clipboard. Paste in a text editor.");
      }).catch(() => {
        console.log("%c[!] Popup blocked. Raw JSON below:", "color:#e74c3c;font-weight:bold;");
        console.log(rawJSON);
        alert("⚠️ Popup blocked! Check the browser console (F12) for results.");
      });
    }
  });
})();
