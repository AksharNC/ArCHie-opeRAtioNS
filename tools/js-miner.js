javascript: (function () {
  console.clear();
  console.log("%c⚡ ArCHie's Miners", "color: orange;font-weight:bold;");
  const e = [
      { name: "AWS API Key", pattern: /AKIA[0-9A-Z]{16}/g },
      {
        name: "AWS Secret",
        pattern:
          /(aws_secret_access_key|aws_access_key_id)[\s:=]{1,3}["'`]?([a-zA-Z0-9/+]{40})["'`]?/gi,
      },
      { name: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24}/g },
      { name: "Google API", pattern: /AIza[0-9A-Za-z-_]{35}/g },
      {
        name: "Generic Secret",
        pattern:
          /(api_key|apikey|secret|token|auth_token|access_token|password|pwd)[\s:=]{1,3}["'`] ?([a-zA-Z0-9_\-\.]{10,})["'`]/gi,
      },
      {
        name: "Bearer Token",
        pattern:
          /Authorization[\s:=]+["'`]?(Bearer\s[a-zA-Z0-9_\-\.]{30,})["'`]?/gi,
      },
      { name: "Node Env", pattern: /process\.env\.([a-zA-Z0-9_]+)/g },
    ],
    t =
      /(?:"|'|`)(((?:[a-zA-Z]{1,10}:\/\/|\/)[^"'/]{1,}\/[a-zA-Z0-9_.\-/?=&%]+)|((?:\/|\.\.\/)[a-zA-Z0-9_.\-]+\.[a-z]{2,4}))(?:"|'|`)/gi,
    n = {
      jsFiles: new Set(),
      endpoints: new Set(),
      assets: new Set(),
      secrets: new Set(),
      errors: [],
    };
  function r(o, s, l) {
    if (!o) return;
    let c;
    for (t.lastIndex = 0; null !== (c = t.exec(o)); ) {
      let a = c[1];
      if (
        a.length > 200 ||
        a.length < 4 ||
        a.includes(" ") ||
        a.includes("<") ||
        a.includes(">") ||
        a.includes("{") ||
        a.includes("}") ||
        a.includes("[") ||
        a.includes("]") ||
        a.includes("(") ||
        a.includes(")") ||
        a.includes("|") ||
        a.includes("^") ||
        a.includes("\\") ||
        a.includes("*") ||
        a.includes("$") ||
        a.includes(";") ||
        a.startsWith("//") ||
        a.startsWith("@") ||
        a.includes("node_modules") ||
        a.match(
          /^(application|text|image|audio|video|font|multipart|model|x-|vnd\.)\//i
        ) ||
        a.match(/^[\d\.\/\-]+$/) ||
        a.match(/^\d{1,4}[\/\-]\d{1,2}[\/\-]\d{1,4}/)
      )
        continue;
      if (a.match(/\.(js|jsx|ts|tsx|map|vue)$/i)) {
        a.startsWith("/") && (a = window.location.origin + a), n.jsFiles.add(a);
        continue;
      }
      a.match(
        /\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ttf|eot|ico|mp4|mp3|webm|pdf|xml|json)$/i
      )
        ? (a.startsWith("/") && (a = window.location.origin + a),
          n.assets.add(JSON.stringify({ url: a, source: s })))
        : (a.startsWith("/") && (a = window.location.origin + a),
          n.endpoints.add(JSON.stringify({ url: a, source: s })));
    }
    e.forEach((e) => {
      e.pattern.lastIndex = 0;
      let t;
      for (; null !== (t = e.pattern.exec(o)); ) {
        let c = t[2] || t[0];
        n.secrets.add(
          JSON.stringify({ type: e.name, content: c, source: s, fullUrl: l })
        );
      }
    });
  }
  document
    .querySelectorAll("script[src]")
    .forEach((e) => e.src && n.jsFiles.add(e.src)),
    document
      .querySelectorAll("script:not([src])")
      .forEach((e) =>
        r(e.innerText, "Inline Source Code", window.location.href)
      ),
    console.log(`[+] Found ${n.jsFiles.size} external scripts. Fetching...`);
  const o = Array.from(n.jsFiles).map((e) =>
    fetch(e)
      .then((e) => e.text())
      .then((t) => r(t, e.split("/").pop(), e))
      .catch((t) => n.errors.push(e))
  );
  Promise.all(o).then(() => {
    const e = Array.from(n.secrets).map(JSON.parse),
      t = Array.from(n.endpoints).map(JSON.parse),
      o = Array.from(n.assets).map(JSON.parse),
      s = Array.from(n.jsFiles),
      l = JSON.stringify(
        {
          target: window.location.hostname,
          timestamp: new Date().toISOString(),
          secrets: e,
          endpoints: t,
          assets: o,
          scripts: s,
        },
        null,
        2
      ),
      c = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>JS Miner - ${
        window.location.hostname
      }</title><style>body{background:#111;color:#ddd;font-family:'Segoe UI',monospace;padding:20px}h2{border-bottom:2px solid #e67e22;padding-bottom:5px;color:#e67e22;margin-top:30px}.stats{font-size:0.9em;color:#888}.box{background:#222;padding:15px;border-radius:5px;margin-bottom:20px;border:1px solid #444}textarea{width:100%;height:150px;background:#000;color:#2ecc71;border:1px solid #444;padding:10px;font-family:monospace;font-size:11px}table{width:100%;border-collapse:collapse;margin-top:10px;background:#222}th,td{padding:10px;border:1px solid #444;text-align:left;font-size:0.9em;word-break:break-all}th{background:#333;color:#fff}tr:hover{background:#2a2a2a}.tag{padding:2px 6px;border-radius:4px;font-weight:bold;font-size:0.8em}.tag-secret{background:#c0392b;color:white}.source{color:#888;font-size:0.85em;font-style:italic}a.secret-link{color:#e74c3c;text-decoration:none;border-bottom:1px dotted #e74c3c;font-weight:bold}a.secret-link:hover{background:#e74c3c;color:white}.btn-link{font-size:0.8em;text-decoration:none;background:#333;color:#fff;padding:2px 5px;border-radius:3px;margin-left:5px}</style></head><body><h1>ArCHie's Miners</h1><div class="stats">Target: ${
        window.location.hostname
      }</div><div class="box"><h3>📄 Raw JSON</h3><textarea id="jsonArea">${l}</textarea></div><h2>🔐 Secrets (${
        e.length
      })</h2><table><thead><tr><th>Type</th><th>Content</th><th>Action</th><th>Source File</th></tr></thead><tbody>${e
        .map((e) => {
          const t = encodeURIComponent(e.content);
          const n = e.fullUrl ? `${e.fullUrl}#:~:text=${t}` : "#";
          return `<tr><td><span class="tag tag-secret">${e.type}</span></td><td style="color:#e74c3c; font-weight:bold;">${e.content}</td><td><a href="${n}" target="_blank" class="btn-link">↗ Open & Highlight</a></td><td class="source">${e.source}</td></tr>`;
        })
        .join("")}</tbody></table><h2>🔗 Endpoints (${
        t.length
      })</h2><table><thead><tr><th>URL/Path</th><th>Found In</th></tr></thead><tbody>${t
        .map(
          (e) =>
            `<tr><td><a href="${e.url}" target="_blank" style="color:#2ecc71; text-decoration:none;">${e.url}</a></td><td class="source">${e.source}</td></tr>`
        )
        .join("")}</tbody></table><h2>📜 JS Files (${
        s.length
      })</h2><table><thead><tr><th>File URL</th></tr></thead><tbody>${s
        .map(
          (e) =>
            `<tr><td><a href="${e}" target="_blank" style="color:#f1c40f;">${e}</a></td></tr>`
        )
        .join("")}</tbody></table><h2>🖼️ Static Assets (${
        o.length
      })</h2><table><thead><tr><th>Asset URL</th><th>Found In</th></tr></thead><tbody>${o
        .map(
          (e) =>
            `<tr><td><a href="${e.url}" target="_blank" style="color:#3498db;">${e.url}</a></td><td class="source">${e.source}</td></tr>`
        )
        .join(
          ""
        )}</tbody></table><script>const ta=document.getElementById("jsonArea");ta.focus(),ta.select();<\/script></body></html>`,
      i = new Blob([c], { type: "text/html;charset=utf-8" }),
      a = URL.createObjectURL(i),
      u = window.open(a, "_blank");
    u || alert("⚠️ Popup Blocked! Please allow popups.");
  });
})();
