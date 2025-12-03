// tools/js-miner.js
(function() {
    console.log("⚡ CyberOps Miner: JS Recon Active");

    // 1. RECON LOGIC (Secrets & Endpoints)
    const findings = [];

    function findSecrets(code) {
        const secretPatterns = [
            // ADDED: node_env, nodejs, node to the regex group below
            /(api_key|secret|token|password|cred|auth|db_conn|private_key|aws_access_key_id|aws_secret_access_key|node_env|nodejs|node)[^=\s"']{0,20}[=\s"']{1,3}[^=\s"']{1,50}/gi,
            /sk_[a-zA-Z0-9_]{24}/g,
            /AKIA[0-9A-Z]{16}/g,
            /[a-f0-9]{32}/gi,
            /[a-f0-9]{40}/gi 
        ];
        secretPatterns.forEach(pattern => {
            let match;
            while ((match = pattern.exec(code)) !== null) {
                // Formatting the output
                findings.push({ type: "🔑 Secret", content: match[0].substring(0, 100) + (match[0].length > 100 ? "..." : "") });
            }
        });
    }

    function findEndpoints(code) {
        const urlPattern = /(https?:\/\/[^\s"'<>]+)|(\/[^\s"'<>]+\.[a-zA-Z0-9]{2,4}\b)/g;
        let match;
        while ((match = urlPattern.exec(code)) !== null) {
            findings.push({ type: "🔗 Endpoint", content: match[0] });
        }
    }

    // Process Inline Scripts
    document.querySelectorAll('script:not([src])').forEach(script => {
        const code = script.textContent;
        findSecrets(code);
        findEndpoints(code);
    });

    // Process External Scripts
    const scriptPromises = [];
    document.querySelectorAll('script[src]').forEach(script => {
        if (script.src) {
            scriptPromises.push(
                fetch(script.src)
                    .then(r => r.text())
                    .then(code => { findSecrets(code); findEndpoints(code); })
                    .catch(e => console.error(`Failed to fetch ${script.src}`, e))
            );
        }
    });

    // 2. GENERATE UI (After scanning finishes)
    Promise.all(scriptPromises).then(() => {
        // Deduplicate findings
        const uniqueFindings = findings.filter((v,i,a)=>a.findIndex(t=>(t.content===v.content))===i);

        if (uniqueFindings.length === 0) {
            alert("CyberOps Miner: No secrets or endpoints found in JS files.");
            return;
        }

        const htmlContent = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>JS Recon Report - ${document.title}</title>
                <style>
                    body { font-family: 'Consolas', 'Monaco', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
                    h2 { color: #3fb950; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
                    .stats { font-size: 0.9em; color: #8b949e; margin-bottom: 20px; }
                    table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #161b22; }
                    th { text-align: left; background: #21262d; padding: 10px; border: 1px solid #30363d; color: #fff; }
                    td { padding: 8px; border: 1px solid #30363d; font-size: 0.85em; word-break: break-all; }
                    tr:hover { background: #1c2128; }
                    .secret { color: #ff7b72; font-weight: bold; } /* Red for secrets */
                    .endpoint { color: #58a6ff; } /* Blue for URLs */
                    .btn { 
                        background: #238636; color: white; border: none; padding: 8px 16px; 
                        cursor: pointer; border-radius: 4px; font-weight: bold; margin-bottom: 15px;
                    }
                    .btn:hover { background: #2ea043; }
                </style>
            </head>
            <body>
                <h2>⚡ CyberOps JS Recon Report</h2>
                <div class="stats">
                    Target: ${window.location.hostname} <br>
                    Total Findings: ${uniqueFindings.length}
                </div>

                <button class="btn" onclick="copyAll()">📋 Copy All to Clipboard</button>

                <table>
                    <thead>
                        <tr>
                            <th style="width: 15%">Type</th>
                            <th>Finding</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${uniqueFindings.map(f => `
                            <tr>
                                <td class="${f.type.includes('Secret') ? 'secret' : 'endpoint'}">${f.type}</td>
                                <td>${f.content}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>

                <script>
                    function copyAll() {
                        const data = ${JSON.stringify(uniqueFindings)};
                        const text = data.map(i => i.type + " | " + i.content).join('\\n');
                        navigator.clipboard.writeText(text).then(() => {
                            alert('✅ All findings copied to clipboard!');
                        });
                    }
                </script>
            </body>
            </html>
        `;

        // Open Popup
        const win = window.open("", "CyberOpsRecon", "width=900,height=700,scrollbars=yes,resizable=yes");
        if (win) {
            win.document.open();
            win.document.write(htmlContent);
            win.document.close();
            win.focus();
        } else {
            alert("⚠️ Popup Blocked!\nPlease allow popups to see the Recon Report.");
        }
    });
})();