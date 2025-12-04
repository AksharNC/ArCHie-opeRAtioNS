// tools/js-miner.js
(function() {
    console.log("⚡ ArCHie's Miners are Active");

    // DATA STORAGE
    const results = {
        staticFiles: new Set(),
        endpoints: new Set(),
        secrets: new Set(),
        errors: [] // Track failed fetches (CORS issues)
    };

    // --- REGEX ARSENAL ---
    const regexEndpoint = /(?:"|')(((?:[a-zA-Z]{1,10}:\/\/|\/)[^"'/]{1,}\/[a-zA-Z0-9_.\-/?=&%]+)|((?:\/|\.\.\/)[a-zA-Z0-9_.\-]+\.[a-z]{2,4}))(?:"|')/gi;

    const regexSecrets = [
        { name: "AWS API Key", pattern: /AKIA[0-9A-Z]{16}/g },
        { name: "AWS Secret", pattern: /(aws_secret_access_key|aws_access_key_id)[\s:=]{1,3}["']([a-zA-Z0-9/+]{40})["']/gi },
        { name: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24}/g },
        { name: "Node Env Access", pattern: /process\.env\.([a-zA-Z0-9_]+)/g },
        { name: "Hardcoded Secret", pattern: /(NODE_ENV|DB_PASSWORD|API_KEY|ACCESS_TOKEN|SECRET_KEY)[\s:=]{1,3}["']([^"']+)["']/gi },
        { name: "Generic Secret", pattern: /(api_key|apikey|token|auth_token|access_token)[\s:=]{1,3}["']([a-zA-Z0-9_\-]{20,})["']/gi },
        { name: "Auth Header", pattern: /Authorization[\s:=]+["'](Bearer\s[a-zA-Z0-9_\-\.]{30,})["']/gi }
    ];

    // --- PROCESSING ---
    function scanText(text, sourceName) {
        // 1. Endpoints
        let match;
        while ((match = regexEndpoint.exec(text)) !== null) {
            let url = match[1];
            // Filter junk and common false positives
            if (!url.match(/\.(png|jpg|jpeg|svg|css|woff|ttf|eot)$/i) && !url.includes('<') && !url.includes('>')) {
                // Attempt to resolve relative URLs to absolute for the report
                let fullUrl = url;
                if (url.startsWith('/')) {
                    fullUrl = window.location.origin + url;
                }
                results.endpoints.add({ url: fullUrl, raw: url, source: sourceName });
            }
        }

        // 2. Secrets
        regexSecrets.forEach(rule => {
            let secretMatch;
            // Reset lastIndex for global regex checks
            rule.pattern.lastIndex = 0; 
            while ((secretMatch = rule.pattern.exec(text)) !== null) {
                let content = secretMatch.length > 1 ? secretMatch[1] : secretMatch[0];
                if (secretMatch.length > 2) content += ` = ${secretMatch[2]}`;
                results.secrets.add({ type: rule.name, content: content, source: sourceName });
            }
        });
    }

    // --- EXECUTION ---
    // 1. Inventory Scripts
    document.querySelectorAll('script[src]').forEach(s => {
        if(s.src) results.staticFiles.add(s.src);
    });

    // 2. Scan Inline
    document.querySelectorAll('script:not([src])').forEach(s => {
        scanText(s.innerText, "Inline Script");
    });

    // 3. Fetch External
    const fetchPromises = Array.from(results.staticFiles).map(url => {
        if (url.includes('js-miner.js')) return Promise.resolve();
        
        return fetch(url)
            .then(r => r.text())
            .then(text => scanText(text, url.split('/').pop()))
            .catch(e => {
                // Log CORS errors or network failures
                results.errors.push(url);
            });
    });

    // --- REPORT ---
    Promise.all(fetchPromises).then(() => {
        const secretArr = Array.from(results.secrets);
        const endpointArr = Array.from(results.endpoints);
        const staticArr = Array.from(results.staticFiles);

        // Prepare JSON data for the button
        const jsonReport = JSON.stringify({
            target: document.location.hostname,
            secrets: secretArr,
            endpoints: endpointArr,
            files: staticArr,
            failed_scans: results.errors
        }, null, 2);

        // Encode data for safe embedding
        const safeJson = encodeURIComponent(jsonReport);

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>JS Miner - ${document.location.hostname}</title>
                <style>
                    body { background: #111; color: #ddd; font-family: 'Segoe UI', monospace; padding: 20px; }
                    h2 { border-bottom: 2px solid #e67e22; padding-bottom: 5px; color: #e67e22; margin-top: 30px; }
                    .stats { font-size: 0.9em; color: #888; }
                    table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #222; }
                    th, td { padding: 10px; border: 1px solid #444; text-align: left; font-size: 0.9em; word-break: break-all; }
                    th { background: #333; color: #fff; }
                    tr:hover { background: #2a2a2a; }
                    .tag { padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.8em; }
                    .tag-secret { background: #c0392b; color: white; }
                    .source { color: #888; font-size: 0.85em; font-style: italic; }
                    .btn { position: fixed; top: 20px; right: 20px; padding: 10px 20px; background: #e67e22; color: white; border: none; cursor: pointer; font-weight: bold; border-radius: 4px; z-index: 1000; }
                    .btn:active { transform: scale(0.95); }
                    .error-list { color: #e74c3c; font-size: 0.85em; margin-bottom: 20px; }
                </style>
            </head>
            <body>
                <h1>🕵️ ArCHie's JS Miner</h1>
                <div class="stats">Target: ${document.location.hostname}</div>
                <button class="btn" id="copyBtn">Copy JSON Report</button>

                ${results.errors.length > 0 ? `<div class="error-list">⚠️ Could not scan ${results.errors.length} files due to CORS/Network restrictions (check console).</div>` : ''}

                <h2>🔐 Secrets (${secretArr.length})</h2>
                <table>
                    <thead><tr><th>Type</th><th>Finding</th><th>Source</th></tr></thead>
                    <tbody>
                        ${secretArr.map(s => `<tr><td><span class="tag tag-secret">${s.type}</span></td><td style="color:#e74c3c; font-weight:bold;">${s.content}</td><td class="source">${s.source}</td></tr>`).join('')}
                    </tbody>
                </table>

                <h2>🔗 Endpoints (${endpointArr.length})</h2>
                <table>
                    <thead><tr><th>URL</th><th>Source</th></tr></thead>
                    <tbody>
                        ${endpointArr.map(e => `<tr><td><a href="${e.url}" target="_blank" style="color:#2ecc71; text-decoration:none;">${e.url}</a></td><td class="source">${e.source}</td></tr>`).join('')}
                    </tbody>
                </table>

                <h2>📂 Static Files (${staticArr.length})</h2>
                <ul>
                    ${staticArr.map(f => `<li><a href="${f}" target="_blank" style="color:#3498db;">${f}</a></li>`).join('')}
                </ul>

                <script>
                    const reportData = decodeURIComponent("${safeJson}");
                    
                    document.getElementById('copyBtn').addEventListener('click', () => {
                        // Fallback method for popups where navigator.clipboard might fail
                        const textarea = document.createElement('textarea');
                        textarea.value = reportData;
                        document.body.appendChild(textarea);
                        textarea.select();
                        try {
                            document.execCommand('copy');
                            alert("✅ JSON Report Copied to Clipboard!");
                        } catch (err) {
                            alert("❌ Copy failed. Manually copy the console output.");
                            console.log(reportData);
                        }
                        document.body.removeChild(textarea);
                    });
                </script>
            </body>
            </html>
        `;

        const win = window.open("", "JSMiner", "width=1000,height=800,scrollbars=yes,resizable=yes");
        if(win) {
            win.document.write(html);
            win.document.close();
        } else {
            alert("⚠️ Popup blocked.");
        }
    });
})();