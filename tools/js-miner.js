// tools/js-miner.js
(function() {
    console.log("⚡ ArCHie's Burp-Style Miner Active");

    // DATA STORAGE
    const results = {
        staticFiles: new Set(), // Just the .js file links
        endpoints: new Set(),   // API routes (/api/v1/user, https://...)
        secrets: new Set()      // Keys, Tokens, Env Vars
    };

    // --- REGEX ARSENAL ---
    
    // 1. ENDPOINTS: Looks for strings inside quotes that start with / or http
    // Filters out common non-endpoints like .png, .css, text/javascript
    const regexEndpoint = /(?:"|')(((?:[a-zA-Z]{1,10}:\/\/|\/)[^"'/]{1,}\/[a-zA-Z0-9_.\-/?=&%]+)|((?:\/|\.\.\/)[a-zA-Z0-9_.\-]+\.[a-z]{2,4}))(?:"|')/gi;

    // 2. SECRETS: High entropy, specific Node patterns, and standard keys
    const regexSecrets = [
        // AWS, Google, Stripe
        { name: "AWS API Key", pattern: /AKIA[0-9A-Z]{16}/g },
        { name: "AWS Secret", pattern: /(aws_secret_access_key|aws_access_key_id)[\s:=]{1,3}["']([a-zA-Z0-9/+]{40})["']/gi },
        { name: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24}/g },
        
        // Node & Env Variables (process.env.DB_PASS, NODE_ENV = "prod")
        { name: "Node Env Access", pattern: /process\.env\.([a-zA-Z0-9_]+)/g },
        { name: "Hardcoded Env/Secret", pattern: /(NODE_ENV|DB_PASSWORD|API_KEY|ACCESS_TOKEN|SECRET_KEY)[\s:=]{1,3}["']([^"']+)["']/gi },
        
        // Generic High Entropy (Bearer tokens, etc)
        { name: "Generic Secret", pattern: /(api_key|apikey|token|auth_token|access_token)[\s:=]{1,3}["']([a-zA-Z0-9_\-]{20,})["']/gi },
        { name: "Authorization Header", pattern: /Authorization[\s:=]+["'](Bearer\s[a-zA-Z0-9_\-\.]{30,})["']/gi }
    ];

    // --- PROCESSING FUNCTIONS ---

    function scanText(text, sourceName) {
        // 1. Extract Endpoints
        let match;
        while ((match = regexEndpoint.exec(text)) !== null) {
            // Clean up the match (remove quotes if grabbed)
            let url = match[1];
            // Filter out junk (css, images, standard html tags)
            if (!url.match(/\.(png|jpg|jpeg|svg|css|woff|ttf)$/i) && !url.includes('<') && !url.includes('>')) {
                results.endpoints.add({ url: url, source: sourceName });
            }
        }

        // 2. Extract Secrets
        regexSecrets.forEach(rule => {
            while ((secretMatch = rule.pattern.exec(text)) !== null) {
                // If it captures a group (value), use that. Otherwise use full match.
                let content = secretMatch.length > 1 ? secretMatch[1] : secretMatch[0];
                if (secretMatch.length > 2) content += ` = ${secretMatch[2]}`; // Handle Key = Value format
                
                results.secrets.add({ type: rule.name, content: content, source: sourceName });
            }
        });
    }

    // --- MAIN EXECUTION ---

    // 1. Get Static Files (The Inventory)
    document.querySelectorAll('script[src]').forEach(s => {
        if(s.src) results.staticFiles.add(s.src);
    });

    // 2. Scan Inline Scripts
    document.querySelectorAll('script:not([src])').forEach(s => {
        scanText(s.innerText, "Inline Script");
    });

    // 3. Fetch & Scan External Files
    const fetchPromises = Array.from(results.staticFiles).map(url => {
        // Skip scanning the miner itself
        if (url.includes('js-miner.js')) return Promise.resolve();

        return fetch(url)
            .then(r => r.text())
            .then(text => scanText(text, url.split('/').pop())) // Pass filename as source
            .catch(e => console.log(`Could not fetch ${url}`));
    });

    // --- REPORT GENERATION ---
    Promise.all(fetchPromises).then(() => {
        
        // Convert Sets to Arrays for display
        const staticArr = Array.from(results.staticFiles);
        const endpointArr = Array.from(results.endpoints);
        const secretArr = Array.from(results.secrets);

        if (endpointArr.length === 0 && secretArr.length === 0 && staticArr.length === 0) {
            alert("Min r finished. No significant data found.");
            return;
        }

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
                    .tag-js { background: #2980b9; color: white; }
                    .tag-secret { background: #c0392b; color: white; }
                    .tag-end { background: #27ae60; color: white; }
                    .source { color: #888; font-size: 0.85em; font-style: italic; }
                    .btn { position: fixed; top: 20px; right: 20px; padding: 10px 20px; background: #e67e22; color: white; border: none; cursor: pointer; font-weight: bold; border-radius: 4px; }
                </style>
            </head>
            <body>
                <h1>🕵️ ArCHie's JS Miner</h1>
                <div class="stats">Target: ${document.location.hostname}</div>
                <button class="btn" onclick="copyReport()">Copy JSON Report</button>

                <h2>🔐 Secrets & Env Vars (${secretArr.length})</h2>
                <table>
                    <thead><tr><th>Type</th><th>Finding</th><th>Source File</th></tr></thead>
                    <tbody>
                        ${secretArr.map(s => `<tr><td><span class="tag tag-secret">${s.type}</span></td><td style="color:#e74c3c; font-weight:bold;">${s.content}</td><td class="source">${s.source}</td></tr>`).join('')}
                    </tbody>
                </table>

                <h2>🔗 Endpoints / API Routes (${endpointArr.length})</h2>
                <table>
                    <thead><tr><th>URL/Path</th><th>Found In</th></tr></thead>
                    <tbody>
                        ${endpointArr.map(e => `<tr><td><a href="${e.url}" target="_blank" style="color:#2ecc71; text-decoration:none;">${e.url}</a></td><td class="source">${e.source}</td></tr>`).join('')}
                    </tbody>
                </table>

                <h2>📂 Static JS Files (${staticArr.length})</h2>
                <table>
                    <thead><tr><th>File URL</th></tr></thead>
                    <tbody>
                        ${staticArr.map(f => `<tr><td><a href="${f}" target="_blank" style="color:#3498db;">${f}</a></td></tr>`).join('')}
                    </tbody>
                </table>

                <script>
                    function copyReport() {
                        const report = {
                            secrets: ${JSON.stringify(secretArr)},
                            endpoints: ${JSON.stringify(endpointArr)},
                            files: ${JSON.stringify(staticArr)}
                        };
                        navigator.clipboard.writeText(JSON.stringify(report, null, 2)).then(() => alert("JSON Report Copied!"));
                    }
                </script>
            </body>
            </html>
        `;

        const win = window.open("", "JSMiner", "width=1000,height=800,scrollbars=yes,resizable=yes");
        if(win) {
            win.document.open();
            win.document.write(html);
            win.document.close();
            win.focus();
        } else {
            alert("⚠️ Popup blocked. Please allow popups for this site.");
        }
    });
})();