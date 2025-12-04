// tools/js-miner-v3.js
(function() {
    console.clear();
    console.log("%c⚡ ArCHie's Miner Starting...", "color: orange; font-weight: bold; font-size: 1.2em;");

    // --- 1. CONFIGURATION & REGEX ---
    const results = {
        staticFiles: new Set(),
        endpoints: new Set(),
        secrets: new Set(),
        errors: []
    };

    const regexSecrets = [
        // AWS & Cloud
        { name: "AWS API Key", pattern: /AKIA[0-9A-Z]{16}/g },
        { name: "AWS Secret", pattern: /(aws_secret_access_key|aws_access_key_id)[\s:=]{1,3}["'`]?([a-zA-Z0-9/+]{40})["'`]?/gi },
        { name: "Stripe Key", pattern: /sk_live_[0-9a-zA-Z]{24}/g },
        { name: "Google API", pattern: /AIza[0-9A-Za-z-_]{35}/g },
        
        // Generic Keywords (keys, tokens, passwords)
        // Improved: Matches "key": "value", key='value', key = `value`
        { name: "Generic Secret", pattern: /(api_key|apikey|secret|token|auth_token|access_token|password|pwd)[\s:=]{1,3}["'`] ?([a-zA-Z0-9_\-\.]{10,})["'`]/gi },
        { name: "Bearer Token", pattern: /Authorization[\s:=]+["'`]?(Bearer\s[a-zA-Z0-9_\-\.]{30,})["'`]?/gi },
        
        // Environment Variables
        { name: "Node Env", pattern: /process\.env\.([a-zA-Z0-9_]+)/g },
    ];

    const regexEndpoint = /(?:"|'|`)(((?:[a-zA-Z]{1,10}:\/\/|\/)[^"'/]{1,}\/[a-zA-Z0-9_.\-/?=&%]+)|((?:\/|\.\.\/)[a-zA-Z0-9_.\-]+\.[a-z]{2,4}))(?:"|'|`)/gi;

    // --- 2. SCANNING LOGIC ---
    function scanText(text, sourceName) {
        if (!text) return;

        // A. Endpoints
        let match;
        // Reset regex state just in case
        regexEndpoint.lastIndex = 0;
        
        while ((match = regexEndpoint.exec(text)) !== null) {
            let url = match[1];
            // Filter junk
            if (!url.match(/\.(png|jpg|jpeg|gif|svg|css|woff|ttf|eot|mp4|mp3)$/i) && !url.includes('<') && url.length < 150) {
                // Resolve relative URLs
                if (url.startsWith('/')) {
                    url = window.location.origin + url;
                }
                results.endpoints.add(JSON.stringify({ url: url, source: sourceName })); 
            }
        }

        // B. Secrets
        regexSecrets.forEach(rule => {
            // CRITICAL: Reset lastIndex before scanning a new string, or matches will be skipped
            rule.pattern.lastIndex = 0; 
            
            let secretMatch;
            while ((secretMatch = rule.pattern.exec(text)) !== null) {
                // Capture the value. Group 2 is usually the value in "key=value" pairs.
                // If no Group 2, use Group 0 (whole match).
                let content = secretMatch[2] || secretMatch[0];
                
                // Context helps verify it's not a false positive
                let fullMatch = secretMatch[0].substring(0, 50); 
                
                results.secrets.add(JSON.stringify({ 
                    type: rule.name, 
                    content: content, 
                    preview: fullMatch,
                    source: sourceName 
                }));
            }
        });
    }

    // --- 3. EXECUTION ---
    
    // Inventory Scripts
    document.querySelectorAll('script[src]').forEach(s => s.src && results.staticFiles.add(s.src));
    
    // Scan Inline Scripts
    document.querySelectorAll('script:not([src])').forEach(s => scanText(s.innerText, "Inline Script"));

    console.log(`%c[+] Found ${results.staticFiles.size} external scripts. Fetching...`, "color: cyan");

    // Fetch External Scripts
    const fetchPromises = Array.from(results.staticFiles).map(url => {
        // Skip self
        if (url.includes('js-miner')) return Promise.resolve();

        return fetch(url)
            .then(r => {
                if (!r.ok) throw new Error(r.status);
                return r.text();
            })
            .then(text => scanText(text, url.split('/').pop()))
            .catch(e => {
                results.errors.push(url);
            });
    });

    // --- 4. REPORT GENERATOR ---
    Promise.all(fetchPromises).then(() => {
        // Parse Sets back to Objects
        const secretArr = Array.from(results.secrets).map(JSON.parse);
        const endpointArr = Array.from(results.endpoints).map(JSON.parse);
        const staticArr = Array.from(results.staticFiles);

        console.log(`%c[+] Scan Complete! Secrets: ${secretArr.length} | Endpoints: ${endpointArr.length}`, "color: lime");

        // Prepare JSON for the Textarea
        const rawJSON = JSON.stringify({
            target: window.location.hostname,
            timestamp: new Date().toISOString(),
            secrets: secretArr,
            endpoints: endpointArr,
            files: staticArr
        }, null, 2);

        // --- BACKUP: PRINT TO CONSOLE ---
        console.log("⬇️ RAW JSON REPORT (Backup) ⬇️");
        console.log(rawJSON);

        // --- UI POPUP ---
        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>JS Miner Report</title>
                <style>
                    body { background: #1a1a1a; color: #eee; font-family: monospace; padding: 20px; }
                    h2 { color: #f39c12; border-bottom: 1px solid #444; padding-bottom: 10px; }
                    .box { background: #2b2b2b; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
                    textarea { width: 100%; height: 150px; background: #000; color: #0f0; border: 1px solid #444; padding: 10px; font-family: monospace; font-size: 11px; }
                    table { width: 100%; border-collapse: collapse; font-size: 12px; }
                    th, td { border: 1px solid #444; padding: 8px; text-align: left; }
                    th { background: #333; }
                    .high { color: #e74c3c; font-weight: bold; }
                    .link { color: #3498db; text-decoration: none; }
                    .source { color: #7f8c8d; font-style: italic; }
                </style>
            </head>
            <body>
                <h1>🕵️ Miner Results: ${window.location.hostname}</h1>
                
                <div class="box">
                    <h3>📄 Raw JSON (Ctrl+A, Ctrl+C to Copy)</h3>
                    <textarea id="jsonArea">${rawJSON}</textarea>
                </div>

                <h2>🔐 Secrets Found (${secretArr.length})</h2>
                <table>
                    <thead><tr><th>Type</th><th>Content</th><th>Source</th></tr></thead>
                    <tbody>
                        ${secretArr.map(s => `<tr><td>${s.type}</td><td class="high">${s.content}</td><td class="source">${s.source}</td></tr>`).join('')}
                    </tbody>
                </table>

                <h2>🔗 Endpoints (${endpointArr.length})</h2>
                <table>
                    <thead><tr><th>URL</th><th>Source</th></tr></thead>
                    <tbody>
                        ${endpointArr.map(e => `<tr><td><a href="${e.url}" target="_blank" class="link">${e.url}</a></td><td class="source">${e.source}</td></tr>`).join('')}
                    </tbody>
                </table>
                
                <script>
                    // Auto-select the textarea for easy copying
                    const ta = document.getElementById('jsonArea');
                    ta.focus();
                    ta.select();
                </script>
            </body>
            </html>
        `;

        const win = window.open("", "JSMiner_v3", "width=900,height=800,scrollbars=yes,resizable=yes");
        if(win) {
            win.document.open();
            win.document.write(html);
            win.document.close();
        } else {
            console.warn("⚠️ Popup Blocked! Use the JSON printed in this console above.");
            alert("Popup blocked! Check your DevTools console for the result object.");
        }
    });
})();