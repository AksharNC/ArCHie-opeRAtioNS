// tools/js-miner.js
(function() {
    console.log("⚡ ArCHie's Miner Active");

    // 1. EXTRACTION LOGIC
    // get all links, convert to array, filter out empty ones
    const links = Array.from(document.querySelectorAll("a"))
        .map(a => ({
            text: a.innerText.trim() || "[Image/No Text]",
            href: a.href
        }))
        .filter(link => link.href && !link.href.startsWith("javascript:"));

    if (links.length === 0) {
        alert("No links found on this page.");
        return;
    }

    // 2. GENERATE HTML CONTENT FOR NEW WINDOW
    // We build a dark-mode, "hacker-style" table
    const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Min r Report - ${document.title}</title>
            <style>
                body { font-family: 'Consolas', 'Monaco', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
                h2 { color: #3fb950; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
                .stats { font-size: 0.9em; color: #8b949e; margin-bottom: 20px; }
                table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #161b22; }
                th { text-align: left; background: #21262d; padding: 10px; border: 1px solid #30363d; color: #fff; }
                td { padding: 8px; border: 1px solid #30363d; font-size: 0.85em; word-break: break-all; }
                tr:hover { background: #1c2128; }
                a { color: #58a6ff; text-decoration: none; }
                a:hover { text-decoration: underline; }
                .btn { 
                    background: #238636; color: white; border: none; padding: 8px 16px; 
                    cursor: pointer; border-radius: 4px; font-weight: bold; margin-bottom: 15px;
                }
                .btn:hover { background: #2ea043; }
            </style>
        </head>
        <body>
            <h2>⚡ ArCHie's Miner Report</h2>
            <div class="stats">
                Target: ${window.location.hostname} <br>
                Total Links Found: ${links.length}
            </div>

            <button class="btn" onclick="copyAll()">📋 Copy All to Clipboard</button>

            <table>
                <thead>
                    <tr>
                        <th style="width: 30%">Anchor Text</th>
                        <th>URL</th>
                    </tr>
                </thead>
                <tbody>
                    ${links.map(l => `
                        <tr>
                            <td>${l.text.substring(0, 50)}${l.text.length > 50 ? '...' : ''}</td>
                            <td><a href="${l.href}" target="_blank">${l.href}</a></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>

            <script>
                function copyAll() {
                    const data = ${JSON.stringify(links)};
                    const text = data.map(i => i.text + " | " + i.href).join('\\n');
                    navigator.clipboard.writeText(text).then(() => {
                        alert('✅ All links copied to clipboard!');
                    });
                }
            </script>
        </body>
        </html>
    `;

    // 3. OPEN POPUP WINDOW
    // We use a unique name so running it twice refreshes the window instead of opening a new one
    const win = window.open("", "ArCHie's Miners", "width=800,height=600,scrollbars=yes,resizable=yes");

    if (win) {
        win.document.open();
        win.document.write(htmlContent);
        win.document.close(); // Crucial: tells the browser "loading is done"
        win.focus();
    } else {
        alert("⚠️ Popup Blocked!\nPlease allow popups for this site to see the Miner Report.");
    }
})();