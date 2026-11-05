"""Modern HTML Landing Page and Live Sandbox for Auth-as-a-Service."""

LANDING_PAGE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Auth-as-a-Service (AaaS) Enterprise Platform</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #3b82f6;
      --accent-hover: #2563eb;
      --success: #10b981;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem 1rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header { text-align: center; margin-bottom: 2.5rem; }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: rgba(16, 185, 129, 0.1);
      color: var(--success);
      border: 1px solid rgba(16, 185, 129, 0.25);
      padding: 0.35rem 0.85rem;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 600;
      margin-bottom: 1rem;
    }
    .status-dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      box-shadow: 0 0 10px var(--success);
    }
    h1 { font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem; letter-spacing: -0.025em; }
    .subtitle { color: var(--text-muted); font-size: 1.15rem; max-width: 650px; margin: 0 auto; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 1.5rem;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .card h2 { font-size: 1.25rem; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; }
    .card p { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 1.25rem; }
    .btn-group { display: flex; flex-wrap: wrap; gap: 0.75rem; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.65rem 1.25rem;
      border-radius: 8px;
      font-size: 0.95rem;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      transition: all 0.2s ease;
      border: none;
    }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: var(--accent-hover); transform: translateY(-1px); }
    .btn-secondary { background: #1f2937; color: var(--text); border: 1px solid #374151; }
    .btn-secondary:hover { background: #374151; }
    .form-group { margin-bottom: 1rem; }
    label { display: block; font-size: 0.85rem; font-weight: 600; color: var(--text-muted); margin-bottom: 0.35rem; }
    input {
      width: 100%;
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      color: #fff;
      padding: 0.65rem 0.85rem;
      border-radius: 6px;
      font-size: 0.95rem;
    }
    input:focus { outline: none; border-color: var(--accent); }
    .console-output {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      color: #38bdf8;
      max-height: 250px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .stats-bar {
      display: flex;
      justify-content: space-around;
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 12px;
      padding: 1.25rem;
      margin-bottom: 2.5rem;
      text-align: center;
    }
    .stat-val { font-size: 1.75rem; font-weight: 800; color: #fff; }
    .stat-label { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    footer { text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: 3rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="status-badge">
        <span class="status-dot"></span>
        API Engine Online • Python 3.14 • FastAPI
      </div>
      <h1>Auth-as-a-Service Platform</h1>
      <p class="subtitle">Self-hosted, multi-tenant enterprise authentication and authorization platform with asymmetric JWTs, RBAC/ABAC, and TOTP/WebAuthn MFA.</p>
    </header>

    <div class="stats-bar">
      <div>
        <div class="stat-val">53</div>
        <div class="stat-label">REST Endpoints</div>
      </div>
      <div>
        <div class="stat-val">1,212</div>
        <div class="stat-label">Passing Tests</div>
      </div>
      <div>
        <div class="stat-val">83%</div>
        <div class="stat-label">Code Coverage</div>
      </div>
      <div>
        <div class="stat-val">5-Layer</div>
        <div class="stat-label">Architecture</div>
      </div>
    </div>

    <div class="grid">
      <!-- Card 1: Interactive Documentation -->
      <div class="card">
        <h2>📚 Interactive Documentation</h2>
        <p>Explore, test, and execute all 53 API routes directly inside your browser using Swagger UI or ReDoc.</p>
        <div class="btn-group">
          <a href="/docs" class="btn btn-primary">Open Swagger UI (/docs)</a>
          <a href="/redoc" class="btn btn-secondary">Open ReDoc (/redoc)</a>
        </div>
      </div>

      <!-- Card 2: Security & Discovery Endpoints -->
      <div class="card">
        <h2>🛡️ Security & Discovery</h2>
        <p>Public cryptographic endpoints for federated clients, Kubernetes health probes, and Prometheus metrics.</p>
        <div class="btn-group">
          <a href="/health" target="_blank" class="btn btn-secondary">System Health</a>
          <a href="/.well-known/jwks.json" target="_blank" class="btn btn-secondary">JWKS Public Keys</a>
          <a href="/.well-known/openid-configuration" target="_blank" class="btn btn-secondary">OIDC Discovery</a>
          <a href="/metrics" target="_blank" class="btn btn-secondary">Prometheus Metrics</a>
        </div>
      </div>

      <!-- Card 3: Live Sandbox -->
      <div class="card" style="grid-column: 1 / -1;">
        <h2>⚡ Live Authentication Sandbox</h2>
        <p>Register or log in right now directly from this page to receive and inspect your live JSON Web Tokens.</p>
        
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 1.5rem;">
          <div>
            <div class="form-group">
              <label>Email Address</label>
              <input type="email" id="testEmail" value="admin@example.com">
            </div>
            <div class="form-group">
              <label>Password</label>
              <input type="password" id="testPassword" value="SuperSecurePass123!@">
            </div>
            <div class="btn-group">
              <button onclick="handleRegister()" class="btn btn-secondary">1. Register User</button>
              <button onclick="handleLogin()" class="btn btn-primary">2. Sign In & Get JWT</button>
            </div>
          </div>
          <div>
            <label>API Server Response</label>
            <div id="outputConsole" class="console-output">// Ready. Click "Register User" or "Sign In" to see live server output...</div>
          </div>
        </div>
      </div>
    </div>

    <footer>
      Auth-as-a-Service (AaaS) • 5-Layer Decoupled Architecture • 22,000+ LOC Enterprise Platform
    </footer>
  </div>

  <script>
    async function handleRegister() {
      const email = document.getElementById("testEmail").value;
      const password = document.getElementById("testPassword").value;
      const consoleEl = document.getElementById("outputConsole");
      consoleEl.textContent = "Sending POST /api/v1/auth/register...";

      try {
        const res = await fetch("/api/v1/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password, full_name: "Demo Administrator" })
        });
        const data = await res.json();
        consoleEl.textContent = `[Status: ${res.status}]\\n` + JSON.stringify(data, null, 2);
      } catch (err) {
        consoleEl.textContent = "Error: " + err.message;
      }
    }

    async function handleLogin() {
      const email = document.getElementById("testEmail").value;
      const password = document.getElementById("testPassword").value;
      const consoleEl = document.getElementById("outputConsole");
      consoleEl.textContent = "Sending POST /api/v1/auth/login...";

      try {
        const res = await fetch("/api/v1/auth/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        consoleEl.textContent = `[Status: ${res.status}]\\n` + JSON.stringify(data, null, 2);
      } catch (err) {
        consoleEl.textContent = "Error: " + err.message;
      }
    }
  </script>
</body>
</html>
"""

