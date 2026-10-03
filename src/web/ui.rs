//! Embedded HTML, CSS, and client-side JavaScript for the Skybouncer Web Dashboard.
//!
//! Serves a self-contained, zero-dependency single-page application (SPA) featuring:
//! - Real-time operational telemetry and KPI metrics.
//! - Interactive dry-run rule evaluation simulator and playground.
//! - Audit timeline of recent bounced violators with one-click pardon buttons.
//! - Dynamic moderation rubric and sensitivity threshold controls.
//! - ATProto OAuth 2.0 PKCE sign-in modal.

use axum::response::Html;

/// HTML payload for the single-page application dashboard.
pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Skybouncer 🛡️ Sovereign Moderation Dashboard</title>
  <meta name="color-scheme" content="light dark">
  <script>
    {
      const colorScheme = localStorage.getItem("color-scheme");
      if (colorScheme) {
        document.querySelector('meta[name="color-scheme"]').content = colorScheme;
      }
    }
  </script>
  <style>
    :root {
      --bg-base: #0f172a;
      --bg-card: rgba(30, 41, 59, 0.7);
      --bg-card-hover: rgba(51, 65, 85, 0.7);
      --border-color: rgba(255, 255, 255, 0.1);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #6366f1;
      --accent-hover: #4f46e5;
      --accent-glow: rgba(99, 102, 241, 0.25);
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.15);
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.15);
      --warning: #f59e0b;
      --radius: 12px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      color-scheme: dark;
    }

    @media (prefers-color-scheme: light) {
      :root {
        --bg-base: #f8fafc;
        --bg-card: rgba(255, 255, 255, 0.85);
        --bg-card-hover: rgba(241, 245, 249, 0.9);
        --border-color: rgba(0, 0, 0, 0.1);
        --text-main: #0f172a;
        --text-muted: #64748b;
        --accent: #4f46e5;
        --accent-hover: #4338ca;
        --accent-glow: rgba(79, 70, 229, 0.2);
        color-scheme: light;
      }
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-base);
      color: var(--text-main);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      line-height: 1.5;
    }

    header {
      background: var(--bg-card);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
      padding: 1rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }

    .brand { display: flex; align-items: center; gap: 0.75rem; }
    .brand-icon { font-size: 1.75rem; }
    .brand-title { font-size: 1.35rem; font-weight: 700; letter-spacing: -0.02em; }
    .brand-subtitle { font-size: 0.8rem; color: var(--text-muted); }

    .header-actions { display: flex; align-items: center; gap: 1rem; }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      background: var(--success-bg);
      color: var(--success);
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.8rem;
      font-weight: 600;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      background: var(--success);
      border-radius: 50%;
      box-shadow: 0 0 8px var(--success);
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

    main {
      flex: 1;
      max-width: 1280px;
      width: 100%;
      margin: 0 auto;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 2rem;
    }

    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
    }
    .kpi-card {
      background: var(--bg-card);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 1.25rem;
      display: flex;
      flex-direction: column;
      gap: 0.25rem;
      transition: transform 0.15s ease, border-color 0.15s ease;
    }
    .kpi-card:hover { transform: translateY(-2px); border-color: var(--accent); }
    .kpi-label { font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); font-weight: 600; }
    .kpi-val { font-size: 1.75rem; font-weight: 800; color: var(--text-main); }
    .kpi-sub { font-size: 0.75rem; color: var(--text-muted); }

    .dashboard-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 2rem;
    }
    @media (max-width: 900px) {
      .dashboard-grid { grid-template-columns: 1fr; }
    }

    .card {
      background: var(--bg-card);
      backdrop-filter: blur(8px);
      border: 1px solid var(--border-color);
      border-radius: var(--radius);
      padding: 1.5rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.75rem;
    }
    .card-title { font-size: 1.1rem; font-weight: 700; display: flex; align-items: center; gap: 0.5rem; }

    textarea, input[type="text"] {
      width: 100%;
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      color: var(--text-main);
      padding: 0.75rem 1rem;
      font-size: 0.95rem;
      font-family: inherit;
      resize: vertical;
      transition: border-color 0.15s ease;
    }
    textarea:focus, input[type="text"]:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-glow);
    }

    .btn {
      background: var(--accent);
      color: white;
      border: none;
      border-radius: 8px;
      padding: 0.65rem 1.25rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: background 0.15s ease, transform 0.1s ease;
    }
    .btn:hover { background: var(--accent-hover); transform: translateY(-1px); }
    .btn:active { transform: translateY(0); }
    .btn-secondary {
      background: rgba(255, 255, 255, 0.08);
      color: var(--text-main);
    }
    .btn-secondary:hover { background: rgba(255, 255, 255, 0.15); }
    .btn-danger {
      background: var(--danger-bg);
      color: var(--danger);
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .btn-danger:hover { background: var(--danger); color: white; }

    .segmented-control {
      display: flex;
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.25rem;
      gap: 0.25rem;
    }
    .segmented-btn {
      flex: 1;
      background: transparent;
      border: none;
      border-radius: 6px;
      color: var(--text-muted);
      padding: 0.5rem 0.75rem;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .segmented-btn.active {
      background: var(--accent);
      color: white;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }

    .chips-row { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .chip {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 0.35rem 0.65rem;
      border-radius: 6px;
      font-size: 0.75rem;
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .chip:hover { border-color: var(--accent); color: var(--text-main); }

    .result-box {
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
      background: rgba(0, 0, 0, 0.15);
    }
    .verdict-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .verdict-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.35rem 0.85rem;
      border-radius: 6px;
      font-weight: 700;
      font-size: 0.9rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .verdict-violation { background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
    .verdict-permitted { background: var(--success-bg); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }

    .progress-bar-container {
      background: rgba(255, 255, 255, 0.1);
      border-radius: 9999px;
      height: 8px;
      width: 100%;
      overflow: hidden;
      position: relative;
    }
    .progress-fill {
      height: 100%;
      border-radius: 9999px;
      transition: width 0.3s ease;
    }

    .table-container {
      overflow-x: auto;
      border: 1px solid var(--border-color);
      border-radius: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
      text-align: left;
    }
    th, td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border-color);
    }
    th {
      background: rgba(0, 0, 0, 0.2);
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.05em;
    }
    tr:hover td { background: var(--bg-card-hover); }

    .toast {
      position: fixed;
      bottom: 2rem;
      right: 2rem;
      background: var(--text-main);
      color: var(--bg-base);
      padding: 0.75rem 1.25rem;
      border-radius: 8px;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
      opacity: 0;
      transform: translateY(10px);
      transition: all 0.2s ease;
      z-index: 100;
      pointer-events: none;
    }
    .toast.show { opacity: 1; transform: translateY(0); }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div>
        <div class="brand-title">Skybouncer</div>
        <div class="brand-subtitle">Sovereign Automated Moderation for ATProto & Bluesky</div>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-badge" id="firehose-badge">
        <div class="pulse-dot"></div>
        <span>Firehose Active</span>
      </div>
      <div class="status-badge" id="queue-badge" style="background: rgba(99, 102, 241, 0.12); color: var(--accent); border: 1px solid rgba(99, 102, 241, 0.25);">
        <span id="queue-badge-text">Queue: Idle (1 worker)</span>
      </div>
      <button class="btn btn-secondary" onclick="showLoginModal()">Bluesky SSO</button>
    </div>
  </header>

  <main>
    <!-- Live Telemetry KPI Cards -->
    <section class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Commits Ingested</div>
        <div class="kpi-val" id="kpi-commits">0</div>
        <div class="kpi-sub">Jetstream Firehose</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Interactions Matched</div>
        <div class="kpi-val" id="kpi-matched">0</div>
        <div class="kpi-sub">Replies, Mentions, Quotes</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Gate Bypassed ($0)</div>
        <div class="kpi-val" id="kpi-bypassed">0</div>
        <div class="kpi-sub">&lt;1&mu;s Followed / Self</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Dedup Cache Hits</div>
        <div class="kpi-val" id="kpi-dedup">0</div>
        <div class="kpi-sub">24h SQLite Cache</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Model Evaluations</div>
        <div class="kpi-val" id="kpi-evals">0</div>
        <div class="kpi-sub">Jev System-1 Classifier</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Evaluation Queue</div>
        <div class="kpi-val" id="kpi-queue-backlog" style="color: var(--accent);">0</div>
        <div class="kpi-sub" id="kpi-queue-sub">0 Enqueued &bull; 1 Worker</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Queue Overflows</div>
        <div class="kpi-val" id="kpi-queue-overflows">0</div>
        <div class="kpi-sub" id="kpi-queue-overflows-sub">Capacity: 256 (0 Shed)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Bounces Executed</div>
        <div class="kpi-val" id="kpi-bounces" style="color: var(--danger);">0</div>
        <div class="kpi-sub" id="kpi-bounces-sub">PDS ModList Items</div>
      </div>
    </section>

    <!-- Main Content Grid -->
    <div class="dashboard-grid">
      <!-- Interactive Simulator Card -->
      <section class="card">
        <div class="card-header">
          <div class="card-title">🧪 Rule Sandbox & Simulator</div>
          <span style="font-size: 0.8rem; color: var(--text-muted);">Dry-run evaluation</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted);">
          Simulate how current rules evaluate incoming text without issuing PDS list mutations.
        </p>
        <div class="chips-row">
          <button class="chip" onclick="setSimText('🎉 Free $AIRDROP live right now! Connect your wallet at https://claim-crypto.xyz')">Crypto Airdrop</button>
          <button class="chip" onclick="setSimText('dm me on telegram https://t.me/cryptopumps for 100x signals')">Telegram Lure</button>
          <button class="chip" onclick="setSimText('You are an absolute clown and nobody respects your awful take')">Harassment</button>
          <button class="chip" onclick="setSimText('I enjoyed your blog post about distributed consensus systems!')">Polite Discourse</button>
        </div>
        <textarea id="sim-text" rows="3" placeholder="Enter post text to test against current rules..."></textarea>
        
        <div style="display: flex; flex-direction: column; gap: 0.5rem; margin-top: 0.25rem;">
          <div style="display: flex; gap: 0.5rem; align-items: center;">
            <input type="text" id="sim-image-url" placeholder="Optional image or meme URL (https://...)" oninput="onSimImageUrlChange()" style="flex: 1; margin: 0; font-size: 0.8rem; padding: 0.45rem 0.75rem;" />
            <input type="file" id="sim-file-input" accept="image/*" style="display:none;" onchange="onSimFileSelected(event)" />
            <button class="chip" type="button" style="white-space: nowrap; height: 34px;" onclick="document.getElementById('sim-file-input').click()">🖼️ Upload File</button>
            <button class="chip" id="sim-clear-img-btn" type="button" style="display:none; color: var(--danger); border-color: rgba(239, 68, 68, 0.4); height: 34px;" onclick="clearSimImage()">✕ Clear</button>
          </div>
          <div id="sim-image-preview-container" style="display: none; padding: 0.5rem; background: rgba(0,0,0,0.2); border: 1px dashed var(--border-color); border-radius: 6px;">
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <img id="sim-image-preview" src="" alt="Simulator image preview" style="max-height: 80px; max-width: 120px; border-radius: 4px; object-fit: contain; background: rgba(0,0,0,0.4);" />
              <div>
                <span id="sim-image-label" style="font-size: 0.75rem; color: var(--text-main); font-weight: 600; display: block;"></span>
                <span style="font-size: 0.7rem; color: var(--text-muted); display: block;">Image will be evaluated alongside post text via Tier 2 Multimodal / Vision fallback.</span>
              </div>
            </div>
          </div>
        </div>

        <div>
          <button class="btn" onclick="runSimulation()">⚡ Evaluate Post</button>
        </div>
        <div class="result-box" id="sim-result" style="display: none;">
          <div class="verdict-header">
            <span class="verdict-badge" id="sim-badge">PERMITTED</span>
            <span style="font-size: 0.8rem; font-weight: 600;" id="sim-evaluator">heuristic</span>
          </div>
          <div id="sim-multimodal-note" style="display:none; font-size: 0.75rem; color: var(--accent); font-weight: 600;">
            🖼️ Evaluated with attached visual context
          </div>
          <div>
            <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.35rem;">
              <span id="sim-category">Category: None</span>
              <span id="sim-confidence">Confidence: 0%</span>
            </div>
            <div class="progress-bar-container">
              <div class="progress-fill" id="sim-bar" style="width: 0%; background: var(--success);"></div>
            </div>
          </div>
          <p style="font-size: 0.85rem;" id="sim-reason"></p>
        </div>
      </section>

      <!-- House Rules & Controls Card -->
      <section class="card">
        <div class="card-header">
          <div class="card-title">📋 House Rules & Sensitivity</div>
          <span style="font-size: 0.8rem; color: var(--text-muted);">Live Sync</span>
        </div>
        <p style="font-size: 0.85rem; color: var(--text-muted);">
          Natural-language moderation prompt evaluated by classifiers.
        </p>
        <div>
          <label style="font-size: 0.75rem; text-transform: uppercase; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 0.35rem;">
            Detection Sensitivity
          </label>
          <div class="segmented-control">
            <button class="segmented-btn" id="sens-low" onclick="setSensitivity('low')">Low (0.90)</button>
            <button class="segmented-btn active" id="sens-med" onclick="setSensitivity('medium')">Medium (0.75)</button>
            <button class="segmented-btn" id="sens-high" onclick="setSensitivity('high')">High (0.60)</button>
          </div>
        </div>
        <div>
          <label style="font-size: 0.75rem; text-transform: uppercase; font-weight: 600; color: var(--text-muted); display: block; margin-bottom: 0.35rem;">
            Moderation Prompt
          </label>
          <textarea id="rules-prompt" rows="4" placeholder="Describe what content should be automatically filtered..."></textarea>
        </div>
        <div>
          <button class="btn" onclick="saveRules()">💾 Save Rubric</button>
        </div>
      </section>
    </div>

    <!-- Live Audit Feed -->
    <section class="card">
      <div class="card-header">
        <div class="card-title">🚫 Recently Bounced Violators</div>
        <button class="btn btn-secondary" style="padding: 0.4rem 0.75rem; font-size: 0.8rem;" onclick="loadBounces()">🔄 Refresh</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Violator DID</th>
              <th>Category</th>
              <th>Confidence</th>
              <th>Reason</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="bounces-table">
            <tr>
              <td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">Loading recent bounces...</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <div class="toast" id="toast">Changes saved</div>

  <script>
    let activeSensitivity = "medium";

    async function fetchStatus() {
      try {
        const res = await fetch("/api/status");
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById("kpi-commits").innerText = data.stats.commits_received.toLocaleString();
        document.getElementById("kpi-matched").innerText = data.stats.interactions_matched.toLocaleString();
        document.getElementById("kpi-bypassed").innerText = (data.stats.gate_bypassed_followed + data.stats.gate_bypassed_self).toLocaleString();
        document.getElementById("kpi-dedup").innerText = data.stats.dedup_cache_hits.toLocaleString();
        document.getElementById("kpi-evals").innerText = data.stats.model_evaluations.toLocaleString();
        document.getElementById("kpi-bounces").innerText = data.stats.bounces_executed.toLocaleString();

        const enqueued = data.stats.eval_queue_enqueued || 0;
        const processed = data.stats.eval_queue_processed || 0;
        const overflows = data.stats.eval_queue_overflows || 0;
        const backlog = Math.max(0, enqueued - processed);

        const backlogEl = document.getElementById("kpi-queue-backlog");
        if (backlogEl) backlogEl.innerText = backlog.toLocaleString();

        const queueSubEl = document.getElementById("kpi-queue-sub");
        if (queueSubEl) queueSubEl.innerText = `${enqueued.toLocaleString()} Enqueued • ${processed.toLocaleString()} Done`;

        const overflowsEl = document.getElementById("kpi-queue-overflows");
        if (overflowsEl) {
          overflowsEl.innerText = overflows.toLocaleString();
          overflowsEl.style.color = overflows > 0 ? "var(--danger)" : "var(--text-main)";
        }

        const overflowsSubEl = document.getElementById("kpi-queue-overflows-sub");
        if (overflowsSubEl) {
          overflowsSubEl.innerText = overflows > 0
            ? `${overflows.toLocaleString()} Shed (Cap: 256)`
            : "Capacity: 256 (0 Shed)";
        }

        const queueBadgeText = document.getElementById("queue-badge-text");
        if (queueBadgeText) {
          queueBadgeText.innerText = backlog > 0
            ? `Queue: ${backlog} pending`
            : "Queue: Idle (1 worker)";
        }

        if (data.dry_run) {
          const badge = document.getElementById("firehose-badge");
          if (badge) {
            badge.style.borderColor = "var(--warning)";
            badge.style.color = "var(--warning)";
            badge.innerHTML = '<div class="pulse-dot" style="background: var(--warning); box-shadow: 0 0 8px var(--warning);"></div><span>🛡️ Shadow Mode (Dry Run)</span>';
          }
          const sub = document.getElementById("kpi-bounces-sub");
          if (sub) sub.innerText = "Simulated Bounces (No Writes)";
        }
      } catch (e) {
        console.error("Status fetch failed", e);
      }
    }

    async function loadRules() {
      try {
        const res = await fetch("/api/rules");
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById("rules-prompt").value = data.prompt;
        setSensitivity(data.sensitivity);
      } catch (e) {
        console.error("Rules fetch failed", e);
      }
    }

    function setSensitivity(val) {
      activeSensitivity = val;
      document.getElementById("sens-low").classList.toggle("active", val === "low");
      document.getElementById("sens-med").classList.toggle("active", val === "medium");
      document.getElementById("sens-high").classList.toggle("active", val === "high");
    }

    async function saveRules() {
      const prompt = document.getElementById("rules-prompt").value;
      try {
        const res = await fetch("/api/rules", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ prompt, sensitivity: activeSensitivity })
        });
        if (res.ok) {
          showToast("✅ Moderation rubric updated successfully!");
        } else {
          showToast("❌ Failed to save rubric");
        }
      } catch (e) {
        showToast("❌ Network error saving rubric");
      }
    }

    let simBase64Image = null;

    function onSimFileSelected(event) {
      const file = event.target.files && event.target.files[0];
      if (!file) return;
      if (file.size > 4 * 1024 * 1024) {
        showToast("⚠️ Image file exceeds 4MB limit");
        return;
      }
      const reader = new FileReader();
      reader.onload = function(e) {
        const fullDataUrl = e.target.result;
        const commaIdx = fullDataUrl.indexOf(",");
        if (commaIdx !== -1) {
          simBase64Image = fullDataUrl.substring(commaIdx + 1);
        } else {
          simBase64Image = fullDataUrl;
        }
        document.getElementById("sim-image-preview").src = fullDataUrl;
        document.getElementById("sim-image-label").innerText = `Uploaded: ${file.name} (${Math.round(file.size / 1024)} KB)`;
        document.getElementById("sim-image-preview-container").style.display = "block";
        document.getElementById("sim-clear-img-btn").style.display = "inline-flex";
        document.getElementById("sim-image-url").value = "";
      };
      reader.readAsDataURL(file);
    }

    function onSimImageUrlChange() {
      const url = document.getElementById("sim-image-url").value.trim();
      if (url.startsWith("http://") || url.startsWith("https://")) {
        simBase64Image = null;
        document.getElementById("sim-image-preview").src = url;
        document.getElementById("sim-image-label").innerText = `Remote URL: ${url.length > 40 ? url.substring(0, 37) + '...' : url}`;
        document.getElementById("sim-image-preview-container").style.display = "block";
        document.getElementById("sim-clear-img-btn").style.display = "inline-flex";
      } else if (!url) {
        if (!simBase64Image) {
          clearSimImage();
        }
      }
    }

    function clearSimImage() {
      simBase64Image = null;
      document.getElementById("sim-image-url").value = "";
      document.getElementById("sim-file-input").value = "";
      document.getElementById("sim-image-preview").src = "";
      document.getElementById("sim-image-preview-container").style.display = "none";
      document.getElementById("sim-clear-img-btn").style.display = "none";
    }

    function setSimText(text) {
      document.getElementById("sim-text").value = text;
      runSimulation();
    }

    async function runSimulation() {
      const text = document.getElementById("sim-text").value.trim();
      if (!text) return;

      const payload = { text };
      const imgUrl = document.getElementById("sim-image-url").value.trim();
      if (simBase64Image) {
        payload.image_base64 = simBase64Image;
      } else if (imgUrl && (imgUrl.startsWith("http://") || imgUrl.startsWith("https://"))) {
        payload.image_url = imgUrl;
      }

      try {
        const res = await fetch("/api/simulate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        if (!res.ok) return;
        const data = await res.json();

        const box = document.getElementById("sim-result");
        const badge = document.getElementById("sim-badge");
        const bar = document.getElementById("sim-bar");
        const multiNote = document.getElementById("sim-multimodal-note");

        box.style.display = "flex";
        if (data.violates) {
          badge.className = "verdict-badge verdict-violation";
          badge.innerText = `VIOLATION: ${data.category || 'Harassment'}`;
          bar.style.background = "var(--danger)";
        } else {
          badge.className = "verdict-badge verdict-permitted";
          badge.innerText = "PERMITTED";
          bar.style.background = "var(--success)";
        }

        const pct = Math.round(data.confidence * 100);
        bar.style.width = `${pct}%`;
        document.getElementById("sim-confidence").innerText = `Confidence: ${pct}% (Threshold: ${Math.round(data.threshold * 100)}%)`;
        document.getElementById("sim-category").innerText = `Category: ${data.category || 'None'}`;

        const evalStr = (data.evaluator || "").toLowerCase();
        if (evalStr.includes("fallback") || evalStr.includes("vision")) {
          document.getElementById("sim-evaluator").innerText = "👁️ Vision Fallback (Tier 2 Multimodal)";
        } else if (evalStr.includes("heuristic")) {
          document.getElementById("sim-evaluator").innerText = "⚡ Heuristic Pre-Filter";
        } else if (data.images_evaluated > 0 || evalStr.includes("multimodal")) {
          document.getElementById("sim-evaluator").innerText = "🧠 Primary Model (Multimodal)";
        } else {
          document.getElementById("sim-evaluator").innerText = "🧠 Jev Model (Text)";
        }

        if (data.images_evaluated > 0) {
          multiNote.style.display = "block";
          multiNote.innerText = `🖼️ Evaluated with ${data.images_evaluated} image payload(s)`;
        } else {
          multiNote.style.display = "none";
        }

        document.getElementById("sim-reason").innerText = data.reason;
      } catch (e) {
        console.error("Simulation failed", e);
      }
    }

    async function loadBounces() {
      try {
        const res = await fetch("/api/bounces?limit=20");
        if (!res.ok) return;
        const bounces = await res.json();
        const tbody = document.getElementById("bounces-table");

        if (bounces.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 2rem;">No accounts have been bounced yet. Shield is active!</td></tr>';
          return;
        }

        tbody.innerHTML = bounces.map(b => `
          <tr>
            <td><code style="font-size: 0.8rem; background: rgba(0,0,0,0.2); padding: 0.2rem 0.4rem; border-radius: 4px;">${b.subject_did}</code></td>
            <td><span class="status-badge" style="background: var(--danger-bg); color: var(--danger); font-size: 0.75rem;">${b.category}</span></td>
            <td><strong>${Math.round(b.confidence * 100)}%</strong></td>
            <td>${escapeHtml(b.reason)}</td>
            <td>
              <button class="btn btn-danger" style="padding: 0.25rem 0.65rem; font-size: 0.75rem;" onclick="pardonUser('${b.subject_did}')">Pardon</button>
            </td>
          </tr>
        `).join("");
      } catch (e) {
        console.error("Bounces fetch failed", e);
      }
    }

    async function pardonUser(did) {
      if (!confirm(`Are you sure you want to pardon ${did} and remove them from your moderation list?`)) return;

      try {
        const res = await fetch("/api/pardon", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ subject_did: did })
        });
        if (res.ok) {
          showToast(`✅ Pardoned ${did}`);
          loadBounces();
          fetchStatus();
        } else {
          showToast("❌ Failed to pardon user");
        }
      } catch (e) {
        showToast("❌ Network error pardoning user");
      }
    }

    function showLoginModal() {
      const handle = prompt("Enter your Bluesky handle to sign in via ATProto OAuth (e.g. alice.bsky.social):");
      if (handle && handle.trim()) {
        window.location.href = `/oauth/login?handle=${encodeURIComponent(handle.trim())}`;
      }
    }

    function showToast(msg) {
      const t = document.getElementById("toast");
      t.innerText = msg;
      t.classList.add("show");
      setTimeout(() => t.classList.remove("show"), 3000);
    }

    function escapeHtml(str) {
      return (str || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }

    // Initial load
    fetchStatus();
    loadRules();
    loadBounces();
    setInterval(fetchStatus, 3000);
  </script>
</body>
</html>
"#;

/// Handler for `GET /`: serves the Single-Page Application dashboard HTML.
pub async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}
