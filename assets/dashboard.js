function resolveThemeFromPref(pref) {
  if (pref === "light" || pref === "dark") return pref;
  return (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) ? "light" : "dark";
}

function syncThemeButtons() {
  const pref = document.documentElement.getAttribute("data-theme-pref") || "system";
  const sysBtn = document.getElementById("theme-btn-system");
  const lightBtn = document.getElementById("theme-btn-light");
  const darkBtn = document.getElementById("theme-btn-dark");
  if (sysBtn) {
    sysBtn.classList.toggle("active", pref === "system");
    sysBtn.setAttribute("aria-pressed", String(pref === "system"));
  }
  if (lightBtn) {
    lightBtn.classList.toggle("active", pref === "light");
    lightBtn.setAttribute("aria-pressed", String(pref === "light"));
  }
  if (darkBtn) {
    darkBtn.classList.toggle("active", pref === "dark");
    darkBtn.setAttribute("aria-pressed", String(pref === "dark"));
  }
}

function setThemePreference(pref) {
  const validPref = (pref === "light" || pref === "dark") ? pref : "system";
  const resolved = resolveThemeFromPref(validPref);
  document.documentElement.setAttribute("data-theme", resolved);
  document.documentElement.setAttribute("data-theme-pref", validPref);
  const meta = document.querySelector('meta[name="color-scheme"]');
  if (meta) meta.content = validPref === "system" ? "light dark" : resolved;
  try {
    localStorage.setItem("atmosphere-theme", validPref);
    localStorage.setItem("color-scheme", validPref);
  } catch (_) {}
  syncThemeButtons();
}

function setHidden(el, shouldHide) {
  if (!el) return;
  el.classList.toggle("is-hidden", !!shouldHide);
}

function setProgressBar(barEl, pct, tone) {
  if (!barEl) return;
  const clamped = Math.max(0, Math.min(100, Number(pct) || 0));
  barEl.style.width = `${clamped}%`;
  barEl.classList.remove("fill-success", "fill-danger", "fill-warning", "fill-accent", "fill-purple");
  if (tone) {
    barEl.classList.add(`fill-${tone}`);
  }
}

(function initAtmosphereChrome() {
  syncThemeButtons();
  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      const pref = document.documentElement.getAttribute("data-theme-pref") || "system";
      if (pref === "system") {
        document.documentElement.setAttribute("data-theme", mq.matches ? "light" : "dark");
      }
    };
    if (mq.addEventListener) mq.addEventListener("change", onChange);
  }

  const isLocal = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";
  const fycUrl = isLocal ? "http://localhost:3030/dashboard" : "https://fyc.mike10010100.com/dashboard";
  const headerSister = document.getElementById("sister-app-header-link");
  const footerSister = document.getElementById("sister-app-footer-link");
  if (headerSister) headerSister.href = fycUrl;
  if (footerSister) footerSister.href = fycUrl;
})();

let activeSensitivity = "medium";
let activeWorkspaceTab = "activity";
let activeGuestPreset = "balanced";
let guestSimInFlight = false;
let simInFlight = false;
let toastTimer = null;
let filterBouncesTimer = null;

const PAGE_SIZE = 50;
let bouncesOffset = 0;
let bouncesTotal = 0;
let evalsOffset = 0;
let evalsTotal = 0;

const loaderControllers = {
  bounces: null,
  allowlist: null,
  storms: null,
  evals: null,
  tenants: null
};

function startLoaderRequest(key) {
  if (loaderControllers[key]) {
    loaderControllers[key].abort();
  }
  const ctrl = new AbortController();
  loaderControllers[key] = ctrl;
  return ctrl;
}

const GUEST_PRESET_DESCRIPTIONS = {
  balanced: "Filters spam, bot links, crypto shilling, and personal attacks on you while allowing normal disagreement and third-party banter.",
  anti_crypto: "Aggressively filters cryptocurrency, airdrops, memecoins, NFT promos, and Telegram/WhatsApp pump links.",
  anti_hostility: "Strictly filters insults, targeted harassment, slurs, threats, and demeaning personal attacks aimed at you.",
  anti_ragebait: "Filters bad-faith sea-lioning, troll provocations, and ragebait aimed at you while allowing other commenters to debate."
};

function switchWorkspaceTab(tab, focusTab = false) {
  const valid = (tab === "rules" || tab === "allowlist") ? tab : "activity";
  activeWorkspaceTab = valid;

  const btnAct = document.getElementById("tab-btn-activity");
  const btnRules = document.getElementById("tab-btn-rules");
  const btnAllow = document.getElementById("tab-btn-allowlist");
  const panAct = document.getElementById("tab-panel-activity");
  const panRules = document.getElementById("tab-panel-rules");
  const panAllow = document.getElementById("tab-panel-allowlist");

  const mapping = [
    { key: "activity", btn: btnAct, panel: panAct },
    { key: "rules", btn: btnRules, panel: panRules },
    { key: "allowlist", btn: btnAllow, panel: panAllow }
  ];

  mapping.forEach(({ key, btn, panel }) => {
    const isSel = valid === key;
    if (btn) {
      btn.classList.toggle("active", isSel);
      btn.setAttribute("aria-selected", String(isSel));
      btn.setAttribute("tabindex", isSel ? "0" : "-1");
      if (isSel && focusTab) btn.focus();
    }
    if (panel) {
      panel.hidden = !isSel;
    }
  });
}

function setGuestPreset(key) {
  const valid = GUEST_PRESET_DESCRIPTIONS[key] ? key : "balanced";
  activeGuestPreset = valid;
  const presets = ["balanced", "anti_crypto", "anti_hostility", "anti_ragebait"];
  presets.forEach(p => {
    const btn = document.getElementById(`guest-preset-${p}`);
    if (btn) {
      btn.classList.toggle("active", valid === p);
      btn.setAttribute("aria-pressed", String(valid === p));
    }
  });
  const descEl = document.getElementById("guest-preset-desc");
  if (descEl) descEl.innerText = GUEST_PRESET_DESCRIPTIONS[valid];
}

function updateGuestCharCount() {
  const input = document.getElementById("guest-sim-text");
  const countEl = document.getElementById("guest-char-count");
  if (input && countEl) {
    countEl.innerText = `${input.value.length} / 500`;
  }
}

function runGuestSample(text) {
  if (guestSimInFlight) return;
  const input = document.getElementById("guest-sim-text");
  if (input) {
    input.value = text;
    updateGuestCharCount();
  }
  runGuestSimulation();
}

async function runGuestSimulation() {
  if (guestSimInFlight) return;
  const input = document.getElementById("guest-sim-text");
  const text = input ? input.value.trim() : "";
  if (!text) {
    showToast("Pick a sample chip or type a reply to evaluate");
    if (input) input.focus();
    return;
  }

  guestSimInFlight = true;
  const btn = document.getElementById("guest-sim-btn");
  const btnLabel = btn ? btn.querySelector(".btn-label") : null;
  const origLabel = btnLabel ? btnLabel.textContent : "Evaluate Sample Reply";
  if (btn) btn.disabled = true;
  if (btnLabel) btnLabel.textContent = "Evaluating...";

  const rateBanner = document.getElementById("guest-sim-rate-banner");
  const rateText = document.getElementById("guest-sim-rate-text");
  const quotaBadge = document.getElementById("guest-quota-badge");

  try {
    const res = await fetch("/api/simulate/guest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ text, preset: activeGuestPreset })
    });

    const hdrRem = res.headers.get("x-ratelimit-remaining");
    const hdrLim = res.headers.get("x-ratelimit-limit");
    if (quotaBadge && hdrRem !== null && hdrLim !== null) {
      quotaBadge.innerText = `${hdrRem} / ${hdrLim} free tries/min`;
      quotaBadge.className = Number(hdrRem) === 0 ? "status-badge badge-warning" : "status-badge badge-accent";
    }

    if (res.status === 429) {
      const retryAfter = res.headers.get("Retry-After") || "60";
      if (quotaBadge) {
        quotaBadge.innerText = "0 / 6 free tries/min";
        quotaBadge.className = "status-badge badge-warning";
      }
      if (rateText) {
        rateText.innerText = `Free sandbox limit reached — resets in ${retryAfter}s, or sign in for unlimited custom testing.`;
      }
      setHidden(rateBanner, false);
      return;
    }

    if (!res.ok) {
      const errMsg = await res.text();
      showToast(errMsg || `Sandbox evaluation failed (${res.status})`);
      return;
    }

    setHidden(rateBanner, true);
    const data = await res.json();

    if (quotaBadge && data.remaining_quota !== undefined && data.quota_limit !== undefined) {
      quotaBadge.innerText = `${data.remaining_quota} / ${data.quota_limit} free tries/min`;
      quotaBadge.className = data.remaining_quota === 0 ? "status-badge badge-warning" : "status-badge badge-accent";
    }

    const box = document.getElementById("guest-sim-result");
    const badge = document.getElementById("guest-sim-badge");
    const bar = document.getElementById("guest-sim-bar");
    const evalEl = document.getElementById("guest-sim-evaluator");
    const catEl = document.getElementById("guest-sim-category");
    const confEl = document.getElementById("guest-sim-confidence");
    const reasonEl = document.getElementById("guest-sim-reason");
    const traceDetails = document.getElementById("guest-sim-trace-details");
    const traceBody = document.getElementById("guest-sim-trace-body");

    setHidden(box, false);
    const pct = Math.round((data.confidence || 0) * 100);
    const threshPct = Math.round((data.threshold || 0.75) * 100);

    if (badge && bar) {
      if (data.violates && data.meets_threshold !== false) {
        badge.className = "verdict-badge verdict-violation";
        badge.innerText = `BOUNCED · ${data.category || "Violation"}`;
        setProgressBar(bar, pct, "danger");
      } else if (data.violates) {
        badge.className = "verdict-badge verdict-permitted";
        badge.innerText = `ALLOWED (Below Threshold) · ${data.category || "Borderline"}`;
        setProgressBar(bar, pct, "warning");
      } else {
        badge.className = "verdict-badge verdict-permitted";
        badge.innerText = "ALLOWED";
        setProgressBar(bar, pct, "success");
      }
    }

    if (catEl) catEl.innerText = `Category: ${data.category || "None"}`;
    if (confEl) confEl.innerText = `Confidence: ${pct}% (Threshold: ${threshPct}%)`;
    if (reasonEl) reasonEl.innerText = data.reason || "";

    if (evalEl) {
      const evalStr = (data.evaluator || "").toLowerCase();
      if (evalStr.includes("uncertainty") || evalStr.includes("fallback")) {
        evalEl.innerText = "Tier-2 Escalation";
      } else if (evalStr.includes("heuristic")) {
        evalEl.innerText = "Instant Heuristic";
      } else {
        evalEl.innerText = "System-1 Fast Classifier";
      }
    }

    if (traceDetails && traceBody) {
      if (data.tier1 && data.tier2) {
        setHidden(traceDetails, false);
        const t1Pct = Math.round((data.tier1.confidence || 0) * 100);
        const t2Line = data.tier2.status === "resolved"
          ? `<div><strong>Tier 2 (${escapeHtml(data.tier2.model || "fallback")}):</strong> ${data.tier2.violates ? "Violation" : "Allowed"} (${Math.round((data.tier2.confidence || 0) * 100)}%) &mdash; ${escapeHtml(data.tier2.reason || "")}</div>`
          : `<div><strong>Tier 2:</strong> Bypassed in 0ms (${escapeHtml(data.tier2.reason || "Tier 1 decisive")})</div>`;
        traceBody.innerHTML = `
          <div><strong>Preset:</strong> ${escapeHtml(RUBRIC_PRESET_LABELS[data.preset] || data.preset)} (${threshPct}% threshold)</div>
          <div><strong>Tier 1 (${escapeHtml(data.tier1.model || "primary")}):</strong> ${data.tier1.violates ? "Violation" : "Allowed"} (${t1Pct}%) &mdash; ${escapeHtml(data.tier1.reason || "")}</div>
          ${t2Line}
        `;
      } else {
        setHidden(traceDetails, true);
      }
    }
  } catch (e) {
    console.error("Guest simulation error", e);
    showToast("Network error running live sandbox");
  } finally {
    guestSimInFlight = false;
    if (btn) btn.disabled = false;
    if (btnLabel) btnLabel.textContent = origLabel;
  }
}

async function fetchStatus() {
  if (!currentUser || document.hidden) return;
  try {
    const res = await fetch("/api/status", { credentials: "same-origin" });
    if (!res.ok) return;
    const data = await res.json();
    const commitsEl = document.getElementById("kpi-commits");
    if (commitsEl) commitsEl.innerText = data.stats.commits_received.toLocaleString();
    const matchedEl = document.getElementById("kpi-matched");
    if (matchedEl) matchedEl.innerText = data.stats.interactions_matched.toLocaleString();
    const bypassedEl = document.getElementById("kpi-bypassed");
    if (bypassedEl) {
      bypassedEl.innerText = (
        data.stats.gate_bypassed_followed +
        data.stats.gate_bypassed_self +
        (data.stats.gate_bypassed_follower || 0) +
        (data.stats.gate_bypassed_allowlist || 0)
      ).toLocaleString();
    }
    const dedupEl = document.getElementById("kpi-dedup");
    if (dedupEl) dedupEl.innerText = data.stats.dedup_cache_hits.toLocaleString();

    const tier1Count = data.stats.tier1_evaluations !== undefined ? data.stats.tier1_evaluations : data.stats.model_evaluations;
    const tier2Count = data.stats.tier2_evaluations || 0;
    const tier2Img = data.stats.tier2_image_escalations || 0;
    const tier2Uncert = data.stats.tier2_uncertainty_escalations || 0;

    const t1El = document.getElementById("kpi-tier1-evals");
    if (t1El) t1El.innerText = tier1Count.toLocaleString();

    const t2El = document.getElementById("kpi-tier2-evals");
    if (t2El) t2El.innerText = tier2Count.toLocaleString();

    const t2Sub = document.getElementById("kpi-tier2-sub");
    if (t2Sub) t2Sub.innerText = `${tier2Img.toLocaleString()} Image • ${tier2Uncert.toLocaleString()} Uncertainty`;

    const evalsLegacy = document.getElementById("kpi-evals");
    if (evalsLegacy) evalsLegacy.innerText = data.stats.model_evaluations.toLocaleString();

    const bouncesEl = document.getElementById("kpi-bounces");
    if (bouncesEl) bouncesEl.innerText = data.stats.bounces_executed.toLocaleString();

    const drawerSummary = document.getElementById("drawer-telemetry-summary");
    if (drawerSummary) {
      drawerSummary.innerText = `${data.stats.commits_received.toLocaleString()} commits · ${tier1Count.toLocaleString()} T1 evals · ${data.stats.bounces_executed.toLocaleString()} bounces`;
    }

    const monCard = document.getElementById("kpi-monitored-card");
    if (data.monitored_users_count !== undefined && data.monitored_users_count !== null) {
      setHidden(monCard, false);
      const monVal = document.getElementById("kpi-monitored-val");
      if (monVal) monVal.innerText = data.monitored_users_count.toLocaleString();
    } else if (!currentUser || !currentUser.is_admin) {
      setHidden(monCard, true);
    }

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
      overflowsEl.classList.toggle("kpi-val-danger", overflows > 0);
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
        badge.className = "status-badge badge-warning";
        badge.innerHTML = '<div class="pulse-dot" aria-hidden="true"></div><span>Shadow Mode (Dry Run)</span>';
      }
      const sub = document.getElementById("kpi-bounces-sub");
      if (sub) sub.innerText = "Simulated Bounces (No Writes)";
    }
  } catch (e) {
    console.error("Status fetch failed", e);
  }
}

let activeBounceDuration = "permanent";
let savedRubricState = null;

function updateSummaryBypassLabel(bypassFollowers) {
  const el = document.getElementById("summary-bypass-val");
  if (el) {
    el.innerText = bypassFollowers ? "Following + Followers" : "Following Only";
  }
}

function updateRulesSyncBadge(isDirty) {
  const ind = document.getElementById("rules-sync-indicator");
  const draftBadge = document.getElementById("sim-draft-badge");
  if (ind) {
    if (isDirty) {
      ind.innerText = "● Unsaved Changes";
      ind.className = "status-badge badge-warning";
    } else {
      ind.innerText = "Saved";
      ind.className = "status-badge badge-neutral";
    }
  }
  if (draftBadge) {
    if (isDirty) {
      draftBadge.innerText = "Testing Draft Rules";
      draftBadge.className = "status-badge badge-warning";
    } else {
      draftBadge.innerText = "Dry Run";
      draftBadge.className = "status-badge badge-neutral";
    }
  }
}

function markRulesDirty() {
  const bypassEl = document.getElementById("bypass-followers-toggle");
  const currentBypass = bypassEl ? bypassEl.checked : true;
  updateSummaryBypassLabel(currentBypass);
  if (!savedRubricState) {
    updateRulesSyncBadge(true);
    return;
  }
  const promptEl = document.getElementById("rules-prompt");
  const currentPrompt = promptEl ? promptEl.value : "";
  const isDirty =
    currentPrompt !== savedRubricState.prompt ||
    activeSensitivity !== savedRubricState.sensitivity ||
    activeBounceDuration !== savedRubricState.bounce_duration ||
    currentBypass !== savedRubricState.bypass_incoming_followers;
  updateRulesSyncBadge(isDirty);
}

function setBounceDuration(val, skipDirtyCheck = false) {
  let rawVal = val;
  if (val && typeof val === "object" && val.custom !== undefined) {
    rawVal = String(val.custom);
  }
  let norm = (rawVal ?? "").toString().toLowerCase().trim();
  const customMatch = norm.match(/^(\d+)s$/);
  if (customMatch) {
    norm = customMatch[1];
  }
  const is24h = norm === "cooldown24h" || norm === "cooldown_24h" || norm === "24h" || norm === "1d" || norm === "86400";
  const is7d = norm === "timeout7d" || norm === "timeout_7d" || norm === "7d" || norm === "1w" || norm === "604800";
  const is30d = norm === "timeout30d" || norm === "timeout_30d" || norm === "30d" || norm === "1m" || norm === "2592000";
  const isCustomSecs = !is24h && !is7d && !is30d && /^\d+$/.test(norm) && Number(norm) > 0;
  const isPerm = !is24h && !is7d && !is30d && !isCustomSecs;

  if (is24h) {
    activeBounceDuration = "cooldown24h";
  } else if (is7d) {
    activeBounceDuration = "timeout7d";
  } else if (is30d) {
    activeBounceDuration = "timeout30d";
  } else if (isCustomSecs) {
    activeBounceDuration = Number(norm);
  } else {
    activeBounceDuration = "permanent";
  }

  const permBtn = document.getElementById("dur-perm");
  const b24hBtn = document.getElementById("dur-24h");
  const b7dBtn = document.getElementById("dur-7d");
  const b30dBtn = document.getElementById("dur-30d");

  if (permBtn) {
    permBtn.classList.toggle("active", isPerm);
    permBtn.setAttribute("aria-pressed", String(isPerm));
  }
  if (b24hBtn) {
    b24hBtn.classList.toggle("active", is24h);
    b24hBtn.setAttribute("aria-pressed", String(is24h));
  }
  if (b7dBtn) {
    b7dBtn.classList.toggle("active", is7d);
    b7dBtn.setAttribute("aria-pressed", String(is7d));
  }
  if (b30dBtn) {
    b30dBtn.classList.toggle("active", is30d);
    b30dBtn.setAttribute("aria-pressed", String(is30d));
  }
  if (!skipDirtyCheck) markRulesDirty();
}

function renderRulesAuthenticated(rubric) {
  const unauthBox = document.getElementById("rules-unauth-container");
  const authBox = document.getElementById("rules-auth-container");
  setHidden(unauthBox, true);
  setHidden(authBox, false);
  if (rubric) {
    const promptEl = document.getElementById("rules-prompt");
    if (promptEl) promptEl.value = rubric.prompt || "";
    setSensitivity(rubric.sensitivity || "medium", true);
    setBounceDuration(rubric.bounce_duration || "permanent", true);
    const bypassToggle = document.getElementById("bypass-followers-toggle");
    const bypassEnabled = rubric.bypass_incoming_followers !== false;
    if (bypassToggle) bypassToggle.checked = bypassEnabled;
    updateSummaryBypassLabel(bypassEnabled);
    savedRubricState = {
      prompt: rubric.prompt || "",
      sensitivity: activeSensitivity,
      bounce_duration: activeBounceDuration,
      bypass_incoming_followers: bypassEnabled
    };
    updateRulesSyncBadge(false);
  }
}

function renderRulesUnauthenticated() {
  const unauthBox = document.getElementById("rules-unauth-container");
  const authBox = document.getElementById("rules-auth-container");
  setHidden(unauthBox, false);
  setHidden(authBox, true);
  const promptEl = document.getElementById("rules-prompt");
  if (promptEl) promptEl.value = "";
  const bypassEl = document.getElementById("bypass-followers-toggle");
  if (bypassEl) bypassEl.checked = true;
  savedRubricState = null;
  updateRulesSyncBadge(false);
}

async function loadRules() {
  if (!currentUser || !currentUser.did) {
    renderRulesUnauthenticated();
    return;
  }
  try {
    const res = await fetch("/api/rules", { credentials: "same-origin" });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        renderRulesUnauthenticated();
      }
      return;
    }
    const data = await res.json();
    renderRulesAuthenticated(data);
  } catch (e) {
    console.error("Rules fetch failed", e);
  }
}

function setSensitivity(val, skipDirtyCheck = false) {
  activeSensitivity = val;
  const lowBtn = document.getElementById("sens-low");
  const medBtn = document.getElementById("sens-med");
  const highBtn = document.getElementById("sens-high");
  if (lowBtn) {
    lowBtn.classList.toggle("active", val === "low");
    lowBtn.setAttribute("aria-pressed", String(val === "low"));
  }
  if (medBtn) {
    medBtn.classList.toggle("active", val === "medium");
    medBtn.setAttribute("aria-pressed", String(val === "medium"));
  }
  if (highBtn) {
    highBtn.classList.toggle("active", val === "high");
    highBtn.setAttribute("aria-pressed", String(val === "high"));
  }
  if (!skipDirtyCheck) markRulesDirty();
}

async function saveRules() {
  if (!currentUser || !currentUser.did) {
    showToast("Please sign in to save your moderation rubric");
    return;
  }
  const promptEl = document.getElementById("rules-prompt");
  const prompt = promptEl ? promptEl.value : "";
  const bypassEl = document.getElementById("bypass-followers-toggle");
  const bypassIncomingFollowers = bypassEl ? bypassEl.checked : true;
  try {
    const res = await fetch("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        prompt,
        sensitivity: activeSensitivity,
        bounce_duration: activeBounceDuration,
        bypass_incoming_followers: bypassIncomingFollowers
      })
    });
    if (res.ok) {
      const data = await res.json();
      if (currentUser) {
        currentUser.rubric = data;
      }
      renderRulesAuthenticated(data);
      showToast("House Rules saved");
    } else if (res.status === 401 || res.status === 403) {
      showToast("Permission denied: cannot modify rules");
    } else {
      const err = await res.text();
      showToast(`Failed to save rubric: ${err}`);
    }
  } catch (e) {
    showToast("Network error saving rubric");
  }
}

let simBase64Image = null;

function onSimFileSelected(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  if (file.size > 4 * 1024 * 1024) {
    showToast("Image file exceeds 4MB limit");
    return;
  }
  const reader = new FileReader();
  reader.onload = function(e) {
    const fullDataUrl = e.target.result;
    const commaIdx = fullDataUrl.indexOf(",");
    simBase64Image = commaIdx !== -1 ? fullDataUrl.substring(commaIdx + 1) : fullDataUrl;
    const prevImg = document.getElementById("sim-image-preview");
    if (prevImg) prevImg.src = fullDataUrl;
    const prevLbl = document.getElementById("sim-image-label");
    if (prevLbl) prevLbl.innerText = `Uploaded: ${file.name} (${Math.round(file.size / 1024)} KB)`;
    setHidden(document.getElementById("sim-image-preview-container"), false);
    setHidden(document.getElementById("sim-clear-img-btn"), false);
    const urlInput = document.getElementById("sim-image-url");
    if (urlInput) urlInput.value = "";
  };
  reader.readAsDataURL(file);
}

function onSimImageUrlChange() {
  const urlInput = document.getElementById("sim-image-url");
  const url = urlInput ? urlInput.value.trim() : "";
  if (url.startsWith("http://") || url.startsWith("https://")) {
    simBase64Image = null;
    const prevImg = document.getElementById("sim-image-preview");
    if (prevImg) prevImg.src = url;
    const prevLbl = document.getElementById("sim-image-label");
    if (prevLbl) prevLbl.innerText = `Remote URL: ${url.length > 40 ? url.substring(0, 37) + "..." : url}`;
    setHidden(document.getElementById("sim-image-preview-container"), false);
    setHidden(document.getElementById("sim-clear-img-btn"), false);
  } else if (!url && !simBase64Image) {
    clearSimImage();
  }
}

function clearSimImage() {
  simBase64Image = null;
  const urlInput = document.getElementById("sim-image-url");
  if (urlInput) urlInput.value = "";
  const fileInput = document.getElementById("sim-file-input");
  if (fileInput) fileInput.value = "";
  const prevImg = document.getElementById("sim-image-preview");
  if (prevImg) prevImg.src = "";
  setHidden(document.getElementById("sim-image-preview-container"), true);
  setHidden(document.getElementById("sim-clear-img-btn"), true);
}

function setSimText(text) {
  if (simInFlight) return;
  const el = document.getElementById("sim-text");
  if (el) el.value = text;
  runSimulation();
}

async function runSimulation() {
  if (simInFlight) return;
  const simTextEl = document.getElementById("sim-text");
  const text = simTextEl ? simTextEl.value.trim() : "";
  if (!text) {
    showToast("Please enter sample post text to simulate");
    return;
  }
  if (!currentUser || !currentUser.did) {
    showToast("Please sign in with Bluesky to run interactive evaluations");
    showLoginModal();
    return;
  }

  const payload = { text };
  const draftPromptEl = document.getElementById("rules-prompt");
  if (draftPromptEl && draftPromptEl.value.trim()) {
    payload.draft_prompt = draftPromptEl.value.trim();
    payload.draft_sensitivity = activeSensitivity;
  }
  const imgUrlEl = document.getElementById("sim-image-url");
  const imgUrl = imgUrlEl ? imgUrlEl.value.trim() : "";
  if (simBase64Image) {
    payload.image_base64 = simBase64Image;
  } else if (imgUrl && (imgUrl.startsWith("http://") || imgUrl.startsWith("https://"))) {
    payload.image_url = imgUrl;
  }

  simInFlight = true;
  const evalBtn = document.getElementById("sim-eval-btn");
  const btnLabel = evalBtn ? evalBtn.querySelector(".btn-label") : null;
  const origLabel = btnLabel ? btnLabel.textContent : "Evaluate Post";
  if (evalBtn) evalBtn.disabled = true;
  if (btnLabel) btnLabel.textContent = "Evaluating...";

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      if (res.status === 401) {
        showToast("Please sign in with Bluesky to run interactive evaluations");
        showLoginModal();
      } else {
        const errText = await res.text();
        showToast(`Simulation failed (${res.status}): ${errText || "Unable to evaluate payload"}`);
      }
      return;
    }
    const data = await res.json();

    const box = document.getElementById("sim-result");
    const badge = document.getElementById("sim-badge");
    const bar = document.getElementById("sim-bar");
    const multiNote = document.getElementById("sim-multimodal-note");

    setHidden(box, false);
    const pct = Math.round(data.confidence * 100);
    if (badge && bar) {
      if (data.violates && data.meets_threshold !== false) {
        badge.className = "verdict-badge verdict-violation";
        badge.innerText = `VIOLATION: ${data.category || "Harassment"}`;
        setProgressBar(bar, pct, "danger");
      } else if (data.violates) {
        badge.className = "verdict-badge verdict-permitted";
        badge.innerText = `BELOW THRESHOLD (PERMITTED): ${data.category || "Borderline"}`;
        setProgressBar(bar, pct, "warning");
      } else {
        badge.className = "verdict-badge verdict-permitted";
        badge.innerText = "PERMITTED";
        setProgressBar(bar, pct, "success");
      }
    }

    const simConf = document.getElementById("sim-confidence");
    if (simConf) simConf.innerText = `Confidence: ${pct}% (Threshold: ${Math.round(data.threshold * 100)}%)`;
    const simCat = document.getElementById("sim-category");
    if (simCat) simCat.innerText = `Category: ${data.category || "None"}`;

    const evalEl = document.getElementById("sim-evaluator");
    const evalStr = (data.evaluator || "").toLowerCase();
    if (evalEl) {
      if (evalStr.includes("uncertainty")) {
        evalEl.innerText = "Uncertainty Escalation · Tier 2";
      } else if (evalStr.includes("fallback") || evalStr.includes("vision")) {
        evalEl.innerText = "Vision Fallback · Tier 2 Multimodal";
      } else if (evalStr.includes("heuristic")) {
        evalEl.innerText = "Heuristic Pre-Filter";
      } else if (data.images_evaluated > 0 || evalStr.includes("multimodal")) {
        evalEl.innerText = "Primary Model · Multimodal";
      } else {
        evalEl.innerText = "System-1 Primary · Text";
      }
    }

    if (data.images_evaluated > 0) {
      setHidden(multiNote, false);
      if (multiNote) multiNote.innerText = `Evaluated with ${data.images_evaluated} image payload(s)`;
    } else {
      setHidden(multiNote, true);
    }

    const simReason = document.getElementById("sim-reason");
    if (simReason) simReason.innerText = data.reason;

    const tiersCont = document.getElementById("sim-tiers-container");
    if (data.tier1 && data.tier2) {
      setHidden(tiersCont, false);

      const t1 = data.tier1;
      const t1Model = document.getElementById("sim-tier1-model");
      if (t1Model) t1Model.innerText = `Model: ${t1.model || "nimble"}`;
      const t1Cat = document.getElementById("sim-tier1-cat");
      if (t1Cat) t1Cat.innerText = `Category: ${t1.category || "None"}`;
      const t1Pct = Math.round(t1.confidence * 100);
      const t1Conf = document.getElementById("sim-tier1-conf");
      if (t1Conf) t1Conf.innerText = `Confidence: ${t1Pct}%`;
      const t1Bar = document.getElementById("sim-tier1-bar");
      setProgressBar(t1Bar, t1Pct, "accent");
      const t1Reason = document.getElementById("sim-tier1-reason");
      if (t1Reason) t1Reason.innerText = t1.reason;

      const t1Badge = document.getElementById("sim-tier1-badge");
      const t1Box = document.getElementById("sim-tier1-box");
      if (t1Badge && t1Box) {
        t1Box.classList.remove("tier-warning", "tier-danger", "tier-success", "tier-purple", "tier-muted");
        if (t1.status === "escalated") {
          t1Badge.innerText = "Escalated to Tier 2";
          t1Badge.className = "status-badge badge-warning badge-tier";
          t1Box.classList.add("tier-warning");
        } else if (t1.status === "bypassed") {
          t1Badge.innerText = "Bypassed";
          t1Badge.className = "status-badge badge-neutral badge-tier";
        } else {
          t1Badge.innerText = t1.violates ? "Violation (Resolved)" : "Permitted (Resolved)";
          t1Badge.className = t1.violates ? "status-badge badge-danger badge-tier" : "status-badge badge-success badge-tier";
          t1Box.classList.add(t1.violates ? "tier-danger" : "tier-success");
        }
      }

      const t2 = data.tier2;
      const t2Model = document.getElementById("sim-tier2-model");
      if (t2Model) t2Model.innerText = `Model: ${t2.model || "gemma4:26b"}`;
      const t2Metrics = document.getElementById("sim-tier2-metrics");
      const t2Badge = document.getElementById("sim-tier2-badge");
      const t2Box = document.getElementById("sim-tier2-box");
      const t2Reason = document.getElementById("sim-tier2-reason");

      if (t2Box) t2Box.classList.remove("tier-warning", "tier-danger", "tier-success", "tier-purple", "tier-muted");
      if (t2.status === "resolved") {
        setHidden(t2Metrics, false);
        const t2Cat = document.getElementById("sim-tier2-cat");
        if (t2Cat) t2Cat.innerText = `Category: ${t2.category || "None"}`;
        const t2Pct = Math.round(t2.confidence * 100);
        const t2Conf = document.getElementById("sim-tier2-conf");
        if (t2Conf) t2Conf.innerText = `Confidence: ${t2Pct}%`;
        const t2Bar = document.getElementById("sim-tier2-bar");
        setProgressBar(t2Bar, t2Pct, "purple");
        if (t2Reason) t2Reason.innerText = t2.reason;

        if (t2Badge) {
          t2Badge.innerText = t2.violates ? "Final: Violation" : "Final: Permitted";
          t2Badge.className = t2.violates ? "status-badge badge-danger badge-tier" : "status-badge badge-success badge-tier";
        }
        if (t2Box) t2Box.classList.add("tier-purple");
      } else {
        setHidden(t2Metrics, true);
        if (t2Reason) t2Reason.innerText = t2.reason;
        if (t2Badge) {
          t2Badge.innerText = "Bypassed (0ms)";
          t2Badge.className = "status-badge badge-neutral badge-tier";
        }
        if (t2Box) t2Box.classList.add("tier-muted");
      }
    } else {
      setHidden(tiersCont, true);
    }

    if (currentUser && currentUser.did) {
      loadAdminEvaluations();
    }
  } catch (e) {
    console.error("Simulation failed", e);
    showToast("Network error running simulation");
  } finally {
    simInFlight = false;
    if (evalBtn) evalBtn.disabled = false;
    if (btnLabel) btnLabel.textContent = origLabel;
  }
}

function bskyProfileUrl(actorOrDid) {
  if (!actorOrDid) return "#";
  const clean = String(actorOrDid).trim().replace(/^@/, "");
  if (clean.startsWith("did:")) {
    const sanitized = clean.replace(/[^a-zA-Z0-9:._%-]/g, "");
    return `https://bsky.app/profile/${sanitized}`;
  }
  return `https://bsky.app/profile/${encodeURIComponent(clean)}`;
}

function bskyPostUrl(actor, rkey) {
  if (!actor || !rkey) return "#";
  const profile = bskyProfileUrl(actor);
  const cleanRkey = String(rkey).replace(/[^a-zA-Z0-9._~-]/g, "");
  return `${profile}/post/${encodeURIComponent(cleanRkey)}`;
}

function formatDid(did) {
  if (!did) return "—";
  const clean = String(did).trim();
  if (clean.length > 20) {
    return clean.substring(0, 16) + "...";
  }
  return clean;
}

const didHandleCache = new Map();
const failedDidResolutions = new Map();
const NEGATIVE_RESOLVE_TTL_MS = 5 * 60 * 1000;
const pendingResolutions = new Set();

function isDidNegativelyCached(did) {
  const exp = failedDidResolutions.get(did);
  if (!exp) return false;
  if (Date.now() < exp) return true;
  failedDidResolutions.delete(did);
  return false;
}

function formatAccountCell(did, knownHandle, rawProfileUrl) {
  if (!did) return '<span class="cell-muted-body">—</span>';
  const cleanDid = String(did).trim();
  let handle = (knownHandle && String(knownHandle).trim().length > 0) ? String(knownHandle).trim() : (didHandleCache.get(cleanDid) || null);
  if (handle) {
    handle = handle.replace(/^@/, "");
    didHandleCache.set(cleanDid, handle);
    failedDidResolutions.delete(cleanDid);
  }

  const profileUrl = rawProfileUrl || bskyProfileUrl(handle || cleanDid);
  const shortDid = formatDid(cleanDid);

  if (handle) {
    return `
      <div class="account-cell" data-did="${escapeHtml(cleanDid)}">
        <a href="${escapeHtml(profileUrl)}" target="_blank" rel="noopener noreferrer" class="account-link" title="Open @${escapeHtml(handle)} on Bluesky">
          <span class="account-handle">@${escapeHtml(handle)}</span> &nearr;
        </a>
        <div class="account-did-subtext" title="${escapeHtml(cleanDid)}">
          ${escapeHtml(shortDid)}
        </div>
      </div>
    `;
  }

  return `
    <div class="account-cell" data-did="${escapeHtml(cleanDid)}" data-needs-resolve="true">
      <a href="${escapeHtml(profileUrl)}" target="_blank" rel="noopener noreferrer" class="account-link" title="Open profile on Bluesky">
        <span class="account-handle account-handle-mono">${escapeHtml(shortDid)}</span> &nearr;
      </a>
      <div class="account-did-subtext" title="${escapeHtml(cleanDid)}">
        ${escapeHtml(shortDid)}
      </div>
    </div>
  `;
}

async function resolveDidToHandle(did) {
  if (!did) return null;
  const cleanDid = did.trim();
  if (didHandleCache.has(cleanDid)) {
    return didHandleCache.get(cleanDid);
  }
  if (isDidNegativelyCached(cleanDid)) {
    return null;
  }
  try {
    const res = await fetch(`/api/resolve?did=${encodeURIComponent(cleanDid)}`, { credentials: "same-origin" });
    if (!res.ok) {
      failedDidResolutions.set(cleanDid, Date.now() + NEGATIVE_RESOLVE_TTL_MS);
      return null;
    }
    const data = await res.json();
    if (data && data.handle) {
      const cleanHandle = data.handle.replace(/^@/, "");
      didHandleCache.set(cleanDid, cleanHandle);
      failedDidResolutions.delete(cleanDid);
      return cleanHandle;
    }
    failedDidResolutions.set(cleanDid, Date.now() + NEGATIVE_RESOLVE_TTL_MS);
  } catch (e) {
    failedDidResolutions.set(cleanDid, Date.now() + NEGATIVE_RESOLVE_TTL_MS);
    console.warn("Failed to resolve DID:", cleanDid, e);
  }
  return null;
}

function updateAccountCellsForDid(did, handle) {
  const cleanHandle = handle.replace(/^@/, "");
  const allCells = document.querySelectorAll(".account-cell");
  allCells.forEach(cell => {
    if (cell.getAttribute("data-did") === did) {
      cell.removeAttribute("data-needs-resolve");
      const handleEl = cell.querySelector(".account-handle");
      if (handleEl) {
        handleEl.textContent = `@${cleanHandle}`;
        handleEl.classList.remove("account-handle-mono");
      }
      const linkEl = cell.querySelector("a");
      if (linkEl) {
        linkEl.href = bskyProfileUrl(cleanHandle);
        linkEl.title = `Open @${cleanHandle} on Bluesky`;
      }
    }
  });
}

function enhanceUnresolvedAccountCells(container) {
  if (!container) return;
  const cells = container.querySelectorAll('.account-cell[data-needs-resolve="true"]');
  if (cells.length === 0) return;

  const didsToResolve = new Set();
  cells.forEach(cell => {
    const did = cell.getAttribute("data-did");
    if (did && !pendingResolutions.has(did)) {
      if (didHandleCache.has(did)) {
        updateAccountCellsForDid(did, didHandleCache.get(did));
      } else if (!isDidNegativelyCached(did)) {
        didsToResolve.add(did);
      }
    }
  });

  for (const did of didsToResolve) {
    pendingResolutions.add(did);
    resolveDidToHandle(did).then(handle => {
      pendingResolutions.delete(did);
      if (handle) {
        updateAccountCellsForDid(did, handle);
      }
    }).catch(() => {
      pendingResolutions.delete(did);
    });
  }
}

function formatPostLink(uri, text) {
  if (!uri || uri.trim() === "") {
    return text && text.trim().length > 0
      ? `<div class="expandable-text cell-muted-sm" title="Click to expand/collapse">${escapeHtml(text)}</div>`
      : '<span class="cell-muted-sm">—</span>';
  }

  let bskyUrl = null;
  const match = uri.match(/^at:\/\/([^/]+)\/app\.bsky\.feed\.post\/([^/]+)$/);
  if (match) {
    const [, actor, rkey] = match;
    bskyUrl = bskyPostUrl(actor, rkey);
  }

  const hasText = text && text.trim().length > 0;
  const displayText = hasText
    ? (text.length > 36 ? text.substring(0, 33) + "..." : text)
    : (match ? `Post ${match[2].substring(0, 8)}...` : "View Post");

  if (bskyUrl) {
    return `
      <div class="post-link-col">
        <a href="${escapeHtml(bskyUrl)}" target="_blank" rel="noopener noreferrer" class="post-link-anchor" title="Open offending post on Bluesky">
          <span class="post-link-underline">${escapeHtml(displayText)}</span> &nearr;
        </a>
        ${hasText ? `<div class="expandable-text eval-expandable-sm" title="Click to expand/collapse: ${escapeHtml(text)}">${escapeHtml(text)}</div>` : ""}
      </div>
    `;
  }

  return `<span class="cell-muted-sm" title="${escapeHtml(uri)}">${escapeHtml(displayText)}</span>`;
}

const RUBRIC_PRESETS = {
  balanced: {
    prompt: "Filter blatant spam, automated bot promotions, crypto/NFT shilling, unwanted commercial links, and direct harassment or personal attacks aimed at the protected user. Allow constructive critique, benign banter, standard disagreements, and arguments or hostility directed at other commenters or third parties.",
    sensitivity: "medium"
  },
  anti_crypto: {
    prompt: "Aggressively filter all cryptocurrency, token, airdrop, memecoin, pump-and-dump, web3 wallet, NFT promotions, unsolicited WhatsApp/Telegram investment invitations, and high-frequency automated bot links.",
    sensitivity: "high"
  },
  anti_hostility: {
    prompt: "Strictly filter hostile language, targeted harassment, abusive insults, slurs, doxxing threats, demeaning personal attacks, and aggressive intimidation directed at the protected user (not hostility aimed at other commenters, public figures, or third parties).",
    sensitivity: "high"
  },
  anti_ragebait: {
    prompt: "Filter bad-faith sea-lioning, deceptive ragebait, troll provocations, and bad-faith harassment aimed at the protected user, while permitting debates or arguments between other commenters.",
    sensitivity: "medium"
  }
};

const RUBRIC_PRESET_LABELS = {
  balanced: "Balanced",
  anti_crypto: "Zero Crypto",
  anti_hostility: "Anti-Hostility",
  anti_ragebait: "Anti-Ragebait"
};

function applyRubricPreset(key) {
  const p = RUBRIC_PRESETS[key];
  if (!p) return;
  const label = RUBRIC_PRESET_LABELS[key] || key;
  const promptEl = document.getElementById("rules-prompt");
  if (promptEl && savedRubricState && promptEl.value.trim() !== "" && promptEl.value !== savedRubricState.prompt) {
    const isKnownPreset = Object.values(RUBRIC_PRESETS).some(preset => preset.prompt === promptEl.value);
    if (!isKnownPreset && !confirm(`Replace your unsaved custom prompt with the "${label}" preset?`)) {
      return;
    }
  }
  if (promptEl) promptEl.value = p.prompt;
  setSensitivity(p.sensitivity);
  markRulesDirty();
  showToast(`Loaded "${label}" preset — click Save House Rules to apply`);
}

let allBounces = [];

function onBouncesScopeChange() {
  bouncesOffset = 0;
  const scopeSelect = document.getElementById("bounces-scope-select");
  const scope = scopeSelect ? scopeSelect.value : "mine";
  const titleEl = document.getElementById("bounces-card-title");
  const subEl = document.getElementById("bounces-card-subtitle");
  if (titleEl && subEl) {
    if (scope === "all") {
      titleEl.innerText = "Recently Bounced Violators (Fleet-Wide)";
      subEl.innerText = "Moderation bounces executed across all enrolled tenant accounts";
    } else if (scope === "mine") {
      titleEl.innerText = "Recently Bounced Violators";
      subEl.innerText = "Recently moderated accounts added to your sovereign block list";
    } else {
      const selectedText = scopeSelect.options[scopeSelect.selectedIndex]?.text || scope;
      titleEl.innerText = `Bounced Violators (${selectedText})`;
      subEl.innerText = "Moderation bounces executed for selected tenant";
    }
  }
  loadBounces();
  if (currentUser && currentUser.is_admin) {
    loadStorms();
  }
}

function scheduleFilterBounces() {
  if (filterBouncesTimer) clearTimeout(filterBouncesTimer);
  filterBouncesTimer = setTimeout(filterBounces, 150);
}

function filterBounces() {
  const query = (document.getElementById("bounces-search-input")?.value || "").toLowerCase().trim();
  if (!query) {
    renderBouncesList(allBounces);
    return;
  }
  const filtered = allBounces.filter(b => {
    const handle = b.handle || didHandleCache.get(b.subject_did) || "";
    const targetHandle = b.protected_handle || didHandleCache.get(b.protected_did) || "";
    return (b.subject_did && b.subject_did.toLowerCase().includes(query)) ||
           (handle && handle.toLowerCase().includes(query)) ||
           (b.protected_did && b.protected_did.toLowerCase().includes(query)) ||
           (targetHandle && targetHandle.toLowerCase().includes(query)) ||
           (b.category && b.category.toLowerCase().includes(query)) ||
           (b.reason && b.reason.toLowerCase().includes(query)) ||
           (b.post_text && b.post_text.toLowerCase().includes(query));
  });
  renderBouncesList(filtered);
}

function renderTableError(tbody, colSpan, message, retryTarget) {
  if (!tbody) return;
  tbody.innerHTML = `
    <tr>
      <td colspan="${colSpan}" class="table-empty-cell">
        <div class="table-error-box">
          <span class="table-error-msg">${escapeHtml(message)}</span>
          <button type="button" class="btn btn-secondary btn-sm btn-retry-loader" data-retry-loader="${escapeHtml(retryTarget)}">Retry</button>
        </div>
      </td>
    </tr>
  `;
}

function updatePaginationBar(barId, infoId, prevId, nextId, total, count, offset) {
  const bar = document.getElementById(barId);
  const info = document.getElementById(infoId);
  const prevBtn = document.getElementById(prevId);
  const nextBtn = document.getElementById(nextId);
  if (!bar) return;
  if (total <= PAGE_SIZE && offset === 0) {
    setHidden(bar, true);
    return;
  }
  setHidden(bar, false);
  if (info) {
    if (total > 0 && count === 0) {
      info.innerText = `0 items on this page (of ${total.toLocaleString()})`;
    } else {
      const start = total === 0 ? 0 : offset + 1;
      const end = Math.min(total, offset + count);
      info.innerText = `Showing ${start.toLocaleString()}–${end.toLocaleString()} of ${total.toLocaleString()}`;
    }
  }
  if (prevBtn) prevBtn.disabled = offset <= 0;
  if (nextBtn) nextBtn.disabled = offset + count >= total;
}

function renderBouncesList(bounces) {
  const tbody = document.getElementById("bounces-table");
  if (!tbody) return;

  const scopeSelect = document.getElementById("bounces-scope-select");
  const isFleetScope = scopeSelect && scopeSelect.value === "all";
  const colSpan = isFleetScope ? 7 : 6;

  if (bounces.length === 0) {
    const query = (document.getElementById("bounces-search-input")?.value || "").trim();
    const emptyMsg = query
      ? "No matching bounced accounts found."
      : "All quiet &mdash; no accounts are currently bounced on your ModList.";
    tbody.innerHTML = `<tr><td colspan="${colSpan}" class="table-empty-cell">${emptyMsg}</td></tr>`;
    return;
  }

  tbody.innerHTML = bounces.map(b => {
    if (b.subject_did && b.handle) {
      didHandleCache.set(b.subject_did, b.handle.replace(/^@/, ""));
    }
    if (b.protected_did && b.protected_handle) {
      didHandleCache.set(b.protected_did, b.protected_handle.replace(/^@/, ""));
    }
    const postLinkHtml = formatPostLink(b.post_uri, b.post_text);
    const ttlBadge = b.expires_at
      ? `<span class="status-badge badge-warning badge-xs badge-inline-gap" title="Expires at ${escapeHtml(formatFullDate(b.expires_at) || formatDate(b.expires_at))}">TTL</span>`
      : `<span class="status-badge badge-neutral badge-xs badge-inline-gap">Permanent</span>`;
    const bouncedTitle = b.bounced_at ? ` title="Bounced: ${escapeHtml(formatFullDate(b.bounced_at))}"` : "";
    const targetCellHtml = isFleetScope
      ? `<td>${formatAccountCell(b.protected_did, b.protected_handle)}</td>`
      : "";
    const upgradePermBtnHtml = b.expires_at
      ? `<button type="button" class="btn btn-secondary btn-sm btn-upgrade-perm" data-did="${escapeHtml(b.subject_did)}" data-protected-did="${escapeHtml(b.protected_did || "")}" title="Upgrade temporary block to permanent">Make Permanent</button>`
      : "";

    return `
    <tr>
      <td>${formatAccountCell(b.subject_did, b.handle)}</td>
      ${targetCellHtml}
      <td>${postLinkHtml}</td>
      <td><span class="status-badge badge-danger badge-sm-text"${bouncedTitle}>${escapeHtml(b.category)}</span>${ttlBadge}</td>
      <td class="cell-num"><strong>${Math.round(b.confidence * 100)}%</strong></td>
      <td><div class="expandable-text cell-reason" title="Click to expand/collapse: ${escapeHtml(b.reason)}">${escapeHtml(b.reason)}</div></td>
      <td>
        <div class="cell-actions">
          <button type="button" class="btn btn-danger btn-sm btn-pardon" data-did="${escapeHtml(b.subject_did)}" data-protected-did="${escapeHtml(b.protected_did || "")}" title="Remove from moderation list">Pardon</button>
          <button type="button" class="btn btn-secondary btn-sm btn-pardon-allow" data-did="${escapeHtml(b.subject_did)}" data-protected-did="${escapeHtml(b.protected_did || "")}" title="Pardon and add to allowlist to immunize against future bounces">Pardon &amp; Allow</button>
          ${upgradePermBtnHtml}
        </div>
      </td>
    </tr>
  `;
  }).join("");

  enhanceUnresolvedAccountCells(tbody);
}

async function loadBounces() {
  const ctrl = startLoaderRequest("bounces");
  const scopeSelect = document.getElementById("bounces-scope-select");
  const scope = scopeSelect ? scopeSelect.value : "mine";
  const isFleetScope = scope === "all";
  const colSpan = isFleetScope ? 7 : 6;
  const tbody = document.getElementById("bounces-table");
  const targetHeader = document.getElementById("bounces-target-header");
  setHidden(targetHeader, !isFleetScope);

  try {
    let url = `/api/bounces?limit=${PAGE_SIZE}&offset=${bouncesOffset}`;

    if (currentUser && currentUser.did) {
      if (currentUser.is_admin) {
        if (scope === "mine") {
          url += `&user_did=${encodeURIComponent(currentUser.did)}`;
        } else if (scope !== "all") {
          url += `&user_did=${encodeURIComponent(scope)}`;
        }
      } else {
        url += `&user_did=${encodeURIComponent(currentUser.did)}`;
      }
    }

    const res = await fetch(url, { credentials: "same-origin", signal: ctrl.signal });
    if (!res.ok) {
      if (res.status === 401) {
        if (tbody) {
          tbody.innerHTML = `<tr><td colspan="${colSpan}" class="table-empty-cell">Sign in with Bluesky to view bounced accounts.</td></tr>`;
        }
        return;
      }
      renderTableError(tbody, colSpan, `Failed to load bounces (HTTP ${res.status}).`, "bounces");
      return;
    }
    const payload = await res.json();
    allBounces = Array.isArray(payload) ? payload : (Array.isArray(payload.bounces) ? payload.bounces : []);
    bouncesTotal = Array.isArray(payload) ? allBounces.length : (typeof payload.total === "number" ? payload.total : allBounces.length);

    const tabBouncesEl = document.getElementById("tab-bounces-count");
    if (tabBouncesEl) tabBouncesEl.innerText = bouncesTotal.toLocaleString();
    const sumBouncesEl = document.getElementById("summary-bounces-val");
    if (sumBouncesEl) sumBouncesEl.innerText = bouncesTotal.toLocaleString();

    allBounces.forEach(b => {
      if (b.subject_did && b.handle) {
        didHandleCache.set(b.subject_did, b.handle.replace(/^@/, ""));
      }
      if (b.protected_did && b.protected_handle) {
        didHandleCache.set(b.protected_did, b.protected_handle.replace(/^@/, ""));
      }
    });
    filterBounces();
    updatePaginationBar(
      "bounces-pagination",
      "bounces-page-info",
      "bounces-prev-btn",
      "bounces-next-btn",
      bouncesTotal,
      allBounces.length,
      bouncesOffset
    );
  } catch (e) {
    if (e && e.name === "AbortError") return;
    console.error("Bounces fetch failed", e);
    renderTableError(tbody, colSpan, "Network error loading bounced accounts.", "bounces");
  }
}

async function upgradeBounceToPerm(did, protectedDid) {
  const cachedHandle = didHandleCache.get(did);
  const displayLabel = cachedHandle ? `@${cachedHandle} (${formatDid(did)})` : did;
  let targetLabel = "";
  if (protectedDid && currentUser && protectedDid !== currentUser.did) {
    const cachedTarget = didHandleCache.get(protectedDid);
    targetLabel = cachedTarget ? ` on @${cachedTarget}'s list` : ` on tenant ${formatDid(protectedDid)}'s list`;
  }
  if (!confirm(`Are you sure you want to upgrade the temporary block for ${displayLabel}${targetLabel} to permanent?`)) return;

  try {
    const res = await fetch("/api/bounces/upgrade", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        subject_did: did,
        protected_did: protectedDid || (currentUser ? currentUser.did : undefined)
      })
    });
    if (res.ok) {
      const data = await res.json();
      const toastDisplay = cachedHandle ? `@${cachedHandle}` : did;
      if (data && data.upgraded) {
        showToast(`Upgraded ${toastDisplay} to permanent block`);
      } else {
        showToast((data && data.message) || `${toastDisplay} could not be upgraded`);
      }
      loadBounces();
      fetchStatus();
    } else {
      showToast("Failed to upgrade block to permanent");
    }
  } catch (e) {
    showToast("Network error upgrading block");
  }
}

async function pardonUser(did, protectedDid, allowlist = false) {
  if (typeof protectedDid === "boolean") {
    allowlist = protectedDid;
    protectedDid = null;
  }
  const cachedHandle = didHandleCache.get(did);
  const displayLabel = cachedHandle ? `@${cachedHandle} (${formatDid(did)})` : did;
  let targetLabel = "";
  if (protectedDid && currentUser && protectedDid !== currentUser.did) {
    const cachedTarget = didHandleCache.get(protectedDid);
    targetLabel = cachedTarget ? ` on @${cachedTarget}'s list` : ` on tenant ${formatDid(protectedDid)}'s list`;
  }
  const confirmMsg = allowlist
    ? `Are you sure you want to pardon ${displayLabel}${targetLabel} AND add them to the allowlist (immunize)?`
    : `Are you sure you want to pardon ${displayLabel}${targetLabel} and remove them from the moderation list?`;
  if (!confirm(confirmMsg)) return;

  try {
    const res = await fetch("/api/pardon", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        subject_did: did,
        protected_did: protectedDid || (currentUser ? currentUser.did : undefined),
        allowlist: !!allowlist,
        reason: allowlist ? "Pardoned & allowlisted via Web Dashboard" : undefined
      })
    });
    if (res.ok) {
      const data = await res.json();
      const toastDisplay = cachedHandle ? `@${cachedHandle}` : did;
      if (data && (data.pardoned || data.allowlisted)) {
        showToast(data.allowlisted ? `Pardoned & allowlisted ${toastDisplay}` : `Pardoned ${toastDisplay}`);
      } else {
        showToast((data && data.message) || `${toastDisplay} was not found in bounced cache`);
      }
      loadBounces();
      loadAllowlist();
      fetchStatus();
    } else {
      showToast("Failed to pardon user");
    }
  } catch (e) {
    showToast("Network error pardoning user");
  }
}

async function loadAllowlist() {
  const ctrl = startLoaderRequest("allowlist");
  const tbody = document.getElementById("allowlist-table");
  try {
    const res = await fetch("/api/allowlist", { credentials: "same-origin", signal: ctrl.signal });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) return;
      renderTableError(tbody, 4, `Failed to load allowlist (HTTP ${res.status}).`, "allowlist");
      return;
    }
    const entries = await res.json();
    entries.forEach(e => {
      const did = e.subject_did || e.allowed_did;
      if (did && e.handle) {
        didHandleCache.set(did, e.handle.replace(/^@/, ""));
      }
    });
    const totalEl = document.getElementById("total-allowlisted");
    if (totalEl) totalEl.innerText = entries.length;
    const tabAllowEl = document.getElementById("tab-allowlist-count");
    if (tabAllowEl) tabAllowEl.innerText = entries.length.toLocaleString();
    if (!tbody) return;

    if (entries.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="table-empty-cell">No accounts on your allowlist yet.</td></tr>';
      return;
    }

    tbody.innerHTML = entries.map(e => {
      const did = e.subject_did || e.allowed_did || "";
      const fullDate = formatFullDate(e.created_at);
      return `
        <tr>
          <td>${formatAccountCell(did, e.handle)}</td>
          <td><span class="cell-muted-body">${escapeHtml(e.reason || "No reason specified")}</span></td>
          <td class="cell-date" title="${escapeHtml(fullDate)}">${formatDate(e.created_at)}</td>
          <td>
            <button type="button" class="btn btn-secondary btn-sm btn-allowlist-remove" data-did="${escapeHtml(did)}">Remove</button>
          </td>
        </tr>
      `;
    }).join("");

    enhanceUnresolvedAccountCells(tbody);
  } catch (e) {
    if (e && e.name === "AbortError") return;
    console.error("Allowlist fetch failed", e);
    renderTableError(tbody, 4, "Network error loading allowlist.", "allowlist");
  }
}

async function addAllowlistEntry() {
  const subjectInput = document.getElementById("allowlist-input-subject");
  const reasonInput = document.getElementById("allowlist-input-reason");
  if (!subjectInput || !subjectInput.value.trim()) {
    showToast("Please enter a handle or DID");
    return;
  }
  const subject = subjectInput.value.trim();
  const reason = reasonInput ? reasonInput.value.trim() : "";

  try {
    const res = await fetch("/api/allowlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        subject: subject,
        reason: reason || undefined
      })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.subject_did && data.handle) {
        didHandleCache.set(data.subject_did, data.handle.replace(/^@/, ""));
      }
      const display = data.handle ? `@${data.handle.replace(/^@/, "")}` : data.subject_did;
      showToast(`Added ${display} to allowlist`);
      subjectInput.value = "";
      if (reasonInput) reasonInput.value = "";
      loadAllowlist();
    } else {
      const err = await res.text();
      showToast(`Failed to add: ${err}`);
    }
  } catch (e) {
    showToast("Network error adding to allowlist");
  }
}

async function removeAllowlistEntry(did) {
  const cachedHandle = didHandleCache.get(did);
  const displayLabel = cachedHandle ? `@${cachedHandle} (${formatDid(did)})` : did;
  if (!confirm(`Are you sure you want to remove ${displayLabel} from your allowlist?`)) return;
  try {
    const res = await fetch(`/api/allowlist/${encodeURIComponent(did)}`, {
      method: "DELETE",
      credentials: "same-origin"
    });
    if (res.ok) {
      const data = await res.json();
      const toastDisplay = cachedHandle ? `@${cachedHandle}` : did;
      if (data && data.removed) {
        showToast(`Removed ${toastDisplay} from allowlist`);
      } else {
        showToast((data && data.message) || `${toastDisplay} was not on allowlist`);
      }
      loadAllowlist();
    } else {
      const err = await res.text();
      showToast(`Failed to remove: ${err}`);
    }
  } catch (e) {
    showToast("Network error removing from allowlist");
  }
}

const SAVED_ACCOUNTS_KEY = "skybouncer_saved_accounts";
let loginCurrentView = "input";
let loginPreviousViewBeforeExplainer = "input";
let loginSavedAccountsEditMode = false;
let loginPreviewData = null;
let loginTypeaheadTimer = null;
let loginTypeaheadItems = [];
let loginTypeaheadActiveIndex = -1;

function loadSavedAccounts() {
  try {
    const raw = localStorage.getItem(SAVED_ACCOUNTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(a => a && typeof a.handle === "string" && a.handle.trim().length > 0);
  } catch (e) {
    return [];
  }
}

function saveAccountToStorage(acct) {
  if (!acct || !acct.handle) return;
  try {
    const cleanHandle = String(acct.handle).trim().replace(/^@/, "").toLowerCase();
    if (!cleanHandle) return;
    const all = loadSavedAccounts();
    const existing = all.find(
      a => (acct.did && a.did === acct.did) || a.handle.toLowerCase() === cleanHandle
    );
    const list = all.filter(
      a => a.handle.toLowerCase() !== cleanHandle && (!acct.did || a.did !== acct.did)
    );
    list.unshift({
      did: acct.did || (existing && existing.did) || "",
      handle: cleanHandle,
      displayName: acct.displayName || acct.display_name || (existing && existing.displayName) || "",
      avatar: acct.avatar || (existing && existing.avatar) || "",
      pdsHost: acct.pdsHost || acct.pds_host || (existing && existing.pdsHost) || "bsky.social",
      lastUsed: Date.now()
    });
    localStorage.setItem(SAVED_ACCOUNTS_KEY, JSON.stringify(list.slice(0, 6)));
  } catch (e) {
    console.warn("Failed to persist saved account", e);
  }
}

function removeSavedAccount(handleOrDid, evt) {
  if (evt) {
    evt.stopPropagation();
    evt.preventDefault();
  }
  try {
    const target = String(handleOrDid || "").trim().toLowerCase();
    const remaining = loadSavedAccounts().filter(
      a => a.handle.toLowerCase() !== target && (a.did || "").toLowerCase() !== target
    );
    localStorage.setItem(SAVED_ACCOUNTS_KEY, JSON.stringify(remaining));
    if (remaining.length === 0) {
      loginSavedAccountsEditMode = false;
      showLoginInputView();
    } else {
      renderSavedAccountsList();
    }
  } catch (e) {
    console.warn("Failed to remove saved account", e);
  }
}

function normalizeUserHandleClient(raw) {
  const clean = String(raw || "").trim().replace(/^@+/, "").trim();
  if (!clean) return { normalized: "", assumedBsky: false };
  if (clean.startsWith("did:") || clean.includes(".")) {
    return { normalized: clean.toLowerCase(), assumedBsky: false };
  }
  const lower = clean.toLowerCase();
  const reserved = ["localhost", "local", "invalid", "internal", "example", "alt", "arpa", "onion"];
  if (reserved.includes(lower) || /^\d+$/.test(lower)) {
    return { normalized: lower, assumedBsky: false };
  }
  return { normalized: `${lower}.bsky.social`, assumedBsky: true };
}

function setLoginError(msg) {
  const banner = document.getElementById("login-error-banner");
  if (!banner) return;
  if (msg) {
    banner.innerText = msg;
    setHidden(banner, false);
  } else {
    banner.innerText = "";
    setHidden(banner, true);
  }
}

function setLoginModalView(viewName) {
  loginCurrentView = viewName;
  const views = ["saved", "input", "confirm", "explainer"];
  views.forEach(v => {
    const el = document.getElementById(`login-view-${v}`);
    setHidden(el, v !== viewName);
  });
  const titleEl = document.getElementById("login-modal-title");
  if (titleEl) {
    const labelEl = titleEl.querySelector("span") || titleEl;
    if (viewName === "saved") {
      labelEl.innerText = "Welcome back";
    } else if (viewName === "confirm") {
      labelEl.innerText = "Is this you?";
    } else if (viewName === "explainer") {
      labelEl.innerText = "How signing in works";
    } else {
      labelEl.innerText = "Sign In with Bluesky";
    }
  }
  const backToSavedBtn = document.getElementById("login-back-to-saved-btn");
  if (backToSavedBtn) {
    const hasSaved = loadSavedAccounts().length > 0;
    setHidden(backToSavedBtn, !(viewName === "input" && hasSaved));
  }
  hideLoginTypeahead();
}

function renderSavedAccountsList() {
  const container = document.getElementById("login-saved-accounts-list");
  const editBtn = document.getElementById("login-saved-edit-btn");
  if (!container) return;
  const accounts = loadSavedAccounts();
  if (editBtn) {
    editBtn.innerText = loginSavedAccountsEditMode ? "Done" : "Edit";
  }
  container.innerHTML = accounts.map(acct => {
    const handle = acct.handle.replace(/^@/, "");
    const display = acct.displayName || `@${handle}`;
    const sub = acct.displayName ? `@${handle}` : (acct.pdsHost || "bsky.social");
    const initial = (handle[0] || "@").toUpperCase();
    const avatarHtml = acct.avatar
      ? `<img src="${escapeHtml(acct.avatar)}" alt="" class="saved-account-avatar-img" />`
      : `<div class="saved-account-avatar-fallback" aria-hidden="true">${escapeHtml(initial)}</div>`;
    const rightAction = loginSavedAccountsEditMode
      ? `<button type="button" class="btn-forget-saved-acct" data-handle="${escapeHtml(handle)}" title="Forget account on this device" aria-label="Forget @${escapeHtml(handle)} on this device">&times;</button>`
      : "";

    return `
      <div class="saved-account-item">
        <button type="button" class="saved-account-btn" data-handle="${escapeHtml(handle)}">
          ${avatarHtml}
          <div class="saved-account-meta">
            <div class="saved-account-display">${escapeHtml(display)}</div>
            <div class="saved-account-sub">${escapeHtml(sub)}</div>
          </div>
          <span class="saved-account-arrow" aria-hidden="true">&rarr;</span>
        </button>
        ${rightAction}
      </div>
    `;
  }).join("");
}

function toggleSavedAccountsEditMode() {
  loginSavedAccountsEditMode = !loginSavedAccountsEditMode;
  renderSavedAccountsList();
}

function showSavedAccountsView() {
  setLoginError(null);
  loginSavedAccountsEditMode = false;
  renderSavedAccountsList();
  setLoginModalView("saved");
}

function showLoginInputView(focusInput = true) {
  setLoginError(null);
  const submitBtn = document.getElementById("login-submit-btn");
  if (submitBtn) {
    submitBtn.disabled = false;
    submitBtn.innerHTML = "Continue &rarr;";
  }
  setLoginModalView("input");
  const input = document.getElementById("login-handle-input");
  if (input) {
    updateBareHandleHint(input.value);
    if (focusInput) {
      setTimeout(() => input.focus(), 40);
    }
  }
}

function toggleLoginExplainer() {
  if (loginCurrentView === "explainer") {
    closeLoginExplainer();
  } else {
    loginPreviousViewBeforeExplainer = loginCurrentView;
    setLoginModalView("explainer");
  }
}

function closeLoginExplainer() {
  setLoginModalView(loginPreviousViewBeforeExplainer || "input");
}

function updateBareHandleHint(rawVal) {
  const hintEl = document.getElementById("login-bare-handle-hint");
  const previewEl = document.getElementById("login-bare-handle-preview");
  if (!hintEl || !previewEl) return;
  const { normalized, assumedBsky } = normalizeUserHandleClient(rawVal);
  if (assumedBsky && normalized) {
    previewEl.innerText = `@${normalized}`;
    setHidden(hintEl, false);
  } else {
    setHidden(hintEl, true);
  }
}

function hideLoginTypeahead() {
  const listEl = document.getElementById("login-typeahead-list");
  if (listEl) {
    setHidden(listEl, true);
    listEl.innerHTML = "";
  }
  const input = document.getElementById("login-handle-input");
  if (input) {
    input.setAttribute("aria-expanded", "false");
    input.removeAttribute("aria-activedescendant");
  }
  loginTypeaheadItems = [];
  loginTypeaheadActiveIndex = -1;
}

function renderLoginTypeahead(actors) {
  const listEl = document.getElementById("login-typeahead-list");
  const input = document.getElementById("login-handle-input");
  if (!listEl) return;
  loginTypeaheadItems = Array.isArray(actors) ? actors : [];
  loginTypeaheadActiveIndex = -1;
  if (loginTypeaheadItems.length === 0) {
    hideLoginTypeahead();
    return;
  }

  listEl.innerHTML = loginTypeaheadItems.map((actor, idx) => {
    const handle = String(actor.handle || "").replace(/^@/, "");
    const displayName = actor.display_name || actor.displayName || "";
    const initial = (handle[0] || "@").toUpperCase();
    const avatarHtml = actor.avatar
      ? `<img src="${escapeHtml(actor.avatar)}" alt="" class="typeahead-avatar-img" />`
      : `<div class="typeahead-avatar-fallback" aria-hidden="true">${escapeHtml(initial)}</div>`;
    return `
      <div id="login-typeahead-opt-${idx}" class="login-typeahead-item" role="option" aria-selected="false" data-index="${idx}" data-handle="${escapeHtml(handle)}">
        ${avatarHtml}
        <div class="typeahead-meta">
          ${displayName ? `<div class="typeahead-display-name">${escapeHtml(displayName)}</div>` : ""}
          <div class="typeahead-handle">@${escapeHtml(handle)}</div>
        </div>
      </div>
    `;
  }).join("");

  setHidden(listEl, false);
  if (input) {
    input.setAttribute("aria-expanded", "true");
    input.removeAttribute("aria-activedescendant");
  }
}

function selectTypeaheadItem(idx) {
  const actor = loginTypeaheadItems[idx];
  if (!actor || !actor.handle) return;
  const input = document.getElementById("login-handle-input");
  if (input) {
    input.value = actor.handle;
    updateBareHandleHint(actor.handle);
  }
  hideLoginTypeahead();
  previewAndConfirmAccount(actor.handle, actor);
}

function onLoginHandleInput(evt) {
  const raw = evt.target.value || "";
  setLoginError(null);
  updateBareHandleHint(raw);
  if (loginTypeaheadTimer) clearTimeout(loginTypeaheadTimer);
  const clean = raw.trim().replace(/^@+/, "");
  if (clean.length < 2 || clean.startsWith("did:")) {
    hideLoginTypeahead();
    return;
  }
  loginTypeaheadTimer = setTimeout(async () => {
    try {
      const res = await fetch(`/api/auth/typeahead?q=${encodeURIComponent(clean)}&limit=6`, { credentials: "same-origin" });
      if (!res.ok) return;
      const data = await res.json();
      const currentInput = document.getElementById("login-handle-input");
      if (currentInput && currentInput.value.trim().replace(/^@+/, "") === clean && loginCurrentView === "input") {
        renderLoginTypeahead(data.actors || []);
      }
    } catch (_) {
      // Non-blocking typeahead
    }
  }, 180);
}

function onLoginHandleKeydown(evt) {
  const listEl = document.getElementById("login-typeahead-list");
  const isOpen = listEl && !listEl.classList.contains("is-hidden") && loginTypeaheadItems.length > 0;
  if (!isOpen) return;

  if (evt.key === "Escape") {
    evt.preventDefault();
    evt.stopPropagation();
    hideLoginTypeahead();
  } else if (evt.key === "ArrowDown") {
    evt.preventDefault();
    loginTypeaheadActiveIndex = (loginTypeaheadActiveIndex + 1) % loginTypeaheadItems.length;
    highlightTypeaheadIndex();
  } else if (evt.key === "ArrowUp") {
    evt.preventDefault();
    loginTypeaheadActiveIndex = (loginTypeaheadActiveIndex - 1 + loginTypeaheadItems.length) % loginTypeaheadItems.length;
    highlightTypeaheadIndex();
  } else if (evt.key === "Enter" && loginTypeaheadActiveIndex >= 0) {
    evt.preventDefault();
    selectTypeaheadItem(loginTypeaheadActiveIndex);
  }
}

function highlightTypeaheadIndex() {
  const listEl = document.getElementById("login-typeahead-list");
  const input = document.getElementById("login-handle-input");
  if (!listEl) return;
  const items = listEl.querySelectorAll(".login-typeahead-item");
  let activeId = "";
  items.forEach((el, idx) => {
    const isSel = idx === loginTypeaheadActiveIndex;
    el.classList.toggle("is-active", isSel);
    el.setAttribute("aria-selected", String(isSel));
    if (isSel) activeId = el.id;
  });
  if (input) {
    if (activeId) {
      input.setAttribute("aria-activedescendant", activeId);
    } else {
      input.removeAttribute("aria-activedescendant");
    }
  }
}

async function previewAndConfirmAccount(rawHandleOrDid, seedActor = null) {
  const { normalized } = normalizeUserHandleClient(rawHandleOrDid);
  if (!normalized) return;

  setLoginError(null);
  hideLoginTypeahead();
  const submitBtn = document.getElementById("login-submit-btn");
  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerText = "Looking up account...";
  }

  try {
    const res = await fetch(`/api/auth/preview?handle=${encodeURIComponent(normalized)}`, { credentials: "same-origin" });
    if (res.ok) {
      const preview = await res.json();
      showLoginConfirmationView({
        did: preview.did || (seedActor && seedActor.did) || "",
        handle: (preview.handle || normalized).replace(/^@/, ""),
        displayName: preview.display_name || (seedActor && (seedActor.display_name || seedActor.displayName)) || "",
        avatar: preview.avatar || (seedActor && seedActor.avatar) || "",
        pdsHost: preview.pds_host || "bsky.social",
        authServerHost: preview.auth_server_host || preview.pds_host || "bsky.social"
      });
      return;
    }
    const errText = await res.text();
    setLoginError(errText || `Could not find account '${normalized}'. Please check the handle and try again.`);
  } catch (e) {
    if (seedActor && (seedActor.did || seedActor.handle)) {
      showLoginConfirmationView({
        did: seedActor.did || "",
        handle: (seedActor.handle || normalized).replace(/^@/, ""),
        displayName: seedActor.display_name || seedActor.displayName || "",
        avatar: seedActor.avatar || "",
        pdsHost: seedActor.pdsHost || "bsky.social",
        authServerHost: seedActor.authServerHost || seedActor.pdsHost || "bsky.social"
      });
      return;
    }
    setLoginError(`Could not reach server to verify '${normalized}'. Please check your connection and try again.`);
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = "Continue &rarr;";
    }
  }
}

function showLoginConfirmationView(info) {
  loginPreviewData = info;
  const avatarImg = document.getElementById("login-confirm-avatar");
  const avatarFallback = document.getElementById("login-confirm-avatar-fallback");
  const nameEl = document.getElementById("login-confirm-display-name");
  const handleEl = document.getElementById("login-confirm-handle");
  const didEl = document.getElementById("login-confirm-did");
  const providerEl = document.getElementById("login-confirm-provider");
  const continueBtn = document.getElementById("login-confirm-continue-btn");
  const steppingBox = document.getElementById("login-stepping-out-box");

  const cleanHandle = (info.handle || "").replace(/^@/, "");
  const providerHost = info.pdsHost || info.authServerHost || "bsky.social";

  if (avatarImg && avatarFallback) {
    if (info.avatar) {
      avatarImg.src = info.avatar;
      setHidden(avatarImg, false);
      setHidden(avatarFallback, true);
    } else {
      avatarImg.src = "";
      setHidden(avatarImg, true);
      setHidden(avatarFallback, false);
      avatarFallback.innerText = (cleanHandle[0] || "@").toUpperCase();
    }
  }
  if (nameEl) {
    nameEl.innerText = info.displayName || `@${cleanHandle}`;
  }
  if (handleEl) {
    handleEl.innerText = `@${cleanHandle}`;
  }
  if (didEl) {
    didEl.innerText = info.did || "";
    setHidden(didEl, !info.did);
  }
  if (providerEl) {
    providerEl.innerText = providerHost;
  }
  setHidden(steppingBox, true);
  if (continueBtn) {
    continueBtn.disabled = false;
    continueBtn.innerHTML = `Continue to ${escapeHtml(providerHost)} &rarr;`;
  }

  setLoginModalView("confirm");
}

function proceedConfirmedLogin() {
  if (!loginPreviewData || !loginPreviewData.handle) return;
  saveAccountToStorage(loginPreviewData);
  const providerHost = loginPreviewData.pdsHost || loginPreviewData.authServerHost || "bsky.social";
  const steppingBox = document.getElementById("login-stepping-out-box");
  const steppingTitle = document.getElementById("login-stepping-out-title");
  const continueBtn = document.getElementById("login-confirm-continue-btn");
  if (steppingTitle) {
    steppingTitle.innerText = `Stepping out to ${providerHost}…`;
  }
  setHidden(steppingBox, false);
  if (continueBtn) {
    continueBtn.disabled = true;
    continueBtn.innerText = `Connecting to ${providerHost}…`;
  }
  const targetHandle = loginPreviewData.handle.replace(/^@/, "");
  window.location.href = `/oauth/login?handle=${encodeURIComponent(targetHandle)}`;
}

function showLoginModal() {
  const modal = document.getElementById("login-modal");
  if (modal) {
    setLoginError(null);
    const input = document.getElementById("login-handle-input");
    if (input) {
      input.value = "";
      updateBareHandleHint("");
    }
    const saved = loadSavedAccounts();
    if (saved.length > 0) {
      showSavedAccountsView();
    } else {
      showLoginInputView(false);
    }
    if (!modal.open && typeof modal.showModal === "function") {
      modal.showModal();
    } else if (!modal.open) {
      modal.setAttribute("open", "");
    }
    if (saved.length === 0 && input) {
      setTimeout(() => input.focus(), 40);
    }
  } else {
    const handle = prompt("Enter your Bluesky or AT Protocol handle to sign in (e.g. alice or alice.bsky.social):");
    if (handle && handle.trim()) {
      const { normalized } = normalizeUserHandleClient(handle);
      window.location.href = `/oauth/login?handle=${encodeURIComponent(normalized)}`;
    }
  }
}

function closeLoginModal() {
  hideLoginTypeahead();
  const modal = document.getElementById("login-modal");
  if (modal && modal.open && typeof modal.close === "function") {
    modal.close();
  } else if (modal) {
    modal.removeAttribute("open");
  }
}

function handleLoginSubmit(e) {
  e.preventDefault();
  const input = document.getElementById("login-handle-input");
  if (input && input.value.trim()) {
    previewAndConfirmAccount(input.value.trim());
  }
}

function showToast(msg) {
  const t = document.getElementById("toast");
  if (!t) return;
  if (toastTimer) clearTimeout(toastTimer);
  t.innerText = msg;
  t.classList.add("show");
  toastTimer = setTimeout(() => {
    t.classList.remove("show");
    toastTimer = null;
  }, 3000);
}

function escapeHtml(str) {
  return (str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

let currentUser = null;

async function checkUserSession() {
  const params = new URLSearchParams(window.location.search);
  if (params.get("auth") === "success") {
    showToast("Authenticated with Bluesky");
    window.history.replaceState({}, document.title, window.location.pathname);
  } else if (params.get("auth") === "error") {
    const err = params.get("error") || params.get("reason") || "Authentication failed";
    showToast(`Auth error: ${err}`);
    window.history.replaceState({}, document.title, window.location.pathname);
  } else if (params.get("auth") === "login") {
    window.history.replaceState({}, document.title, window.location.pathname);
    setTimeout(() => showLoginModal(), 50);
  }

  try {
    const res = await fetch("/api/me", { credentials: "same-origin" });
    if (!res.ok) {
      renderUnauthenticated();
      return;
    }
    const data = await res.json();
    if (data.authenticated) {
      currentUser = data;
      if (data.handle) {
        saveAccountToStorage({
          did: data.did || "",
          handle: data.handle
        });
      }
      renderAuthenticated(data);
      renderRulesAuthenticated(data.rubric);
      fetchStatus();

      const allowlistCard = document.getElementById("allowlist-card");
      if (allowlistCard) {
        setHidden(allowlistCard, false);
        loadAllowlist();
      }

      const evalCard = document.getElementById("admin-eval-card");
      if (evalCard) {
        setHidden(evalCard, false);
        const titleEl = document.getElementById("eval-card-title");
        if (titleEl) {
          titleEl.innerText = data.is_admin
            ? "Multi-Tenant Evaluation Audit Log (Admin)"
            : "Your Interaction Evaluation Log";
        }
        loadAdminEvaluations();
      }

      const adminCard = document.getElementById("admin-fleet-card");
      if (data.is_admin) {
        setHidden(adminCard, false);
        loadAdminTenants();
      } else {
        setHidden(adminCard, true);
      }

      const bouncesScope = document.getElementById("bounces-admin-scope-container");
      setHidden(bouncesScope, !data.is_admin);
      const stormsCard = document.getElementById("storms-card");
      setHidden(stormsCard, false);
      loadBounces();
      loadStorms();
    } else {
      currentUser = null;
      renderUnauthenticated();
    }
  } catch (e) {
    console.error("Session check failed", e);
    renderUnauthenticated();
  }
}

function renderAuthenticated(user) {
  setHidden(document.getElementById("onboarding-view"), true);
  setHidden(document.getElementById("workspace-view"), false);
  setHidden(document.getElementById("unauth-telemetry-note"), true);

  const container = document.getElementById("auth-header-container");
  if (!container) return;
  const displayName = user.handle ? `@${user.handle}` : (user.did ? user.did.substring(0, 16) + "..." : "Authenticated");
  const roleBadgeHtml = user.is_admin
    ? '<span class="status-badge badge-warning badge-xs">Admin</span>'
    : '<span class="status-badge badge-accent badge-xs">Tenant</span>';

  container.innerHTML = `
    <div class="auth-user-pill">
      <span class="auth-user-handle">${escapeHtml(displayName)}</span>
      ${roleBadgeHtml}
    </div>
    <button type="button" class="btn btn-secondary btn-sm" data-action="sign-out">Sign Out</button>
  `;

  setHidden(document.getElementById("tenant-banner-card"), false);

  const bannerName = document.getElementById("tenant-banner-name");
  if (bannerName) bannerName.innerText = user.handle ? `@${user.handle}` : (user.did || "Sovereign Account");

  const roleBadge = document.getElementById("tenant-role-badge");
  if (roleBadge) {
    if (user.is_admin) {
      roleBadge.innerText = "Fleet Administrator";
      roleBadge.className = "status-badge badge-warning";
    } else {
      roleBadge.innerText = "Protected Tenant";
      roleBadge.className = "status-badge badge-accent";
    }
  }

  const adminCard = document.getElementById("admin-fleet-card");
  const monCard = document.getElementById("kpi-monitored-card");
  if (user.is_admin) {
    setHidden(adminCard, false);
    setHidden(monCard, false);
    if (user.monitored_users_count !== undefined) {
      const monVal = document.getElementById("kpi-monitored-val");
      if (monVal) monVal.innerText = user.monitored_users_count.toLocaleString();
    }
  } else {
    setHidden(adminCard, true);
    setHidden(monCard, true);
  }

  const statusBadge = document.getElementById("tenant-status-badge");
  const toggleBtn = document.getElementById("tenant-toggle-btn");
  const sumProtVal = document.getElementById("summary-protection-val");
  const sumProtSub = document.getElementById("summary-protection-sub");
  if (statusBadge && toggleBtn) {
    if (user.is_active) {
      statusBadge.innerText = "Defenses Active";
      statusBadge.className = "status-badge badge-success";
      toggleBtn.innerText = "Pause Defenses";
      toggleBtn.className = "btn btn-secondary btn-sm";
      if (sumProtVal) {
        sumProtVal.innerText = "Active";
        sumProtVal.classList.add("val-success");
        sumProtVal.classList.remove("val-warning");
      }
      if (sumProtSub) sumProtSub.innerText = "Monitoring replies, mentions & quotes";
    } else {
      statusBadge.innerText = "Defenses Paused";
      statusBadge.className = "status-badge badge-warning";
      toggleBtn.innerText = "Resume Defenses";
      toggleBtn.className = "btn btn-sm";
      if (sumProtVal) {
        sumProtVal.innerText = "Paused";
        sumProtVal.classList.add("val-warning");
        sumProtVal.classList.remove("val-success");
      }
      if (sumProtSub) sumProtSub.innerText = "Inbound moderation temporarily paused";
    }
  }

  const didDisplay = document.getElementById("tenant-did-display");
  if (didDisplay) didDisplay.innerText = user.did || "";

  const blockBadge = document.getElementById("tenant-block-badge");
  if (blockBadge) {
    if (user.is_list_blocked) {
      setHidden(blockBadge, false);
      blockBadge.innerText = "Auto-Block Active";
      blockBadge.className = "status-badge badge-success";
    } else {
      setHidden(blockBadge, true);
    }
  }

  const modContainer = document.getElementById("tenant-modlist-link-container");
  if (modContainer) {
    if (user.mod_list_uri) {
      const webUrl = formatModListUrl(user.mod_list_uri);
      const blockNote = user.is_list_blocked ? " • Auto-Block Active on Bluesky" : "";
      if (webUrl) {
        modContainer.innerHTML = `<a href="${escapeHtml(webUrl)}" target="_blank" rel="noopener noreferrer" class="modlist-link">Mod List &nearr;</a><span class="modlist-inline-note">${escapeHtml(blockNote)}</span>`;
      } else {
        modContainer.innerHTML = `<code class="mono-pill">${escapeHtml(user.mod_list_uri)}</code><span class="modlist-inline-note">${escapeHtml(blockNote)}</span>`;
      }
    } else {
      modContainer.innerHTML = `<span class="modlist-inline-note">Mod list auto-provisions on first bounce</span>`;
    }
  }
}

function renderUnauthenticated() {
  setHidden(document.getElementById("onboarding-view"), false);
  setHidden(document.getElementById("workspace-view"), true);
  const opDrawer = document.getElementById("operator-drawer");
  if (opDrawer) opDrawer.open = false;
  switchWorkspaceTab("activity");

  setHidden(document.getElementById("unauth-telemetry-note"), false);
  const container = document.getElementById("auth-header-container");
  if (container) {
    container.innerHTML = `
      <button type="button" class="btn btn-sm" data-action="open-login">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/>
        </svg>
        Sign In with Bluesky
      </button>
    `;
  }
  setHidden(document.getElementById("tenant-banner-card"), true);
  setHidden(document.getElementById("admin-fleet-card"), true);
  setHidden(document.getElementById("allowlist-card"), true);
  setHidden(document.getElementById("admin-eval-card"), true);
  setHidden(document.getElementById("kpi-monitored-card"), true);
  setHidden(document.getElementById("storms-card"), true);
  setHidden(document.getElementById("active-storm-banner"), true);
  setHidden(document.getElementById("bounces-admin-scope-container"), true);
  setHidden(document.getElementById("bounces-target-header"), true);
  setHidden(document.getElementById("bounces-pagination"), true);
  setHidden(document.getElementById("evals-pagination"), true);
  renderRulesUnauthenticated();
}

async function signOut() {
  try {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  } catch (e) {
    console.error("Logout request error", e);
  }
  localStorage.removeItem("skybouncer_did");
  currentUser = null;
  allBounces = [];
  bouncesOffset = 0;
  bouncesTotal = 0;
  evalsOffset = 0;
  evalsTotal = 0;
  allStorms = [];
  stormModeActiveState = false;
  currentBannerStorm = null;
  const stormsList = document.getElementById("storms-list");
  if (stormsList) stormsList.innerHTML = "";
  const tabBouncesEl = document.getElementById("tab-bounces-count");
  if (tabBouncesEl) tabBouncesEl.innerText = "0";
  const tabAllowEl = document.getElementById("tab-allowlist-count");
  if (tabAllowEl) tabAllowEl.innerText = "0";
  const sumBouncesEl = document.getElementById("summary-bounces-val");
  if (sumBouncesEl) sumBouncesEl.innerText = "0";
  const scopeSelect = document.getElementById("bounces-scope-select");
  if (scopeSelect) scopeSelect.value = "mine";
  renderUnauthenticated();
  renderRulesUnauthenticated();
  showToast("Signed out");
}

async function toggleCurrentTenantDefense() {
  if (!currentUser) return;
  const targetActive = !currentUser.is_active;

  try {
    const res = await fetch("/api/tenant/toggle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ is_active: targetActive })
    });
    if (res.ok) {
      const data = await res.json();
      showToast(data.is_active ? "Defenses resumed" : "Defenses paused");
      currentUser.is_active = data.is_active;
      renderAuthenticated(currentUser);
      if (currentUser.is_admin) {
        loadAdminTenants();
      }
    } else {
      const err = await res.text();
      showToast(`Error: ${err}`);
    }
  } catch (e) {
    showToast("Network error toggling defense");
  }
}

async function loadAdminTenants() {
  const ctrl = startLoaderRequest("tenants");
  const tbody = document.getElementById("admin-tenants-table");
  try {
    const res = await fetch("/api/admin/tenants", { credentials: "same-origin", signal: ctrl.signal });
    if (!res.ok) {
      if (res.status === 403 || res.status === 401) {
        setHidden(document.getElementById("admin-fleet-card"), true);
        return;
      }
      renderTableError(tbody, 6, `Failed to load tenant fleet (HTTP ${res.status}).`, "tenants");
      return;
    }
    const data = await res.json();
    if (data.tenants) {
      data.tenants.forEach(t => {
        if (t.did && t.handle) {
          didHandleCache.set(t.did, t.handle.replace(/^@/, ""));
        }
      });

      const scopeSelect = document.getElementById("bounces-scope-select");
      if (scopeSelect) {
        const currentVal = scopeSelect.value;
        let opts = '<option value="mine">My Bounces Only</option><option value="all">Fleet-Wide (All Tenants)</option>';
        data.tenants.forEach(t => {
          const label = t.handle ? `@${t.handle.replace(/^@/, "")}` : (t.did.substring(0, 16) + "...");
          opts += `<option value="${escapeHtml(t.did)}">Tenant: ${escapeHtml(label)}</option>`;
        });
        scopeSelect.innerHTML = opts;
        if (Array.from(scopeSelect.options).some(o => o.value === currentVal)) {
          scopeSelect.value = currentVal;
        }
      }
    }
    const totalEl = document.getElementById("admin-total-tenants");
    if (totalEl) totalEl.innerText = data.total;
    const activeEl = document.getElementById("admin-active-tenants");
    if (activeEl) activeEl.innerText = data.active_count;
    const pausedEl = document.getElementById("admin-paused-tenants");
    if (pausedEl) pausedEl.innerText = data.paused_count;
    const kpiMonVal = document.getElementById("kpi-monitored-val");
    if (kpiMonVal && data.monitored_count !== undefined) {
      kpiMonVal.innerText = data.monitored_count.toLocaleString();
    }

    if (!tbody) return;

    if (data.tenants.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="table-empty-cell">No tenants enrolled in fleet yet.</td></tr>';
      return;
    }

    tbody.innerHTML = data.tenants.map(t => {
      const statusBadge = t.is_active
        ? '<span class="status-badge badge-success badge-sm-text">Active</span>'
        : '<span class="status-badge badge-warning badge-sm-text">Paused</span>';
      const sessionBadge = t.has_session
        ? '<span class="session-connected">● OAuth Connected</span>'
        : '<span class="cell-muted-sm">○ Service Token</span>';
      let modLink = '<span class="cell-muted-sm">Pending</span>';
      if (t.mod_list_uri) {
        const listUrl = formatModListUrl(t.mod_list_uri);
        modLink = listUrl
          ? `<a href="${escapeHtml(listUrl)}" target="_blank" rel="noopener noreferrer" class="modlist-link">List &nearr;</a>`
          : `<code class="mono-pill mono-pill-sm">${escapeHtml(t.mod_list_uri)}</code>`;
      }
      const toggleAction = t.is_active
        ? `<button type="button" class="btn btn-secondary btn-sm btn-tenant-toggle" data-did="${escapeHtml(t.did)}" data-active="false">Pause</button>`
        : `<button type="button" class="btn btn-sm btn-tenant-toggle" data-did="${escapeHtml(t.did)}" data-active="true">Resume</button>`;

      return `
        <tr>
          <td>${formatAccountCell(t.did, t.handle)}</td>
          <td>${statusBadge}</td>
          <td>${sessionBadge}</td>
          <td class="cell-date" title="${escapeHtml(formatFullDate(t.created_at))}">${formatDate(t.created_at)}</td>
          <td>${modLink}</td>
          <td>${toggleAction}</td>
        </tr>
      `;
    }).join("");

    enhanceUnresolvedAccountCells(tbody);
  } catch (e) {
    if (e && e.name === "AbortError") return;
    console.error("Admin fleet load failed", e);
    renderTableError(tbody, 6, "Network error loading tenant fleet.", "tenants");
  }
}

async function toggleAdminTenant(did, newActive) {
  const cachedHandle = didHandleCache.get(did);
  const displayLabel = cachedHandle ? `@${cachedHandle}` : did;
  try {
    const res = await fetch("/api/tenant/toggle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ did, is_active: newActive })
    });
    if (res.ok) {
      const data = await res.json();
      showToast(data.is_active ? `Defenses resumed for ${displayLabel}` : `Defenses paused for ${displayLabel}`);
      loadAdminTenants();
      if (currentUser && currentUser.did === did) {
        currentUser.is_active = data.is_active;
        renderAuthenticated(currentUser);
      }
    } else {
      const err = await res.text();
      showToast(`Error: ${err}`);
    }
  } catch (e) {
    showToast("Network error toggling tenant");
  }
}

function formatModListUrl(uri) {
  if (!uri || typeof uri !== "string") return null;
  const m = uri.trim().match(/^at:\/\/([^/]+)\/app\.bsky\.graph\.list\/([a-zA-Z0-9._~-]+)$/);
  if (!m) return null;
  return `${bskyProfileUrl(m[1])}/lists/${encodeURIComponent(m[2])}`;
}

async function loadAdminEvaluations() {
  const ctrl = startLoaderRequest("evals");
  const sourceFilter = document.getElementById("admin-eval-source-filter")?.value || "all";
  const url = `/api/evaluations?limit=${PAGE_SIZE}&offset=${evalsOffset}&source=${encodeURIComponent(sourceFilter)}`;
  const tbody = document.getElementById("admin-evals-table");

  try {
    const res = await fetch(url, { credentials: "same-origin", signal: ctrl.signal });
    if (!res.ok) {
      if (res.status === 403 || res.status === 401) {
        setHidden(document.getElementById("admin-eval-card"), true);
        return;
      }
      renderTableError(tbody, 8, `Failed to load evaluation logs (HTTP ${res.status}).`, "evals");
      return;
    }
    const data = await res.json();
    evalsTotal = typeof data.total === "number" ? data.total : 0;
    const evalList = Array.isArray(data.evaluations) ? data.evaluations : [];
    const totalEl = document.getElementById("admin-total-evals");
    if (totalEl) totalEl.innerText = evalsTotal.toLocaleString();

    if (!tbody) return;

    if (evalList.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="table-empty-cell">No evaluation logs recorded yet. Incoming interactions from the Bluesky Jetstream firehose will appear here in real time.</td></tr>';
      updatePaginationBar("evals-pagination", "evals-page-info", "evals-prev-btn", "evals-next-btn", evalsTotal, 0, evalsOffset);
      return;
    }

    evalList.forEach(ev => {
      if (ev.target_did && ev.target_handle) {
        didHandleCache.set(ev.target_did, ev.target_handle.replace(/^@/, ""));
      }
      if (ev.author_did && ev.author_handle) {
        didHandleCache.set(ev.author_did, ev.author_handle.replace(/^@/, ""));
      }
    });

    tbody.innerHTML = evalList.map(renderEvaluationRow).join("");
    enhanceUnresolvedAccountCells(tbody);
    updatePaginationBar(
      "evals-pagination",
      "evals-page-info",
      "evals-prev-btn",
      "evals-next-btn",
      evalsTotal,
      evalList.length,
      evalsOffset
    );
  } catch (e) {
    if (e && e.name === "AbortError") return;
    console.error("Evaluation log load failed", e);
    renderTableError(tbody, 8, "Network error loading evaluation logs.", "evals");
  }
}

function renderEvaluationRow(ev) {
  const ts = formatDate(ev.timestamp_us);
  const fullTs = formatFullDate(ev.timestamp_us);
  const isLive = ev.source === "live";
  const sourceBadge = isLive
    ? '<span class="status-badge badge-accent badge-xs">Live</span>'
    : '<span class="status-badge badge-purple badge-xs">Sim</span>';

  const targetCellHtml = formatAccountCell(ev.target_did, ev.target_handle);
  const authorCellHtml = formatAccountCell(ev.author_did, ev.author_handle);
  const postLinkHtml = formatPostLink(ev.post_uri, ev.post_text);

  const t1Violates = ev.primary_action === "violation";
  const t1Badge = t1Violates
    ? `<span class="status-badge badge-danger badge-xs">Violation (${Math.round(ev.primary_confidence * 100)}%)</span>`
    : `<span class="status-badge badge-success badge-xs">Allow (${Math.round(ev.primary_confidence * 100)}%)</span>`;
  const t1Category = ev.primary_category ? `<span class="eval-cat-text">${escapeHtml(ev.primary_category)}</span>` : "";

  let t2Html = '<span class="cell-muted-sm">— Resolved in T1</span>';
  if (ev.escalated) {
    const t2Violates = ev.fallback_action === "violation";
    const t2Badge = t2Violates
      ? `<span class="status-badge badge-danger badge-xs">Violation (${Math.round((ev.fallback_confidence || 0) * 100)}%)</span>`
      : `<span class="status-badge badge-success badge-xs">Allow (${Math.round((ev.fallback_confidence || 0) * 100)}%)</span>`;
    const t2Category = ev.fallback_category ? `<span class="eval-cat-text">${escapeHtml(ev.fallback_category)}</span>` : "";
    const escReason = ev.escalation_reason || "Escalated";
    t2Html = `
      <div class="eval-tier-col">
        <div class="eval-tier-row">
          <span class="status-badge badge-warning badge-xs" title="${escapeHtml(escReason)}">${escapeHtml(escReason)}</span>
          <code class="mono-pill mono-pill-sm">${escapeHtml(ev.fallback_model || "")}</code>
        </div>
        <div class="eval-tier-row">${t2Badge} ${t2Category}</div>
        <div class="expandable-text eval-expandable-sm" title="Click to expand/collapse: ${escapeHtml(ev.fallback_reason || "")}">
          ${escapeHtml(ev.fallback_reason || "")}
        </div>
      </div>
    `;
  }

  let outcomeBadge = `<span class="status-badge badge-neutral badge-sm-text">${escapeHtml(ev.outcome)}</span>`;
  if (ev.outcome.includes("Bounced")) {
    outcomeBadge = `<span class="status-badge badge-danger badge-sm-text">${escapeHtml(ev.outcome)}</span>`;
  } else if (ev.outcome.includes("Below") || ev.outcome.includes("Skipped")) {
    outcomeBadge = `<span class="status-badge badge-warning badge-sm-text">${escapeHtml(ev.outcome)}</span>`;
  } else if (ev.outcome.includes("Permitted") || ev.outcome.includes("Allow")) {
    outcomeBadge = `<span class="status-badge badge-success badge-sm-text">${escapeHtml(ev.outcome)}</span>`;
  }

  return `
    <tr>
      <td class="cell-ts" title="${escapeHtml(fullTs)}">${escapeHtml(ts)}</td>
      <td>${sourceBadge}</td>
      <td class="cell-actor">${targetCellHtml}</td>
      <td class="cell-actor">${authorCellHtml}</td>
      <td>${postLinkHtml}</td>
      <td>
        <div class="eval-tier-col">
          <div class="eval-tier-row">
            <code class="mono-pill mono-pill-sm">${escapeHtml(ev.primary_model)}</code>
            ${t1Badge}
          </div>
          <div>${t1Category}</div>
          <div class="expandable-text eval-expandable-sm" title="Click to expand/collapse: ${escapeHtml(ev.primary_reason)}">
            ${escapeHtml(ev.primary_reason)}
          </div>
        </div>
      </td>
      <td>${t2Html}</td>
      <td>${outcomeBadge}</td>
    </tr>
  `;
}

function parseTimestampToMs(val) {
  if (val === null || val === undefined || val === "") return null;
  if (typeof val === "number" || (!isNaN(val) && !isNaN(parseFloat(val)))) {
    const num = Number(val);
    if (num === 0) return null;
    if (num > 1e14) {
      return Math.round(num / 1000);
    } else if (num < 1e11) {
      return Math.round(num * 1000);
    } else {
      return Math.round(num);
    }
  }
  const parsed = Date.parse(val);
  return isNaN(parsed) ? null : parsed;
}

function formatDate(val) {
  if (val === null || val === undefined || val === "") return "—";
  try {
    const ms = parseTimestampToMs(val);
    if (ms === null) return String(val);
    const d = new Date(ms);
    if (isNaN(d.getTime())) return String(val);
    const nowYear = new Date().getFullYear();
    const opts = {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit"
    };
    if (d.getFullYear() !== nowYear) {
      opts.year = "numeric";
    }
    return d.toLocaleString(undefined, opts);
  } catch (e) {
    return String(val);
  }
}

function formatFullDate(val) {
  if (val === null || val === undefined || val === "") return "";
  try {
    const ms = parseTimestampToMs(val);
    if (ms === null) return "";
    const d = new Date(ms);
    return isNaN(d.getTime()) ? "" : d.toLocaleString();
  } catch (e) {
    return "";
  }
}

let allStorms = [];
let stormModeActiveState = false;
let currentBannerStorm = null;

function atPostUriToBskyUrl(atUri) {
  if (!atUri || typeof atUri !== "string") return null;
  const m = atUri.match(/^at:\/\/(did:[^/]+)\/app\.bsky\.feed\.post\/([A-Za-z0-9._:-]+)$/);
  if (!m) return null;
  return `https://bsky.app/profile/${encodeURIComponent(m[1])}/post/${encodeURIComponent(m[2])}`;
}

function stormSeverityBadgeClass(severity) {
  const s = (severity || "").toLowerCase();
  if (s === "critical" || s === "high") return "badge-warning";
  return "badge-accent";
}

function getSelectedStormScopeDid() {
  if (!currentUser) return null;
  if (!currentUser.is_admin) return currentUser.did;
  const scopeSelect = document.getElementById("bounces-scope-select");
  const scope = scopeSelect ? scopeSelect.value : "mine";
  if (scope === "all") return null;
  if (scope === "mine") return currentUser.did;
  return scope;
}

async function loadStorms() {
  if (!currentUser) return;
  const ctrl = startLoaderRequest("storms");
  const listEl = document.getElementById("storms-list");
  try {
    let url = "/api/storms?limit=20";
    const scopedDid = getSelectedStormScopeDid();
    if (scopedDid) {
      url += `&user_did=${encodeURIComponent(scopedDid)}`;
    }
    const res = await fetch(url, { credentials: "same-origin", signal: ctrl.signal });
    if (!res.ok) {
      if (res.status === 401 || res.status === 403) return;
      if (listEl) {
        listEl.innerHTML = `
          <div class="storms-empty table-error-box">
            <span class="table-error-msg">Failed to load storm telemetry (HTTP ${res.status}).</span>
            <button type="button" class="btn btn-secondary btn-sm btn-retry-loader" data-retry-loader="storms">Retry</button>
          </div>
        `;
      }
      return;
    }
    const data = await res.json();
    stormModeActiveState = !!data.storm_mode_active;
    allStorms = Array.isArray(data.storms) ? data.storms : [];
    renderStorms();
  } catch (e) {
    if (e && e.name === "AbortError") return;
    console.error("Storms fetch failed", e);
    if (listEl) {
      listEl.innerHTML = `
        <div class="storms-empty table-error-box">
          <span class="table-error-msg">Network error loading storm telemetry.</span>
          <button type="button" class="btn btn-secondary btn-sm btn-retry-loader" data-retry-loader="storms">Retry</button>
        </div>
      `;
    }
  }
}

function formatTargetAccountLabel(targetDid, targetHandle) {
  if (targetHandle) {
    return `@${String(targetHandle).replace(/^@/, "")}`;
  }
  if (targetDid && didHandleCache.has(targetDid)) {
    return `@${didHandleCache.get(targetDid)}`;
  }
  return formatDid(targetDid || "");
}

function renderStorms() {
  const modeBadge = document.getElementById("storm-mode-status-badge");
  const modeBtn = document.getElementById("storm-mode-toggle-btn");
  if (modeBadge) {
    if (stormModeActiveState) {
      modeBadge.innerText = "⛈️ Storm Mode Active";
      modeBadge.className = "status-badge badge-warning badge-xs";
    } else {
      modeBadge.innerText = "Normal";
      modeBadge.className = "status-badge badge-neutral badge-xs";
    }
  }
  if (modeBtn) {
    modeBtn.innerText = stormModeActiveState ? "Exit Storm Mode" : "Enable Storm Mode";
  }

  const scopeSelect = document.getElementById("bounces-scope-select");
  const scopeVal = scopeSelect ? scopeSelect.value : "mine";
  const showTargetPill = !!(currentUser && currentUser.is_admin && scopeVal !== "mine");

  const activeList = allStorms.filter((s) => (s.status || "").toLowerCase() === "active");
  currentBannerStorm = activeList.length > 0 ? activeList[0] : null;
  const bannerEl = document.getElementById("active-storm-banner");
  if (bannerEl) {
    if (stormModeActiveState || currentBannerStorm) {
      setHidden(bannerEl, false);
      const titleEl = document.getElementById("active-storm-banner-title");
      const targetPillEl = document.getElementById("active-storm-banner-target");
      const sumEl = document.getElementById("active-storm-banner-summary");
      const lockBtn = document.getElementById("banner-lock-btn");
      const detachBtn = document.getElementById("banner-detach-btn");
      if (currentBannerStorm) {
        const sev = (currentBannerStorm.severity || "elevated").toUpperCase();
        const oon = currentBannerStorm.metrics ? (currentBannerStorm.metrics.unique_oon_authors_short || 0) : 0;
        if (titleEl) {
          titleEl.innerText = `[${sev}] Coordinated Surge Detected (${oon} out-of-network accounts)`;
        }
        if (targetPillEl) {
          const isOtherTenant = currentUser && currentBannerStorm.target_did && currentBannerStorm.target_did !== currentUser.did;
          if (showTargetPill || isOtherTenant) {
            targetPillEl.innerText = formatTargetAccountLabel(currentBannerStorm.target_did, currentBannerStorm.target_handle);
            setHidden(targetPillEl, false);
          } else {
            setHidden(targetPillEl, true);
          }
        }
        const snippet = (currentBannerStorm.focal_post_snippet || "").trim();
        if (sumEl) {
          sumEl.innerText = snippet
            ? `Focal post: "${snippet.slice(0, 120)}" • Digest batching & 3x headroom active.`
            : "Individual bounce DMs are collapsed into periodic digests while your surge subsides.";
        }
        const isMentions = (currentBannerStorm.focal_post_uri || "").endsWith("/_mentions");
        setHidden(lockBtn, isMentions);
        const hasCats = Array.isArray(currentBannerStorm.catalyst_qt_uris) && currentBannerStorm.catalyst_qt_uris.length > 0;
        setHidden(detachBtn, isMentions || !hasCats);
      } else {
        if (titleEl) titleEl.innerText = "Storm Mode Enabled Manually";
        const manualTargetDid = getSelectedStormScopeDid() || (currentUser && currentUser.did);
        const isOtherTenant = !!(currentUser && manualTargetDid && manualTargetDid !== currentUser.did);
        if (targetPillEl) {
          if (manualTargetDid && (showTargetPill || isOtherTenant)) {
            const manualTargetHandle = currentUser && manualTargetDid === currentUser.did ? currentUser.handle : null;
            targetPillEl.innerText = formatTargetAccountLabel(manualTargetDid, manualTargetHandle);
            setHidden(targetPillEl, false);
          } else {
            setHidden(targetPillEl, true);
          }
        }
        if (sumEl) sumEl.innerText = "Individual bounce DMs are batched into periodic digests with 3x evaluation headroom.";
        setHidden(lockBtn, true);
        setHidden(detachBtn, true);
      }
    } else {
      setHidden(bannerEl, true);
    }
  }

  const listEl = document.getElementById("storms-list");
  if (!listEl) return;

  if (allStorms.length === 0) {
    listEl.innerHTML = '<div class="storms-empty">No dogpile surges detected yet. Out-of-network reply/quote spikes will appear here automatically.</div>';
    return;
  }

  listEl.innerHTML = allStorms.map((s) => {
    const m = s.metrics || {};
    const oon = m.unique_oon_authors_short || 0;
    const total = m.unique_authors_short || 0;
    const oonPct = Math.round((m.out_of_network_ratio || 0) * 100);
    const directRatio = Number(m.direct_ratio || 0).toFixed(2);
    const dunkRatio = Number(m.dunk_ratio || 0).toFixed(1);
    const scorePct = Math.round((m.composite_score || 0) * 100);
    const isMentions = (s.focal_post_uri || "").endsWith("/_mentions");
    const postUrl = !isMentions ? atPostUriToBskyUrl(s.focal_post_uri) : null;
    const sevLabel = escapeHtml((s.severity || "elevated").toUpperCase());
    const statusLabel = escapeHtml((s.status || "active").toUpperCase());
    const targetBadgeHtml = (showTargetPill || (currentUser && s.target_did && s.target_did !== currentUser.did))
      ? `<span class="status-badge badge-accent badge-xs" title="${escapeHtml(s.target_did || "")}">${escapeHtml(formatTargetAccountLabel(s.target_did, s.target_handle))}</span>`
      : "";

    let postHtml = isMentions
      ? `<strong>Aggregate @mentions surge</strong>`
      : (postUrl
          ? `<a href="${postUrl}" target="_blank" rel="noopener noreferrer" class="storm-post-link">View Focal Post ↗</a>`
          : `<code class="mono-pill">${escapeHtml(s.focal_post_uri || "")}</code>`);
    if (s.focal_post_snippet) {
      postHtml += ` <span class="storm-card-snippet">&ldquo;${escapeHtml(s.focal_post_snippet.slice(0, 140))}&rdquo;</span>`;
    }

    let catalystHtml = "";
    if (s.top_catalyst) {
      const cat = s.top_catalyst;
      const catAuthor = cat.author_handle ? `@${cat.author_handle.replace(/^@/, "")}` : cat.author_did;
      const catUrl = atPostUriToBskyUrl(cat.post_uri);
      const catLink = catUrl ? `<a href="${catUrl}" target="_blank" rel="noopener noreferrer" class="storm-qt-link">QT ↗</a>` : "";
      catalystHtml = `<div class="storm-card-catalyst">Catalyst: <strong>${escapeHtml(catAuthor)}</strong> (${cat.like_count || 0} likes, ${Number(cat.dunk_ratio || 0).toFixed(1)}x root likes) ${catLink}${cat.text_snippet ? ` &mdash; &ldquo;${escapeHtml(cat.text_snippet.slice(0, 100))}&rdquo;` : ""}</div>`;
    }

    let stanceHtml = "";
    if (s.stance && s.stance.summary) {
      const confPct = Math.round((s.stance.confidence || 0) * 100);
      stanceHtml = `<div class="storm-card-stance">Stance (<strong>${escapeHtml(s.stance.classification || "evaluated")}</strong>, ${confPct}%): ${escapeHtml(s.stance.summary)}</div>`;
    }

    const defensiveParts = [];
    if ((m.defensive_blocks || 0) > 0) defensiveParts.push(`${m.defensive_blocks} blocks`);
    if ((m.defensive_detaches || 0) > 0) defensiveParts.push(`${m.defensive_detaches} detaches`);
    const defensiveNote = defensiveParts.length > 0 ? ` • Defensive: ${defensiveParts.join(", ")}` : "";

    const hasCatalysts = Array.isArray(s.catalyst_qt_uris) && s.catalyst_qt_uris.length > 0;
    let actionsHtml = "";
    if (!isMentions) {
      if (s.threadgate_applied) {
        actionsHtml += `<button type="button" class="btn btn-secondary btn-sm btn-storm-unlock" data-post-uri="${escapeHtml(s.focal_post_uri)}" data-protected-did="${escapeHtml(s.target_did)}">🔓 Unlock Replies</button>`;
      } else {
        actionsHtml += `<button type="button" class="btn btn-sm btn-storm-lock" data-post-uri="${escapeHtml(s.focal_post_uri)}" data-policy="following" data-protected-did="${escapeHtml(s.target_did)}">🔒 Lock Replies</button>`;
      }
      if (hasCatalysts) {
        actionsHtml += `<button type="button" class="btn btn-secondary btn-sm btn-storm-detach" data-post-uri="${escapeHtml(s.focal_post_uri)}" data-protected-did="${escapeHtml(s.target_did)}" data-disable-all="false">✂️ Detach QTs</button>`;
      } else {
        actionsHtml += `<button type="button" class="btn btn-secondary btn-sm btn-storm-detach" data-post-uri="${escapeHtml(s.focal_post_uri)}" data-protected-did="${escapeHtml(s.target_did)}" data-disable-all="true">🚫 Disable Quotes</button>`;
      }
    }
    if ((s.status || "").toLowerCase() === "active") {
      actionsHtml += `<button type="button" class="btn btn-secondary btn-sm btn-storm-dismiss" data-storm-id="${Number(s.id)}">Dismiss</button>`;
    }

    return `
      <div class="storm-card">
        <div class="storm-card-head">
          <div class="storm-card-badges">
            <span class="status-badge ${stormSeverityBadgeClass(s.severity)}">${sevLabel}</span>
            <span class="status-badge badge-neutral">${statusLabel}</span>
            ${targetBadgeHtml}
            <span class="cell-muted-sm">${formatDate(s.updated_at_us || s.started_at_us)}</span>
          </div>
          <div class="storm-card-actions">${actionsHtml}</div>
        </div>
        <div class="storm-card-post">${postHtml}</div>
        <div class="storm-card-metrics">
          Score: <strong>${scorePct}%</strong> • OON: <strong>${oon}/${total}</strong> (${oonPct}%) • direct_ratio: ${directRatio} • dunk_ratio: ${dunkRatio}x • Bounced: <strong>${s.bounces_during_storm || 0}</strong>${escapeHtml(defensiveNote)}
        </div>
        ${catalystHtml}
        ${stanceHtml}
      </div>
    `;
  }).join("");
}

async function toggleStormMode(enabled, targetDidOverride = null) {
  if (!currentUser) return;
  const targetDid = targetDidOverride || getSelectedStormScopeDid() || currentUser.did;
  try {
    const res = await fetch("/api/storms/mode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ enabled: !!enabled, target_did: targetDid })
    });
    if (res.ok) {
      const data = await res.json();
      stormModeActiveState = !!data.storm_mode_active;
      showToast(stormModeActiveState ? "⛈️ Storm Mode enabled" : "🟢 Storm Mode disabled");
      loadStorms();
    } else {
      showToast("Failed to update Storm Mode");
    }
  } catch (e) {
    showToast("Network error toggling Storm Mode");
  }
}

async function dismissStormEvent(stormId) {
  try {
    const res = await fetch("/api/storms/dismiss", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ storm_id: stormId })
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.dismissed) {
        showToast("Storm dismissed");
      } else {
        showToast("Storm was already dismissed");
      }
      loadStorms();
    } else {
      showToast("Failed to dismiss storm");
    }
  } catch (e) {
    showToast("Network error dismissing storm");
  }
}

async function lockStormThread(postUri, policy, protectedDid) {
  try {
    const res = await fetch("/api/storms/lock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        post_uri: postUri,
        policy: policy || "following",
        protected_did: protectedDid || (currentUser ? currentUser.did : undefined)
      })
    });
    if (res.ok) {
      showToast("🔒 Thread replies locked on PDS");
      loadStorms();
    } else {
      const msg = await res.text();
      showToast(`Lock failed: ${msg}`);
    }
  } catch (e) {
    showToast("Network error locking thread");
  }
}

async function unlockStormThread(postUri, protectedDid) {
  try {
    const res = await fetch("/api/storms/unlock", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        post_uri: postUri,
        protected_did: protectedDid || (currentUser ? currentUser.did : undefined)
      })
    });
    if (res.ok) {
      showToast("🔓 Threadgate lock removed");
      loadStorms();
    } else {
      showToast("Failed to unlock thread");
    }
  } catch (e) {
    showToast("Network error unlocking thread");
  }
}

async function detachStormQuotes(postUri, protectedDid, disableAllQuotes) {
  try {
    const res = await fetch("/api/storms/detach", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        post_uri: postUri,
        disable_all_quotes: !!disableAllQuotes,
        protected_did: protectedDid || (currentUser ? currentUser.did : undefined)
      })
    });
    if (res.ok) {
      showToast(disableAllQuotes ? "🚫 Quotes disabled on PDS" : "✂️ Catalyst quote-posts detached");
      loadStorms();
    } else {
      const msg = await res.text();
      showToast(`Postgate update failed: ${msg}`);
    }
  } catch (e) {
    showToast("Network error updating postgate");
  }
}

function lockBannerStormPost() {
  if (currentBannerStorm && currentBannerStorm.focal_post_uri) {
    lockStormThread(currentBannerStorm.focal_post_uri, "following", currentBannerStorm.target_did);
  }
}

function detachBannerStormPost() {
  if (currentBannerStorm && currentBannerStorm.focal_post_uri) {
    detachStormQuotes(currentBannerStorm.focal_post_uri, currentBannerStorm.target_did, false);
  }
}

function initEventBindings() {
  document.querySelectorAll(".theme-btn[data-theme-pref]").forEach(btn => {
    btn.addEventListener("click", () => setThemePreference(btn.dataset.themePref));
  });

  document.addEventListener("click", (e) => {
    const loginTrigger = e.target.closest('[data-action="open-login"]');
    if (loginTrigger) {
      showLoginModal();
      return;
    }
    const signOutTrigger = e.target.closest('[data-action="sign-out"]');
    if (signOutTrigger) {
      signOut();
      return;
    }
    const retryBtn = e.target.closest(".btn-retry-loader");
    if (retryBtn) {
      const target = retryBtn.dataset.retryLoader;
      if (target === "bounces") loadBounces();
      else if (target === "allowlist") loadAllowlist();
      else if (target === "storms") loadStorms();
      else if (target === "evals") loadAdminEvaluations();
      else if (target === "tenants") loadAdminTenants();
      return;
    }
    const expandable = e.target.closest(".expandable-text");
    if (expandable) {
      expandable.classList.toggle("expanded");
    }
    if (!e.target.closest("#login-form")) {
      hideLoginTypeahead();
    }
  });

  document.querySelectorAll("[data-guest-preset]").forEach(btn => {
    btn.addEventListener("click", () => setGuestPreset(btn.dataset.guestPreset));
  });
  document.querySelectorAll("[data-guest-sample]").forEach(btn => {
    btn.addEventListener("click", () => runGuestSample(btn.dataset.guestSample || ""));
  });
  const guestSimText = document.getElementById("guest-sim-text");
  if (guestSimText) guestSimText.addEventListener("input", updateGuestCharCount);
  const guestSimBtn = document.getElementById("guest-sim-btn");
  if (guestSimBtn) guestSimBtn.addEventListener("click", runGuestSimulation);

  const tenantToggleBtn = document.getElementById("tenant-toggle-btn");
  if (tenantToggleBtn) tenantToggleBtn.addEventListener("click", toggleCurrentTenantDefense);

  const bannerLockBtn = document.getElementById("banner-lock-btn");
  if (bannerLockBtn) bannerLockBtn.addEventListener("click", lockBannerStormPost);
  const bannerDetachBtn = document.getElementById("banner-detach-btn");
  if (bannerDetachBtn) bannerDetachBtn.addEventListener("click", detachBannerStormPost);
  const bannerStormModeBtn = document.getElementById("banner-storm-mode-btn");
  if (bannerStormModeBtn) {
    bannerStormModeBtn.addEventListener("click", () => {
      const targetDid = (currentBannerStorm && currentBannerStorm.target_did) || getSelectedStormScopeDid() || (currentUser && currentUser.did);
      toggleStormMode(false, targetDid);
    });
  }

  const tabList = document.querySelector('.workspace-tabs[role="tablist"]');
  if (tabList) {
    const tabs = Array.from(tabList.querySelectorAll('[role="tab"]'));
    tabs.forEach((tabBtn, idx) => {
      tabBtn.addEventListener("click", () => switchWorkspaceTab(tabBtn.dataset.tab));
      tabBtn.addEventListener("keydown", (evt) => {
        let nextIdx = -1;
        if (evt.key === "ArrowRight") {
          nextIdx = (idx + 1) % tabs.length;
        } else if (evt.key === "ArrowLeft") {
          nextIdx = (idx - 1 + tabs.length) % tabs.length;
        } else if (evt.key === "Home") {
          nextIdx = 0;
        } else if (evt.key === "End") {
          nextIdx = tabs.length - 1;
        }
        if (nextIdx >= 0) {
          evt.preventDefault();
          switchWorkspaceTab(tabs[nextIdx].dataset.tab, true);
        }
      });
    });
  }

  const stormToggleBtn = document.getElementById("storm-mode-toggle-btn");
  if (stormToggleBtn) stormToggleBtn.addEventListener("click", () => toggleStormMode(!stormModeActiveState));
  const stormsRefreshBtn = document.getElementById("storms-refresh-btn");
  if (stormsRefreshBtn) stormsRefreshBtn.addEventListener("click", loadStorms);

  const stormsList = document.getElementById("storms-list");
  if (stormsList) {
    stormsList.addEventListener("click", (e) => {
      const btnLock = e.target.closest(".btn-storm-lock");
      if (btnLock && btnLock.dataset.postUri) {
        lockStormThread(btnLock.dataset.postUri, btnLock.dataset.policy || "following", btnLock.dataset.protectedDid);
        return;
      }
      const btnUnlock = e.target.closest(".btn-storm-unlock");
      if (btnUnlock && btnUnlock.dataset.postUri) {
        unlockStormThread(btnUnlock.dataset.postUri, btnUnlock.dataset.protectedDid);
        return;
      }
      const btnDetach = e.target.closest(".btn-storm-detach");
      if (btnDetach && btnDetach.dataset.postUri) {
        detachStormQuotes(btnDetach.dataset.postUri, btnDetach.dataset.protectedDid, btnDetach.dataset.disableAll === "true");
        return;
      }
      const btnDismiss = e.target.closest(".btn-storm-dismiss");
      if (btnDismiss && btnDismiss.dataset.stormId) {
        dismissStormEvent(Number(btnDismiss.dataset.stormId));
      }
    });
  }

  const bouncesScopeSelect = document.getElementById("bounces-scope-select");
  if (bouncesScopeSelect) bouncesScopeSelect.addEventListener("change", onBouncesScopeChange);
  const bouncesRefreshBtn = document.getElementById("bounces-refresh-btn");
  if (bouncesRefreshBtn) bouncesRefreshBtn.addEventListener("click", loadBounces);
  const bouncesSearchInput = document.getElementById("bounces-search-input");
  if (bouncesSearchInput) bouncesSearchInput.addEventListener("input", scheduleFilterBounces);

  const bouncesPrevBtn = document.getElementById("bounces-prev-btn");
  if (bouncesPrevBtn) {
    bouncesPrevBtn.addEventListener("click", () => {
      bouncesOffset = Math.max(0, bouncesOffset - PAGE_SIZE);
      loadBounces();
    });
  }
  const bouncesNextBtn = document.getElementById("bounces-next-btn");
  if (bouncesNextBtn) {
    bouncesNextBtn.addEventListener("click", () => {
      if (bouncesOffset + PAGE_SIZE < bouncesTotal) {
        bouncesOffset += PAGE_SIZE;
        loadBounces();
      }
    });
  }

  const bouncesTable = document.getElementById("bounces-table");
  if (bouncesTable) {
    bouncesTable.addEventListener("click", (e) => {
      const btnPardon = e.target.closest(".btn-pardon");
      if (btnPardon && btnPardon.dataset.did) {
        pardonUser(btnPardon.dataset.did, btnPardon.dataset.protectedDid, false);
        return;
      }
      const btnPardonAllow = e.target.closest(".btn-pardon-allow");
      if (btnPardonAllow && btnPardonAllow.dataset.did) {
        pardonUser(btnPardonAllow.dataset.did, btnPardonAllow.dataset.protectedDid, true);
        return;
      }
      const btnUpgradePerm = e.target.closest(".btn-upgrade-perm");
      if (btnUpgradePerm && btnUpgradePerm.dataset.did) {
        upgradeBounceToPerm(btnUpgradePerm.dataset.did, btnUpgradePerm.dataset.protectedDid);
      }
    });
  }

  document.querySelectorAll("[data-rubric-preset]").forEach(btn => {
    btn.addEventListener("click", () => applyRubricPreset(btn.dataset.rubricPreset));
  });
  const rulesPrompt = document.getElementById("rules-prompt");
  if (rulesPrompt) rulesPrompt.addEventListener("input", markRulesDirty);
  document.querySelectorAll("[data-sensitivity]").forEach(btn => {
    btn.addEventListener("click", () => setSensitivity(btn.dataset.sensitivity));
  });
  document.querySelectorAll("[data-duration]").forEach(btn => {
    btn.addEventListener("click", () => setBounceDuration(btn.dataset.duration));
  });
  const bypassToggle = document.getElementById("bypass-followers-toggle");
  if (bypassToggle) bypassToggle.addEventListener("change", markRulesDirty);
  const saveRulesBtn = document.getElementById("save-rules-btn");
  if (saveRulesBtn) saveRulesBtn.addEventListener("click", saveRules);

  document.querySelectorAll("[data-sim-sample]").forEach(btn => {
    btn.addEventListener("click", () => setSimText(btn.dataset.simSample || ""));
  });
  const simImgUrl = document.getElementById("sim-image-url");
  if (simImgUrl) simImgUrl.addEventListener("input", onSimImageUrlChange);
  const simFileInput = document.getElementById("sim-file-input");
  if (simFileInput) simFileInput.addEventListener("change", onSimFileSelected);
  const simAttachBtn = document.getElementById("sim-attach-img-btn");
  if (simAttachBtn && simFileInput) {
    simAttachBtn.addEventListener("click", () => simFileInput.click());
  }
  const simClearImgBtn = document.getElementById("sim-clear-img-btn");
  if (simClearImgBtn) simClearImgBtn.addEventListener("click", clearSimImage);
  const simEvalBtn = document.getElementById("sim-eval-btn");
  if (simEvalBtn) simEvalBtn.addEventListener("click", runSimulation);

  const allowlistRefreshBtn = document.getElementById("allowlist-refresh-btn");
  if (allowlistRefreshBtn) allowlistRefreshBtn.addEventListener("click", loadAllowlist);
  const allowlistAddBtn = document.getElementById("allowlist-add-btn");
  if (allowlistAddBtn) allowlistAddBtn.addEventListener("click", addAllowlistEntry);
  const allowlistTable = document.getElementById("allowlist-table");
  if (allowlistTable) {
    allowlistTable.addEventListener("click", (evt) => {
      const btn = evt.target.closest(".btn-allowlist-remove");
      if (btn && btn.dataset.did) {
        removeAllowlistEntry(btn.dataset.did);
      }
    });
  }

  const evalSourceFilter = document.getElementById("admin-eval-source-filter");
  if (evalSourceFilter) {
    evalSourceFilter.addEventListener("change", () => {
      evalsOffset = 0;
      loadAdminEvaluations();
    });
  }
  const evalsRefreshBtn = document.getElementById("admin-evals-refresh-btn");
  if (evalsRefreshBtn) evalsRefreshBtn.addEventListener("click", loadAdminEvaluations);
  const evalsPrevBtn = document.getElementById("evals-prev-btn");
  if (evalsPrevBtn) {
    evalsPrevBtn.addEventListener("click", () => {
      evalsOffset = Math.max(0, evalsOffset - PAGE_SIZE);
      loadAdminEvaluations();
    });
  }
  const evalsNextBtn = document.getElementById("evals-next-btn");
  if (evalsNextBtn) {
    evalsNextBtn.addEventListener("click", () => {
      if (evalsOffset + PAGE_SIZE < evalsTotal) {
        evalsOffset += PAGE_SIZE;
        loadAdminEvaluations();
      }
    });
  }

  const tenantsRefreshBtn = document.getElementById("admin-tenants-refresh-btn");
  if (tenantsRefreshBtn) tenantsRefreshBtn.addEventListener("click", loadAdminTenants);
  const tenantsTable = document.getElementById("admin-tenants-table");
  if (tenantsTable) {
    tenantsTable.addEventListener("click", (e) => {
      const btn = e.target.closest(".btn-tenant-toggle");
      if (btn && btn.dataset.did) {
        toggleAdminTenant(btn.dataset.did, btn.dataset.active === "true");
      }
    });
  }

  const loginModal = document.getElementById("login-modal");
  if (loginModal) {
    loginModal.addEventListener("close", () => hideLoginTypeahead());
    if (!("closedBy" in HTMLDialogElement.prototype)) {
      const isOutsideDialog = (e, dlg) => {
        const r = dlg.getBoundingClientRect();
        return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
      };
      let pressedOutside = false;
      loginModal.addEventListener("pointerdown", (e) => {
        pressedOutside = isOutsideDialog(e, loginModal);
      });
      loginModal.addEventListener("pointerup", (e) => {
        if (pressedOutside && isOutsideDialog(e, loginModal)) {
          closeLoginModal();
        }
        pressedOutside = false;
      });
    }
  }
  const infoToggleBtn = document.getElementById("login-info-toggle-btn");
  if (infoToggleBtn) infoToggleBtn.addEventListener("click", toggleLoginExplainer);
  const loginCloseBtn = document.getElementById("login-close-btn");
  if (loginCloseBtn) loginCloseBtn.addEventListener("click", closeLoginModal);
  const savedEditBtn = document.getElementById("login-saved-edit-btn");
  if (savedEditBtn) savedEditBtn.addEventListener("click", toggleSavedAccountsEditMode);
  const useAnotherBtn = document.getElementById("login-use-another-btn");
  if (useAnotherBtn) useAnotherBtn.addEventListener("click", () => showLoginInputView());

  const savedAccountsList = document.getElementById("login-saved-accounts-list");
  if (savedAccountsList) {
    savedAccountsList.addEventListener("click", (evt) => {
      const forgetBtn = evt.target.closest(".btn-forget-saved-acct");
      if (forgetBtn) {
        removeSavedAccount(forgetBtn.dataset.handle, evt);
        return;
      }
      const accountBtn = evt.target.closest(".saved-account-btn");
      if (!accountBtn || loginSavedAccountsEditMode) return;
      const h = accountBtn.dataset.handle;
      const accounts = loadSavedAccounts();
      const acct = accounts.find(a => a.handle.replace(/^@/, "").toLowerCase() === (h || "").toLowerCase());
      if (h) previewAndConfirmAccount(h, acct || null);
    });
  }

  const loginForm = document.getElementById("login-form");
  if (loginForm) loginForm.addEventListener("submit", handleLoginSubmit);
  const handleInput = document.getElementById("login-handle-input");
  if (handleInput) {
    handleInput.addEventListener("input", onLoginHandleInput);
    handleInput.addEventListener("keydown", onLoginHandleKeydown);
  }
  const typeaheadList = document.getElementById("login-typeahead-list");
  if (typeaheadList) {
    typeaheadList.addEventListener("mousedown", (evt) => {
      const item = evt.target.closest(".login-typeahead-item");
      if (!item) return;
      evt.preventDefault();
      selectTypeaheadItem(Number(item.dataset.index));
    });
  }
  const backToSavedBtn = document.getElementById("login-back-to-saved-btn");
  if (backToSavedBtn) backToSavedBtn.addEventListener("click", showSavedAccountsView);
  const loginCancelBtn = document.getElementById("login-cancel-btn");
  if (loginCancelBtn) loginCancelBtn.addEventListener("click", closeLoginModal);
  const confirmContinueBtn = document.getElementById("login-confirm-continue-btn");
  if (confirmContinueBtn) confirmContinueBtn.addEventListener("click", proceedConfirmedLogin);
  const switchAccountBtn = document.getElementById("login-switch-account-btn");
  if (switchAccountBtn) switchAccountBtn.addEventListener("click", () => showLoginInputView(true));
  const explainerBackBtn = document.getElementById("login-explainer-back-btn");
  if (explainerBackBtn) explainerBackBtn.addEventListener("click", closeLoginExplainer);

  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && currentUser) {
      fetchStatus();
    }
  });
}

initEventBindings();
renderRulesUnauthenticated();
checkUserSession();
setInterval(() => {
  if (currentUser && !document.hidden) {
    fetchStatus();
  }
}, 3000);
