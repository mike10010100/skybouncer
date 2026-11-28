(function() {
  try {
    var stored = localStorage.getItem("atmosphere-theme") || localStorage.getItem("color-scheme") || "system";
    var pref = (stored === "light" || stored === "dark") ? stored : "system";
    var resolved = pref === "system"
      ? (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
      : pref;
    document.documentElement.setAttribute("data-theme", resolved);
    document.documentElement.setAttribute("data-theme-pref", pref);
    var meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.content = pref === "system" ? "light dark" : resolved;
  } catch (_) {}
})();
