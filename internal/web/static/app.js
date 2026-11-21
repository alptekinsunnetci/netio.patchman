// netio.patchman: small progressive enhancements. The dashboard works without JS.
(function () {
  "use strict";

  // Confirmation for destructive or fleet-wide actions.
  // A submit button with its own data-confirm (even empty) overrides the form's.
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var src = e.submitter && e.submitter.hasAttribute("data-confirm") ? e.submitter : form;
    var msg = src.getAttribute && src.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      e.preventDefault();
    }
  });

  document.addEventListener("click", function (e) {
    var btn = e.target.closest && e.target.closest("[data-copy]");
    if (!btn) return;
    var el = document.getElementById(btn.getAttribute("data-copy"));
    if (!el) return;
    var text = el.value || el.textContent || "";
    var done = function () {
      btn.classList.add("is-copied");
      setTimeout(function () { btn.classList.remove("is-copied"); }, 1500);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { el.select(); });
    } else {
      el.select();
      try { document.execCommand("copy"); done(); } catch (err) { /* user can copy manually */ }
    }
  });

  document.addEventListener("change", function (e) {
    var name = e.target.getAttribute && e.target.getAttribute("data-check-all");
    if (!name) return;
    var form = e.target.form;
    if (!form) return;
    var boxes = form.querySelectorAll('input[type="checkbox"][name="' + name + '"]');
    for (var i = 0; i < boxes.length; i++) boxes[i].checked = e.target.checked;
  });

  // Sections shown only for one radio choice: data-show-when="name=value".
  // Without JS every section stays visible.
  function syncShowWhen() {
    var els = document.querySelectorAll("[data-show-when]");
    for (var i = 0; i < els.length; i++) {
      var rule = els[i].getAttribute("data-show-when").split("=");
      var form = els[i].closest("form");
      var checked = form && form.querySelector('input[name="' + rule[0] + '"]:checked');
      els[i].hidden = !(checked && checked.value === rule[1]);
    }
  }
  document.addEventListener("change", function (e) {
    if (e.target.type === "radio") syncShowWhen();
  });

  // Agent install command picker: every command is rendered by the server
  // in data attributes; picking a distribution also resets the sudo default.
  function installCmd(box, resetSudo) {
    var sel = box.querySelector("[data-installcmd-os]");
    var sudo = box.querySelector("[data-installcmd-sudo]");
    var out = document.getElementById(box.getAttribute("data-installcmd"));
    if (!sel || !sudo || !out) return;
    var opt = sel.options[sel.selectedIndex];
    if (resetSudo) sudo.checked = opt.hasAttribute("data-default-sudo");
    out.value = opt.getAttribute(sudo.checked ? "data-sudo" : "data-root");
  }
  document.addEventListener("change", function (e) {
    var box = e.target.closest && e.target.closest("[data-installcmd]");
    if (box) installCmd(box, e.target.hasAttribute("data-installcmd-os"));
  });
  function initInstallCmd() {
    var boxes = document.querySelectorAll("[data-installcmd]");
    for (var i = 0; i < boxes.length; i++) {
      var opts = boxes[i].querySelector(".installcmd__opts");
      if (opts) opts.hidden = false;
      installCmd(boxes[i], false);
    }
  }

  // Proportional bar segments (inline styles are blocked by CSP).
  function applyGrow() {
    var segs = document.querySelectorAll("[data-grow]");
    for (var i = 0; i < segs.length; i++) {
      segs[i].style.flexGrow = segs[i].getAttribute("data-grow");
    }
  }
  // Trend charts: crosshair, dot and tooltip for the nearest day with data.
  // The server draws the lines; the tooltip text uses the page's own labels.
  function trendShow(plot, idx) {
    var vals = plot.getAttribute("data-values").split(",");
    var labels = plot.getAttribute("data-labels").split("|");
    var n = vals.length;
    if (n < 2) return;
    idx = Math.max(0, Math.min(n - 1, idx));
    var best = -1;
    for (var d = 0; d < n && best < 0; d++) {
      if (idx - d >= 0 && vals[idx - d] !== "") best = idx - d;
      else if (idx + d < n && vals[idx + d] !== "") best = idx + d;
    }
    if (best < 0) return;
    var max = parseFloat(plot.querySelector(".trend__tick--max").textContent) || 1;
    var x = best / (n - 1) * 100;
    var y = (1 - parseFloat(vals[best]) / max) * 100;
    var cross = plot.querySelector(".trend__cross");
    cross.setAttribute("x1", x);
    cross.setAttribute("x2", x);
    cross.classList.add("is-visible");
    var dot = plot.querySelector(".trend__dot");
    dot.style.left = x + "%";
    dot.style.top = y + "%";
    dot.hidden = false;
    var tip = plot.querySelector(".trend__tip");
    tip.textContent = labels[best] + " · " + plot.getAttribute("data-name") + ": " + vals[best];
    tip.style.left = Math.min(Math.max(x, 12), 88) + "%";
    tip.hidden = false;
    plot.setAttribute("data-idx", best);
  }
  function trendHide(plot) {
    plot.querySelector(".trend__cross").classList.remove("is-visible");
    plot.querySelector(".trend__dot").hidden = true;
    plot.querySelector(".trend__tip").hidden = true;
  }
  function initTrends() {
    var plots = document.querySelectorAll(".trend__plot");
    for (var i = 0; i < plots.length; i++) {
      (function (plot) {
        var n = plot.getAttribute("data-values").split(",").length;
        plot.tabIndex = 0;
        plot.addEventListener("mousemove", function (e) {
          var r = plot.getBoundingClientRect();
          trendShow(plot, Math.round((e.clientX - r.left) / r.width * (n - 1)));
        });
        plot.addEventListener("mouseleave", function () { trendHide(plot); });
        plot.addEventListener("blur", function () { trendHide(plot); });
        plot.addEventListener("focus", function () { trendShow(plot, n - 1); });
        plot.addEventListener("keydown", function (e) {
          var cur = parseInt(plot.getAttribute("data-idx") || String(n - 1), 10);
          if (e.key === "ArrowLeft") { trendShow(plot, cur - 1); e.preventDefault(); }
          if (e.key === "ArrowRight") { trendShow(plot, cur + 1); e.preventDefault(); }
          if (e.key === "Escape") trendHide(plot);
        });
      })(plots[i]);
    }
  }

  // Print button (reports); printing works from the browser menu without JS.
  document.addEventListener("click", function (e) {
    if (e.target.closest && e.target.closest("[data-print]")) window.print();
  });

  function init() {
    initTrends();
    applyGrow();
    syncShowWhen();
    initInstallCmd();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
