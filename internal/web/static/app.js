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
    // form.elements also holds inputs tied to the form with a form attribute.
    var els = form.elements;
    for (var i = 0; i < els.length; i++) {
      if (els[i].type === "checkbox" && els[i].name === name) els[i].checked = e.target.checked;
    }
  });

  // Sections shown only for some radio choices: data-show-when="name=a|b".
  // Without JS every section stays visible.
  function syncShowWhen() {
    var els = document.querySelectorAll("[data-show-when]");
    for (var i = 0; i < els.length; i++) {
      var rule = els[i].getAttribute("data-show-when").split("=");
      var form = els[i].closest("form");
      var checked = form && form.querySelector('input[name="' + rule[0] + '"]:checked');
      els[i].hidden = !(checked && rule[1].split("|").indexOf(checked.value) >= 0);
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
    var sudoLabel = sudo.closest("label");
    if (sudoLabel) sudoLabel.hidden = opt.hasAttribute("data-nosudo");
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

  // Self-update progress: poll the status while the updater works and show
  // the current step, the elapsed time and the moment the server is out of
  // reach (it restarts during the update, so failed requests are retried).
  // The texts are rendered by the server; this only switches them. The page
  // reloads when the update is over.
  function initSelfUpdate() {
    var boxes = document.querySelectorAll("[data-selfupdate]");
    if (!boxes.length || !window.fetch) return;
    var url = boxes[0].getAttribute("data-selfupdate");
    var startVersion = boxes[0].getAttribute("data-version") || "";
    var elapsed = parseInt(boxes[0].getAttribute("data-elapsed") || "0", 10) || 0;
    var fails = 0;
    var each = function (sel, fn) {
      for (var i = 0; i < boxes.length; i++) {
        var els = boxes[i].querySelectorAll(sel);
        for (var j = 0; j < els.length; j++) fn(els[j]);
      }
    };
    var show = function (sel, on) { each(sel, function (el) { el.hidden = !on; }); };
    var two = function (n) { return (n < 10 ? "0" : "") + n; };
    var tick = function () {
      var h = Math.floor(elapsed / 3600), m = Math.floor(elapsed / 60) % 60, sec = elapsed % 60;
      var text = h ? h + ":" + two(m) + ":" + two(sec) : m + ":" + two(sec);
      each("[data-selfupdate-elapsed]", function (el) { el.textContent = text; });
    };
    var steps = function (cur) {
      each("[data-steps]", function (list) {
        var items = list.querySelectorAll("[data-step]"), at = -1, k;
        for (k = 0; k < items.length; k++) if (items[k].getAttribute("data-step") === cur) at = k;
        if (at < 0) return;
        for (k = 0; k < items.length; k++) {
          items[k].classList.toggle("is-done", k < at);
          items[k].classList.toggle("is-current", k === at);
          items[k].classList.toggle("is-todo", k > at);
        }
      });
    };
    tick();
    setInterval(function () { elapsed++; tick(); }, 1000);
    var poll = function () {
      fetch(url, { credentials: "same-origin", cache: "no-store" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (st) {
          if (!st || typeof st.active !== "boolean") throw new Error("status");
          fails = 0;
          show("[data-selfupdate-offline]", false);
          if (!st.active) { window.location.reload(); return; }
          if (typeof st.elapsed === "number") { elapsed = st.elapsed; tick(); }
          if (st.step) steps(st.step);
          show("[data-selfupdate-stalled]", !!st.stalled);
          show("[data-selfupdate-newserver]", !!st.version && !!startVersion && st.version !== startVersion);
          if (st.step && st.step !== "queued" && st.from) {
            var v = st.from + (st.to ? " → " + st.to : "");
            each("[data-selfupdate-versions]", function (el) { el.textContent = v; });
          }
          var logs = document.querySelectorAll("[data-selfupdate-log]");
          for (var i = 0; i < logs.length; i++) logs[i].textContent = st.log || "";
          setTimeout(poll, 3000);
        })
        .catch(function () {
          // One missed answer can be a slow request; two mean the server is away.
          fails++;
          if (fails >= 2) show("[data-selfupdate-offline]", true);
          setTimeout(poll, 3000);
        });
    };
    setTimeout(poll, 3000);
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
    initSelfUpdate();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
