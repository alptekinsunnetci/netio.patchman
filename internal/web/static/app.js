// netio.patchman: small progressive enhancements. The dashboard works without JS.
(function () {
  "use strict";

  // Confirmation for destructive or fleet-wide actions.
  document.addEventListener("submit", function (e) {
    var form = e.target;
    var msg = form.getAttribute && form.getAttribute("data-confirm");
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

  // Proportional bar segments (inline styles are blocked by CSP).
  function applyGrow() {
    var segs = document.querySelectorAll("[data-grow]");
    for (var i = 0; i < segs.length; i++) {
      segs[i].style.flexGrow = segs[i].getAttribute("data-grow");
    }
  }
  function init() {
    applyGrow();
    syncShowWhen();
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
