// Live demo: the pages are static copies of the panel. Forms are not sent and
// links to pages outside the demo show a short notice instead.
(function () {
  var tr = (document.documentElement.lang || "").indexOf("tr") === 0;
  var text = tr
    ? { form: "Bu bir demo: işlemler çalışmaz ve kaydedilmez. Kendi sunucunuzda denemek için README'deki kurulum adımlarına bakın.",
        page: "Bu sayfa demoda yer almıyor." }
    : { form: "This is a demo: actions are not carried out or saved. To try it for real, see the installation steps in the README.",
        page: "This page is not part of the demo." };
  var timer;
  function toast(message) {
    var el = document.querySelector(".demo-toast");
    if (!el) {
      el = document.createElement("div");
      el.className = "demo-toast";
      el.setAttribute("role", "status");
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.hidden = false;
    clearTimeout(timer);
    timer = setTimeout(function () { el.hidden = true; }, 4000);
  }
  document.addEventListener("submit", function (e) {
    e.preventDefault();
    e.stopImmediatePropagation();
    toast(text.form);
  }, true);
  document.addEventListener("click", function (e) {
    var a = e.target.closest && e.target.closest('a[href="#demo-unavailable"]');
    if (a) {
      e.preventDefault();
      toast(text.page);
    }
  }, true);
})();
