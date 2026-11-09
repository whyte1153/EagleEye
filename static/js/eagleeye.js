/* EagleEye UI behaviour: mobile sidebar + UTC clock.  No inline scripts (CSP friendly). */
(function () {
  "use strict";
  var body = document.body;
  var btn = document.getElementById("menu-toggle");
  if (btn) {
    btn.addEventListener("click", function () {
      var open = body.classList.toggle("nav-open");
      btn.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { body.classList.remove("nav-open"); btn.setAttribute("aria-expanded", "false"); }
    });
    body.addEventListener("click", function (e) {
      if (body.classList.contains("nav-open") && !e.target.closest(".ee-sidebar") && !e.target.closest("#menu-toggle")) {
        body.classList.remove("nav-open"); btn.setAttribute("aria-expanded", "false");
      }
    });
  }
  var clock = document.getElementById("utc-clock");
  if (clock) {
    var tick = function () { clock.textContent = new Date().toISOString().slice(0, 19).replace("T", " ") + " UTC"; };
    tick(); setInterval(tick, 1000);
  }
})();
