// flint's web UI: progressive enhancements only. Every page works
// without this script. It is loaded from the page's head, so the theme
// is applied before the page is drawn, and wires the page up once it is
// parsed. The Content-Security-Policy allows no inline script.
(function () {
  "use strict";

  var THEMES = ["auto", "light", "dark"];
  var root = document.documentElement;

  function storedTheme() {
    try {
      var t = window.localStorage.getItem("flint-theme");
      return THEMES.indexOf(t) >= 0 ? t : "auto";
    } catch (e) {
      return "auto";
    }
  }

  function applyTheme(t) {
    if (t === "auto") {
      root.removeAttribute("data-theme");
    } else {
      root.setAttribute("data-theme", t);
    }
  }

  applyTheme(storedTheme());

  function copy(text, button) {
    function done(ok) {
      var label = button.textContent;
      button.textContent = ok ? "Copied" : "Copy failed";
      button.disabled = true;
      setTimeout(function () {
        button.textContent = label;
        button.disabled = false;
      }, 1500);
    }
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
      return;
    }
    // Plain HTTP: fall back to selecting the text in a hidden field.
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "offscreen";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    document.body.removeChild(area);
    done(ok);
  }

  document.addEventListener("DOMContentLoaded", function () {
    var toggle = document.querySelector("[data-theme-toggle]");
    if (toggle) {
      var label = function (t) { toggle.textContent = "Theme: " + t; };
      label(storedTheme());
      toggle.hidden = false;
      toggle.addEventListener("click", function () {
        var t = THEMES[(THEMES.indexOf(storedTheme()) + 1) % THEMES.length];
        try {
          window.localStorage.setItem("flint-theme", t);
        } catch (e) {
          // Storage refused: the choice lasts for this page only.
        }
        applyTheme(t);
        label(t);
      });
    }

    document.querySelectorAll("[data-copy], [data-copy-text]").forEach(function (button) {
      button.hidden = false;
      button.addEventListener("click", function () {
        var text = button.getAttribute("data-copy-text");
        if (text === null) {
          var pre = button.parentElement.querySelector("pre");
          text = pre ? pre.textContent : "";
        }
        copy(text, button);
      });
    });

    document.querySelectorAll("button[data-confirm]").forEach(function (button) {
      button.addEventListener("click", function (event) {
        if (!window.confirm(button.getAttribute("data-confirm"))) {
          event.preventDefault();
        }
      });
    });
  });
})();
