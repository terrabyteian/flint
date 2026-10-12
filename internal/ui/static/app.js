// flint's web UI: progressive enhancements only. Every page works
// without this script. It is loaded from the page's head and wires the
// page up once it is parsed. The Content-Security-Policy allows no inline
// script.
(function () {
  "use strict";

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
