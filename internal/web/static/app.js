/* Boardchestrator app shell script.
 *
 * No build step (SPEC §3): plain ES5-compatible script, served with a CSP
 * nonce. Alpine runs its CSP build, so every component used by x-data is
 * registered here via Alpine.data() and templates reference only
 * property/method names.
 */
"use strict";

window.bc = window.bc || {};

/* ---------- SSE helper (stub) ----------
 * Named-event subscription over a single EventSource. The /events endpoint
 * lands in WU-007; until then nothing calls connect(). Reconnect/backoff and
 * Last-Event-ID replay are deliberately left to WU-007/WU-212.
 */
bc.sse = (function () {
  var source = null;
  var handlers = {}; // event name -> [fn]

  return {
    connect: function (url) {
      if (source) {
        return source;
      }
      source = new EventSource(url || "/events");
      Object.keys(handlers).forEach(function (name) {
        handlers[name].forEach(function (fn) {
          source.addEventListener(name, fn);
        });
      });
      return source;
    },
    on: function (name, fn) {
      (handlers[name] = handlers[name] || []).push(fn);
      if (source) {
        source.addEventListener(name, fn);
      }
    },
    close: function () {
      if (source) {
        source.close();
        source = null;
      }
    },
    connected: function () {
      return source !== null;
    }
  };
})();

/* ---------- Theme ----------
 * The nonced inline bootstrap in the layout applies the persisted choice
 * before first paint; this handles toggling afterwards. Effective theme
 * falls back to prefers-color-scheme when the user has not chosen.
 */
bc.theme = {
  effective: function () {
    var explicit = document.documentElement.getAttribute("data-theme");
    if (explicit === "dark" || explicit === "light") {
      return explicit;
    }
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
    return "light";
  },
  set: function (theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("bc-theme", theme);
    } catch (e) {
      /* private browsing: theme just won't persist */
    }
  },
  toggle: function () {
    bc.theme.set(bc.theme.effective() === "dark" ? "light" : "dark");
  }
};

/* ---------- Alpine components ---------- */

document.addEventListener("alpine:init", function () {
  window.Alpine.data("shell", function () {
    return {
      drawerOpen: false,
      openDrawer: function () {
        this.drawerOpen = true;
      },
      closeDrawer: function () {
        this.drawerOpen = false;
      },
      toggleTheme: function () {
        bc.theme.toggle();
      }
    };
  });
});
