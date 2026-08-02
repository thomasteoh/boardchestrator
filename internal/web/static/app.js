/* Boardchestrator app shell script.
 *
 * No build step (SPEC §3): plain ES5-compatible script, served with a CSP
 * nonce. Alpine runs its CSP build, so every component used by x-data is
 * registered here via Alpine.data() and templates reference only
 * property/method names.
 */
"use strict";

window.bc = window.bc || {};

/* CSRF token from meta tag (set by server) */
bc.csrfToken = function () {
  var m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.getAttribute('content') : '';
};

/* ---------- SSE helper with reconnect/backoff ----------
 * Named-event subscription over a single EventSource. Supports reconnect with
 * exponential backoff, missed-event refetch on reconnection, and partial
 * refresh dispatch via bc.sse.refresh().
 */
bc.sse = (function () {
  var source = null;
  var handlers = {};     // event name -> [fn]
  var lastEventID = 0;
  var retryDelay = 1000; // ms, doubles up to 30s
  var maxDelay = 30000;
  var reconnectTimer = null;
  var refetchURL = null;

  function connect(url) {
    url = url || "/events";

    source = new EventSource(url);

    source.addEventListener("open", function () {
      retryDelay = 1000; // reset on successful connection
    });

    source.addEventListener("error", function () {
      // EventSource auto-reconnects by default; we override with backoff
      // by closing and re-opening with a timer.
      if (source.readyState === EventSource.CLOSED) {
        source.close();
        source = null;
        scheduleReconnect(url);
      }
    });

    // Track Last-Event-ID from incoming messages for replay on reconnect
    source.addEventListener("message", function (e) {
      lastEventID = parseInt(e.lastEventId, 10) || 0;
    });

    Object.keys(handlers).forEach(function (name) {
      handlers[name].forEach(function (fn) {
        source.addEventListener(name, fn);
      });
    });

    return source;
  }

  function scheduleReconnect(url) {
    if (reconnectTimer) return;
    reconnectTimer = setTimeout(function () {
      reconnectTimer = null;
      connect(url);
      // After reconnection, refetch any missed events since lastEventID
      if (refetchURL && lastEventID > 0) {
        refetchMissed(url, lastEventID);
      }
    }, retryDelay);
    retryDelay = Math.min(retryDelay * 2, maxDelay);
  }

  function refetchMissed(url, sinceID) {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", url + "?since=" + sinceID, true);
    xhr.onload = function () {
      if (xhr.status === 200) {
        var lines = xhr.responseText.split("\n");
        var currentEvent = null;
        var currentData = "";
        for (var i = 0; i < lines.length; i++) {
          var line = lines[i];
          if (line.startsWith("event: ")) {
            currentEvent = line.substring(7);
          } else if (line.startsWith("data: ")) {
            currentData = line.substring(6);
          } else if (line === "") {
            // blank line = event boundary
            if (currentEvent && currentData) {
              dispatchEvent(currentEvent, currentData);
            }
            currentEvent = null;
            currentData = "";
          }
        }
      }
    };
    xhr.send();
  }

  function dispatchEvent(name, data) {
    var fns = handlers[name];
    if (!fns) return;
    var evt = { data: data };
    fns.forEach(function (fn) { fn(evt); });
  }

  return {
    connect: function (url) {
      if (source) {
        return source;
      }
      refetchURL = url || "/events";
      return connect(refetchURL);
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
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      lastEventID = 0;
    },
    connected: function () {
      return source !== null;
    },
    // Called by page-specific Alpine components to register partial-refresh
    // handlers for SSE events.
    refresh: function (eventName, selector, url) {
      bc.sse.on(eventName, function (e) {
        if (htmx) {
          htmx.ajax("GET", url, {
            target: selector,
            swap: "innerHTML"
          });
        }
      });
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
      unreadCount: 0,
      openDrawer: function () {
        this.drawerOpen = true;
      },
      closeDrawer: function () {
        this.drawerOpen = false;
      },
      toggleTheme: function () {
        bc.theme.toggle();
      },
      init: function () {
        // Register notification-badge SSE handler
        var self = this;
        bc.sse.on("notification", function () {
          bc.sse.refresh("notification", "#notif-badge", "/api/notif/unread-count");
        });
      }
    };
  });

  /* Board drag-and-drop */
  window.Alpine.data("board", function (cfg) {
    var el = null;
    var sort = null;
    return {
      init: function () {
        el = this.$el;
        var cols = el.querySelector(".bc-board-columns");
        if (!cols) return;

        // Register SSE partial refresh for board cards
        bc.sse.refresh("task-updated", "#board-" + cfg.projectID, "/app/project/" + cfg.projectID + "/board/partial");

        sort = Sortable.create(cols, {
          group: "board",
          animation: 150,
          ghostClass: "bc-dragging",
          direction: "horizontal",
          draggable: ".bc-board-column",
          onEnd: function (evt) {
            // Column reorder — dispatch board.column.reorder
            var id = evt.item.dataset.colId;
            if (!id) return;
            var pos = evt.newIndex;
            htmx.ajax("POST", "/api/action/board.column.reorder", {
              target: "#board-" + cfg.projectID,
              swap: "outerHTML",
              headers: { "X-CSRF-Token": bc.csrfToken() },
              vals: JSON.stringify({
                id: id,
                project_id: cfg.projectID,
                position: pos
              })
            });
          }
        });

        // Card-level sortable per column
        el.querySelectorAll(".bc-col-cards").forEach(function (list) {
          Sortable.create(list, {
            group: "cards",
            animation: 150,
            ghostClass: "bc-card-dragging",
            draggable: ".bc-card",
            onEnd: function (evt) {
              var cardId = evt.item.dataset.sortKey;
              var colEl = list.closest(".bc-board-column");
              var colId = colEl ? colEl.id.replace("col-", "") : "";
              var newStatus = colEl ? colEl.dataset.status : "backlog";
              htmx.ajax("POST", "/api/action/task.move", {
                target: "#board-" + cfg.projectID,
                swap: "outerHTML",
                headers: { "X-CSRF-Token": bc.csrfToken() },
                vals: JSON.stringify({
                  id: cardId,
                  project_id: cfg.projectID,
                  to_status: newStatus,
                  sort_order: evt.newIndex
                })
              });
            }
          });
        });
      },
      destroy: function () {
        if (sort) sort.destroy();
      }
    };
  });

  /* Task detail — SSE-driven partial refresh for comments */
  window.Alpine.data("taskDetail", function (cfg) {
    return {
      init: function () {
        bc.sse.refresh("task-updated", "#comments-list", "/api/project/" + cfg.projectID + "/task/" + cfg.taskID + "/comments-partial");
      }
    };
  });
});
