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

/* ---------- Global keyboard shortcuts ---------- */
document.addEventListener("keydown", function (e) {
  // Ignore if focus is inside an input/textarea/select
  var tag = (e.target || {}).tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;

  // ? opens help dialog (Shift+? too)
  if (e.key === "?" && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    var el = document.getElementById("help-dialog");
    if (el) {
      // Toggle x-show via Alpine if available
      var alpine = document.querySelector("[x-data]");
      if (alpine && window.Alpine) {
        var data = Alpine.$data(alpine);
        if (data) data.helpOpen = !data.helpOpen;
      }
    }
  }

  // n → new task (board/backlog page)
  if ((e.key === "n" || e.key === "N") && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    var addBtn = document.querySelector(".bc-col-actions .bc-btn-primary, .bc-backlog-add");
    if (addBtn) addBtn.click();
  }

  // g + letter → navigation
  if (e.key === "g" && !e.ctrlKey && !e.metaKey) {
    document.addEventListener("keydown", navKeyHandler, { once: true });
  }
});

function navKeyHandler(e) {
  var path = "";
  switch (e.key) {
    case "b": case "B": path = "/boards"; break;
    case "l": case "L": path = "/backlog"; break;
    case "c": case "C": path = "/chat"; break;
    case "s": case "S": path = "/search"; break;
    case "n": case "N": path = "/notifications"; break;
  }
  if (path) {
    e.preventDefault();
    window.location.href = path;
  }
}

/* ---------- Alpine components ---------- */

document.addEventListener("alpine:init", function () {
  window.Alpine.data("shell", function () {
    return {
      drawerOpen: false,
      unreadCount: 0,
      helpOpen: false,
      openDrawer: function () {
        this.drawerOpen = true;
        // Focus trap: move focus into drawer panel
        var self = this;
        setTimeout(function () {
          var panel = document.querySelector(".bc-drawer-panel");
          if (panel) panel.focus();
        }, 50);
      },
      closeDrawer: function () {
        this.drawerOpen = false;
        // Return focus to the drawer button
        var btn = document.querySelector(".bc-drawer-btn");
        if (btn) btn.focus();
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

        // Keyboard: Escape closes drawer or help dialog
        document.addEventListener("keydown", function (e) {
          if (e.key === "Escape" || e.key === "Esc") {
            if (self.drawerOpen) self.closeDrawer();
            if (self.helpOpen) self.helpOpen = false;
          }
        });
      }
    };
  });

  /* Board drag-and-drop + mobile focus mode + keyboard grab-move-drop */
  window.Alpine.data("board", function (cfg) {
    var el = null;
    var sort = null;
    var focusCol = 0;
    var totalCols = 0;
    // Keyboard grab-move-drop state
    var grabbedCard = null;        // DOM element of the currently grabbed card
    var grabbedCardCol = null;     // column element the card belongs to
    var grabActive = false;
    return {
      focusCol: 0,
      totalCols: 0,
      init: function () {
        el = this.$el;
        var cols = el.querySelector(".bc-board-columns");
        if (!cols) return;

        // Count columns
        var colEls = cols.querySelectorAll(".bc-board-column");
        this.totalCols = colEls.length;

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

        // Card-level sortable per column with touch-friendly long-press delay
        el.querySelectorAll(".bc-col-cards").forEach(function (list) {
          Sortable.create(list, {
            group: "cards",
            animation: 150,
            ghostClass: "bc-card-dragging",
            draggable: ".bc-card",
            delay: 300,
            delayOnTouchOnly: true,
            touchStartThreshold: 8,
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

        // Mobile focus mode: track visible column via IntersectionObserver
        var self = this;
        var observer = new IntersectionObserver(function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              var colIdx = parseInt(entry.target.dataset.colIdx, 10);
              if (!isNaN(colIdx)) {
                self.focusCol = colIdx;
              }
            }
          });
        }, { threshold: 0.5 });

        colEls.forEach(function (col, i) {
          col.dataset.colIdx = i;
          observer.observe(col);
        });

        // Store observer for destroy
        this._observer = observer;

        // Keyboard grab-move-drop: Space to grab, arrows to move, Enter to drop, Esc to release
        document.addEventListener("keydown", function (e) {
          if (e.key === " " && !e.ctrlKey && !e.metaKey && !e.altKey) {
            // Grab the focused card (if any card is focused)
            var focused = document.activeElement;
            if (focused && focused.classList.contains("bc-card")) {
              e.preventDefault();
              grabbedCard = focused;
              grabbedCardCol = focused.closest(".bc-board-column");
              grabActive = true;
              focused.classList.add("bc-card-grabbed");
            }
          }
          if (grabActive) {
            if (e.key === "ArrowUp" || e.key === "ArrowDown") {
              e.preventDefault();
              // Move to previous/next column
              var colsList = el.querySelectorAll(".bc-board-column");
              var currentIdx = -1;
              for (var i = 0; i < colsList.length; i++) {
                if (colsList[i] === grabbedCardCol) { currentIdx = i; break; }
              }
              var targetIdx = e.key === "ArrowUp" ? currentIdx - 1 : currentIdx + 1;
              if (targetIdx >= 0 && targetIdx < colsList.length) {
                grabbedCardCol = colsList[targetIdx];
                var targetList = colsList[targetIdx].querySelector(".bc-col-cards");
                if (targetList) targetList.appendChild(grabbedCard);
              }
            }
            if (e.key === "Enter") {
              // Drop: dispatch move action
              e.preventDefault();
              var cardId = grabbedCard.dataset.sortKey;
              var colEl = grabbedCardCol;
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
                  sort_order: -1
                })
              });
              grabbedCard.classList.remove("bc-card-grabbed");
              grabbedCard = null;
              grabbedCardCol = null;
              grabActive = false;
            }
            if (e.key === "Escape" || e.key === "Esc") {
              // Release: move card back to original column
              if (grabbedCard && grabbedCardCol) {
                var origList = grabbedCardCol.querySelector(".bc-col-cards");
                if (origList) origList.appendChild(grabbedCard);
              }
              if (grabbedCard) grabbedCard.classList.remove("bc-card-grabbed");
              grabbedCard = null;
              grabbedCardCol = null;
              grabActive = false;
            }
          }
        });
      },
      prevCol: function () {
        if (this.focusCol > 0) {
          this.focusCol = this.focusCol - 1;
          this.scrollToCol(this.focusCol);
        }
      },
      nextCol: function () {
        if (this.focusCol < this.totalCols - 1) {
          this.focusCol = this.focusCol + 1;
          this.scrollToCol(this.focusCol);
        }
      },
      scrollToCol: function (idx) {
        var col = this.$el.querySelector('[data-col-idx="' + idx + '"]');
        if (col) col.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "start" });
      },
      destroy: function () {
        if (sort) sort.destroy();
        if (this._observer) this._observer.disconnect();
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
