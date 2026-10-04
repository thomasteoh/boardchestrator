/* Passkeys (WU-612, SPEC §7.9). Progressive enhancement: every passkey
 * control lives in a [data-bc-passkey-box] rendered hidden, revealed here only
 * when the browser has WebAuthn. Ceremonies:
 *   data-bc-passkey="login"  GET begin -> navigator.credentials.get -> POST finish
 *   data-bc-passkey="signup" (form) GET begin?name=&invite=|email=&bootstrap=1
 *                            -> navigator.credentials.create -> POST finish
 *   data-bc-passkey="add"    POST begin (CSRF header) -> create -> POST finish
 * The server keeps the ceremony in the sealed flow cookie; this file only
 * converts between base64url JSON and ArrayBuffers. No inline script, no
 * third-party code. */
(function () {
  "use strict";

  var supported = typeof window.PublicKeyCredential === "function" &&
    !!(navigator.credentials && navigator.credentials.create);

  function reveal(root) {
    if (!supported) return;
    var boxes = (root || document).querySelectorAll("[data-bc-passkey-box]");
    for (var i = 0; i < boxes.length; i++) boxes[i].hidden = false;
  }

  function b64urlToBuf(s) {
    s = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function bufToB64url(buf) {
    if (!buf) return null;
    var bytes = new Uint8Array(buf);
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeDescriptors(list) {
    if (!list) return list;
    return list.map(function (d) {
      var c = Object.assign({}, d);
      c.id = b64urlToBuf(d.id);
      return c;
    });
  }

  function creationOptions(json) {
    var pk = Object.assign({}, json.publicKey);
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.user = Object.assign({}, pk.user, { id: b64urlToBuf(pk.user.id) });
    pk.excludeCredentials = decodeDescriptors(pk.excludeCredentials);
    return { publicKey: pk };
  }

  function requestOptions(json) {
    var pk = Object.assign({}, json.publicKey);
    pk.challenge = b64urlToBuf(pk.challenge);
    pk.allowCredentials = decodeDescriptors(pk.allowCredentials);
    return { publicKey: pk };
  }

  function extensions(cred) {
    try { return cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}; } catch (e) { return {}; }
  }

  function attestationJSON(cred) {
    var r = cred.response;
    var transports = [];
    try { if (r.getTransports) transports = r.getTransports(); } catch (e) { /* optional */ }
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: extensions(cred),
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        attestationObject: bufToB64url(r.attestationObject),
        transports: transports
      }
    };
  }

  function assertionJSON(cred) {
    var r = cred.response;
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: extensions(cred),
      response: {
        clientDataJSON: bufToB64url(r.clientDataJSON),
        authenticatorData: bufToB64url(r.authenticatorData),
        signature: bufToB64url(r.signature),
        userHandle: bufToB64url(r.userHandle)
      }
    };
  }

  // request fetches JSON; a non-2xx answer becomes an Error carrying the
  // server's fixed copy.
  function request(method, url, body, csrf) {
    var headers = { "Accept": "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    if (csrf) headers["X-CSRF-Token"] = csrf;
    return fetch(url, {
      method: method,
      credentials: "same-origin",
      headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body)
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) {
          var msg = data.error || "Something went wrong. Please try again.";
          if (data.ref) msg += " Reference: " + data.ref;
          throw new Error(msg);
        }
        return data;
      });
    });
  }

  function errorBox(el) {
    var box = el.closest("[data-bc-passkey-box]");
    return box ? box.querySelector("[data-bc-passkey-error]") : null;
  }

  function showError(el, err) {
    var p = errorBox(el);
    if (!p) return;
    var msg = err && err.message ? err.message : String(err);
    if (err && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      msg = "The passkey request was cancelled or timed out. Please try again.";
    } else if (err && err.name === "InvalidStateError") {
      msg = "This device already has a passkey for your account.";
    }
    p.textContent = msg;
    p.hidden = false;
  }

  function clearError(el) {
    var p = errorBox(el);
    if (p) { p.textContent = ""; p.hidden = true; }
  }

  function done(data) {
    if (data && typeof data.redirect === "string" && data.redirect.charAt(0) === "/" &&
        data.redirect.charAt(1) !== "/" && data.redirect.charAt(1) !== "\\") {
      window.location.assign(data.redirect);
    } else {
      window.location.reload();
    }
  }

  function withBusy(el, run) {
    if (el.getAttribute("aria-busy") === "true") return;
    el.setAttribute("aria-busy", "true");
    clearError(el);
    run().then(done).catch(function (err) { showError(el, err); })
      .then(function () { el.removeAttribute("aria-busy"); });
  }

  function login(btn) {
    withBusy(btn, function () {
      var url = btn.getAttribute("data-begin");
      var rt = btn.getAttribute("data-return-to");
      if (rt) url += "?return_to=" + encodeURIComponent(rt);
      return request("GET", url).then(function (opts) {
        return navigator.credentials.get(requestOptions(opts));
      }).then(function (cred) {
        return request("POST", btn.getAttribute("data-finish"), assertionJSON(cred));
      });
    });
  }

  function register(el, beginMethod, beginURL, csrf) {
    return request(beginMethod, beginURL, beginMethod === "POST" ? {} : undefined, csrf).then(function (opts) {
      return navigator.credentials.create(creationOptions(opts));
    }).then(function (cred) {
      return request("POST", el.getAttribute("data-finish"), attestationJSON(cred), csrf);
    });
  }

  function signup(form) {
    withBusy(form, function () {
      var q = new URLSearchParams();
      q.set("name", form.elements.name ? form.elements.name.value : "");
      if (form.getAttribute("data-bootstrap") === "1") {
        q.set("bootstrap", "1");
        q.set("email", form.elements.email ? form.elements.email.value : "");
      } else {
        q.set("invite", form.getAttribute("data-invite") || "");
      }
      return register(form, "GET", form.getAttribute("data-begin") + "?" + q.toString(), "");
    });
  }

  function add(btn) {
    withBusy(btn, function () {
      return register(btn, "POST", btn.getAttribute("data-begin"), btn.getAttribute("data-csrf"));
    });
  }

  document.addEventListener("click", function (ev) {
    if (!supported || !ev.target.closest) return;
    var el = ev.target.closest("[data-bc-passkey]");
    if (!el || el.tagName === "FORM") return;
    var kind = el.getAttribute("data-bc-passkey");
    if (kind === "login") { ev.preventDefault(); login(el); }
    if (kind === "add") { ev.preventDefault(); add(el); }
  });

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    if (!supported || !form.matches || !form.matches("form[data-bc-passkey='signup']")) return;
    ev.preventDefault();
    signup(form);
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { reveal(document); });
  } else {
    reveal(document);
  }
  // hx-boost swaps the body; reveal the new page's controls too.
  document.addEventListener("htmx:load", function (ev) { reveal(ev.target); });
})();
