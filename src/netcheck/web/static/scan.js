// Runs before the scan form is submitted:
//  1. DNS check: look up a random <token>.dns.<domain> so our DNS server sees which
//     resolver the browser uses, then wait until the server has seen it.
//  2. Dual-stack: ask v4.<domain> and v6.<domain> for a one-time claim, so the scan
//     can cover both of the visitor's addresses. Each claim records the address the
//     request came from; the page never sends an address itself.
// Every step is best-effort. If something fails, the form still submits and the
// server reports that check as "couldn't check".
"use strict";

(function () {
  const form = document.getElementById("scan-form");
  if (!form) return;
  const status = document.getElementById("scan-status");
  const button = form.querySelector("button[type=submit]");

  function say(text) {
    status.textContent = text;
  }

  function randomToken() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function withTimeout(promise, ms) {
    return Promise.race([
      promise,
      new Promise((resolve) => setTimeout(() => resolve(null), ms)),
    ]);
  }

  async function getClaim(host) {
    try {
      const resp = await withTimeout(
        fetch(`https://${host}/api/claim`, { method: "POST", mode: "cors", credentials: "omit", cache: "no-store" }),
        3000,
      );
      if (!resp || !resp.ok) return "";
      const data = await resp.json();
      return typeof data.claim === "string" ? data.claim : "";
    } catch (e) {
      return "";
    }
  }

  async function waitForDns(token, ms) {
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      try {
        const resp = await fetch(`/api/dns/${token}`, { cache: "no-store" });
        if (resp.ok && (await resp.json()).seen === true) return true;
      } catch (e) {
        // keep polling
      }
      await new Promise((r) => setTimeout(r, 400));
    }
    return false;
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    button.disabled = true;
    say("Starting your check…");

    const token = randomToken();
    form.elements.dns_token.value = token;
    // The request will fail (there's no web server for this name); the DNS lookup
    // that happens first is all we need.
    fetch(`https://${token}.${form.dataset.dnsZone}/ping`, { mode: "no-cors", cache: "no-store" }).catch(() => {});

    const [claims] = await Promise.all([
      Promise.all([getClaim(form.dataset.v4Host), getClaim(form.dataset.v6Host)]),
      waitForDns(token, 5000),
    ]);
    const claimInputs = form.querySelectorAll("input[name=claim]");
    claims.forEach((c, i) => { claimInputs[i].value = c; });

    say("Scanning your connection. This takes about 15 seconds…");
    form.submit(); // doesn't re-fire the submit event
  });
})();
