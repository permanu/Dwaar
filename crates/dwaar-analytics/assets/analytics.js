(function() {
  // Honour Do Not Track and Global Privacy Control (GPC). Either signal
  // causes the beacon to be suppressed entirely — no data leaves the browser.
  if (navigator.doNotTrack === "1") return;
  if (navigator.globalPrivacyControl === true) return;

  // Read the server-issued beacon auth token from the meta tag the injector
  // embedded at page-load time. Format: "<nonce_b64>:<sig_hex>". If the tag
  // is absent (e.g. the response wasn't HTML-injectable) we still send the
  // beacon but without authentication — the server will reject it at the
  // verification step, which is the desired fail-closed behaviour.
  var authMeta = document.querySelector('meta[name="dwaar-beacon-auth"]');
  var authVal = authMeta ? authMeta.getAttribute("content") || "" : "";
  var authParts = authVal.split(":");
  var nonce = authParts[0] || "";
  var sig = authParts[1] || "";

  var d = {
    u: location.href,
    r: document.referrer || undefined,
    sw: screen.width,
    sh: screen.height,
    lg: navigator.language,
    nonce: nonce,
    sig: sig
  };

  // LCP (Largest Contentful Paint)
  try {
    new PerformanceObserver(function(l) {
      var e = l.getEntries();
      if (e.length) d.lcp = Math.round(e[e.length - 1].startTime);
    }).observe({ type: "largest-contentful-paint", buffered: true });
  } catch(_) {}

  // CLS (Cumulative Layout Shift)
  try {
    var cls = 0;
    new PerformanceObserver(function(l) {
      var e = l.getEntries();
      for (var i = 0; i < e.length; i++) {
        if (!e[i].hadRecentInput) cls += e[i].value;
      }
      d.cls = Math.round(cls * 1000) / 1000;
    }).observe({ type: "layout-shift", buffered: true });
  } catch(_) {}

  // INP (Interaction to Next Paint)
  // simplified: tracks worst interaction, not p98
  try {
    var maxInp = 0;
    new PerformanceObserver(function(l) {
      var e = l.getEntries();
      for (var i = 0; i < e.length; i++) {
        if (e[i].duration > maxInp) maxInp = e[i].duration;
      }
      d.inp = Math.round(maxInp);
    }).observe({ type: "event", buffered: true, durationThreshold: 16 });
  } catch(_) {}

  var t0 = performance.now();

  var sent = false;
  function send() {
    if (sent) return;
    sent = true;
    d.tp = Math.round(performance.now() - t0);
    var url = "/_dwaar/collect";
    var body = JSON.stringify(d);
    if (navigator.sendBeacon) {
      navigator.sendBeacon(url, body);
    } else if (typeof fetch === "function") {
      // keepalive allows the request to outlive the page, same semantics
      // as sendBeacon. We swallow errors — this is best-effort telemetry
      // and the page is unloading.
      fetch(url, { method: "POST", body: body, keepalive: true }).catch(function() {});
    }
    // Else: drop silently. Sync XHR on unload is a UX regression we will
    // not inflict on legacy browsers (L-23).
  }

  document.addEventListener("visibilitychange", function() {
    if (document.visibilityState === "hidden") send();
  });
})();
