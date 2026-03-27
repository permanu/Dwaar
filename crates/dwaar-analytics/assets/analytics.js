(function() {
  if (navigator.doNotTrack === "1") return;

  var d = {
    u: location.href,
    r: document.referrer || null,
    sw: screen.width,
    sh: screen.height,
    lg: navigator.language
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

  function send() {
    d.tp = Math.round(performance.now() - t0);
    var url = "/_dwaar/collect";
    var body = JSON.stringify(d);
    if (navigator.sendBeacon) {
      navigator.sendBeacon(url, body);
    } else {
      var xhr = new XMLHttpRequest();
      xhr.open("POST", url, false);
      xhr.setRequestHeader("Content-Type", "application/json");
      xhr.send(body);
    }
  }

  document.addEventListener("visibilitychange", function() {
    if (document.visibilityState === "hidden") send();
  });
})();
