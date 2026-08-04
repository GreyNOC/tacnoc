/**
 * Header Hygiene — a harmless example TACNOC extension.
 *
 * Demonstrates the capability-based SDK. It uses ONLY the injected `tacnoc`
 * API object — no require(), no filesystem, no network. Each capability is used
 * defensively (guarded by a feature check) so the extension still loads if the
 * user grants a subset of permissions.
 *
 * Contract: an extension is a CommonJS module that exports `activate(tacnoc)`.
 */

function activate(tacnoc) {
  tacnoc.log('header-hygiene activated (sdk ' + tacnoc.version + ')');

  // 1) Passive check: flag responses that expose an X-Debug header.
  if (tacnoc.registerScannerCheck) {
    tacnoc.registerScannerCheck({
      module: 'header-hygiene',
      version: '1.0.0',
      appliesTo: function (ex) {
        return !!ex.response;
      },
      run: function (ctx) {
        var ex = ctx.exchange;
        var dbg = ex.response.headers.find(function (h) {
          return h.name.toLowerCase() === 'x-debug';
        });
        if (!dbg) return [];
        return [
          {
            dedupeKey: ex.host + '|x-debug',
            title: 'Debug header exposed (X-Debug)',
            severity: 'low',
            confidence: 'firm',
            description: 'The response includes an X-Debug header which may leak internal state.',
            remediation: 'Remove debug/diagnostic headers from production responses.',
            evidence: [
              { location: 'response-headers', excerpt: 'X-Debug: ' + dbg.value, field: 'X-Debug' },
            ],
          },
        ];
      },
    });
  }

  // 2) Data transform: ROT13 (purely illustrative).
  if (tacnoc.registerTransform) {
    tacnoc.registerTransform({
      id: 'rot13',
      label: 'ROT13 (example)',
      category: 'encode',
      transform: function (input) {
        return input.replace(/[a-zA-Z]/g, function (c) {
          var base = c <= 'Z' ? 65 : 97;
          return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
        });
      },
    });
  }

  // 3) Sanitized traffic counter.
  var count = 0;
  if (tacnoc.onTraffic) {
    tacnoc.onTraffic(function () {
      count += 1;
      if (count % 25 === 0) tacnoc.log('observed ' + count + ' exchanges');
    });
  }

  // 4) Read-only editor tab (returns PLAIN TEXT; never executed as HTML).
  if (tacnoc.registerEditorTab) {
    tacnoc.registerEditorTab({
      id: 'header-summary',
      label: 'Header Summary',
      render: function (event) {
        var req = event.requestHeaders.length;
        var res = event.responseHeaders ? event.responseHeaders.length : 0;
        return 'Request headers: ' + req + '\nResponse headers: ' + res;
      },
    });
  }
}

module.exports = { activate: activate };
