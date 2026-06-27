# PropellerAds `sfp.js` — walkthrough

This directory contains a complete, reproducible analysis of an in-the-wild **PropellerAds-family "smart popunder" tag** (`sfp.js`, build `2026.5.0`). Every artifact named below is committed to the repository; you can follow the steps without making any network call.

> [!WARNING]
> **The file at `artifacts/payload.js` is a live ad-fraud / browser-hijack payload.** It is *not* a binary exploit, but executing it in a browser will: install a full-viewport invisible overlay that hijacks the next click, open a popunder window to an attacker-billable URL, null the new tab's `window.opener` to break referrer chain, register a back-button hijack, fingerprint the visitor, and beacon results to five throwaway tracker domains. Treat it as you would any other malicious-by-design script. Do not `node` `payload.js`, do not paste it into a browser console, do not host it from a webserver you control without isolating the origin.
>
> The companion file `payload.deobf.js` is the reaper-rewritten plaintext: every string-array decoder call has been substituted with its literal. It is intended for *reading*, not for *running*. The obfuscator's anti-tamper guard (`oa()` at line 65) reads `decoder.toString()`; with the strings inlined that guard short-circuits, but the rest of the file will still attempt to mutate the DOM and call `window.open` if you execute it.

## Contents

- `REPORT.md` — full analysis. Read this for the actual findings.
- `SHA256SUMS` — integrity hashes for every artifact in this tree.
- `artifacts/` — original payload, rewritten plaintext, and the extracted config + IOCs.

```
artifacts/
├── payload.js                 original obfuscated 97 KB JS, one minified line
├── payload.deobf.js           reaper-rewritten plaintext (2 355 substitutions, 143 KB)
├── placement-config.json      extracted bootstrap config (DL placeholders table)
└── iocs.txt                   network indicators in a grep-friendly form
```

The filename `1285133f2f3d4bffd19ce5188f677353.js` (preserved as `payload.js` here) is itself an indicator: the basename is the MD5-shaped `placementKey` the publisher was billed against. PropellerAds serves tags from MD5-named paths to a small rotating pool of throwaway hostnames.

## Reproducing the analysis end-to-end

Every step below operates on the committed files. No network. No execution of the payload.

### 1. Static scan of the obfuscated original

```sh
npx tsx src/cli.ts examples/propellerads-sfp/artifacts/payload.js
```

reaper reports 18 `Unreachable code after return` findings, 12 unused variables, and 9 `['constructor']` bracket-access obfuscation patterns. The structure is recognisable as an obfuscator.io-family string-array IIFE; the strings themselves are still hidden behind the decoder.

### 2. Extract indicators directly from the obfuscated source

```sh
npx tsx src/cli.ts examples/propellerads-sfp/artifacts/payload.js -i
```

reaper's IOC extractor walks string literals at the AST level — it does **not** see anything behind the decoder. On the raw payload it finds only the five plaintext domains the obfuscator left as bare literals (the decoy `parseInt("…")` strings were not domains). After rewriting (step 3) the same command yields the full beacon-path inventory.

### 3. Deobfuscate the payload

```sh
npx tsx src/cli.ts examples/propellerads-sfp/artifacts/payload.js \
    --rewrite /tmp/reaper-out
diff /tmp/reaper-out/examples__propellerads-sfp__artifacts__payload.deobf.js \
     examples/propellerads-sfp/artifacts/payload.deobf.js
```

`--rewrite` boots the decoder (`pqkm2o3`) and the string-array fn (`pqkm2o2`) inside a sandboxed Node `vm`, runs the rotator IIFE so the array settles into its final order, then substitutes every wrapper or alias call with the plaintext string it returns. Expected console output:

```
…/payload.js  →  …/payload.deobf.js  (2355/2355 substitutions, 0 wrappers)
```

`0 wrappers` is correct — this variant has no wrapper *functions*; it uses 378 identifier *aliases* (`var Ne = pqkm2o3;` injected into every function scope), which reaper handles via its alias-resolution pass (`src/analyzers/stringarray.ts`). The `diff` should be empty: the committed `payload.deobf.js` is exactly what reaper produces today on this input.

### 4. Read the placement config

```sh
cat examples/propellerads-sfp/artifacts/placement-config.json
```

This is the bootstrap config the publisher's page was implicitly relying on (the `DL` placeholders table at `payload.deobf.js` line ~2400). It exposes:

- the five disposable tracker domains the network rotates;
- the publisher's billing identifiers (`placementKey`, `invBackId`, `templateId`);
- the frequency-cap settings (max-per-page, max-per-period, back-button cooldown);
- the beacon URL templates;
- the creative-fetch URL template (the full query-string envelope that includes the page-title-derived keywords, screen dimensions, timezone, bot-score, and per-visitor UUID).

### 5. Locate the click-hijack overlay in the rewritten source

```sh
grep -n 'createTransparentLayer' examples/propellerads-sfp/artifacts/payload.deobf.js
```

The overlay is constructed at the line under `createTransparentLayer:` (around line 1638 of the rewritten file). It is a `position: fixed`, viewport-sized `<div>` with `opacity: 0.01`, `zIndex: 2147483650`, containing an `<a target="_blank" href="<ad-url>">` that fills the entire viewport. The next genuine click anywhere on the page is silently captured and routed to the ad URL.

### 6. Cross-reference the IOCs

```sh
cat examples/propellerads-sfp/artifacts/iocs.txt
```

One indicator per line. The five `domain` entries should go straight into any DNS / proxy blocklist. The five `path` entries identify the beacon endpoints — useful as URL-pattern signatures even if the host rotates. The three `id` entries fingerprint this specific publisher account across pages and rotations.

### 7. Dynamic confirmation (optional, Docker required)

```sh
./scripts/analyze.sh examples/propellerads-sfp/artifacts/payload.deobf.js \
    --dynamic-only --observe-network --timeout 8
```

The sandbox runs the rewritten payload inside a `--network none` container with a stub `fetch` / `http` / `https` / `XMLHttpRequest` responder. Real egress stays blocked, but the script proceeds far enough that the URL/method/body it *would* have sent are captured as `[REAPER]` JSON lines on stderr. The `/pixel/` beacon to `drainalmost.com` and the `/stats` GET to `protrafficinspector.com` are the easiest to spot.

> [!NOTE]
> The payload's anti-debug `oa()` guard re-reads `decoder.toString()` at runtime. After rewriting, the decoder is still declared (reaper only strips top-level scaffolding; here it lives nested inside the outer IIFE), so the guard short-circuits cleanly and execution proceeds.

## Verifying integrity

```sh
cd examples/propellerads-sfp && sha256sum -c SHA256SUMS
```

If any artifact has been modified, this will report the mismatch. Unlike the EtherHiding example, this payload's "infrastructure" is just DNS records and ad-server URLs, not on-chain contract state — the committed `payload.js` is a snapshot that the network may rotate at any time (new `placementKey`, new domains, new build). Re-encountering the same `placementKey` on a different host is a strong correlation signal.

## See also

`REPORT.md` (this directory) — the analysis writeup, indicators, mitigations, and limitations.
