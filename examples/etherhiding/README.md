# EtherHiding — walkthrough

This directory contains a complete, reproducible analysis of an in-the-wild **EtherHiding + ClickFix** sample. Every artifact named below is committed to the repository; you can follow the steps without making any network call.

> [!CAUTION]
> **The files under `artifacts/` are real, live malware**, fetched directly from attacker-controlled smart contracts on the BNB Smart Chain testnet. They are committed as inert data files (`.js`, `.b64`, `.hex`, `.txt`) and will not run unless you deliberately execute them. Do not run any `clipboard-payload.txt`, do not paste it into a shell, do not `node` any `.js` file under `artifacts/`. The repository ships these for reverse-engineering, not for use.

## Contents

- `sample.html` — minimal HTML shell containing the malicious `<script src="data:text/javascript;base64,...">` payload from the original DOM dump. This is the only file a victim browser ever sees.
- `REPORT.md` — full malware analysis report. Read this for the actual findings.
- `SHA256SUMS` — integrity hashes for every artifact in this tree.
- `artifacts/` — every intermediate and final-stage artifact in the chain, organised by stage.

```
artifacts/
├── stage1/                      browser-side loader (carried in sample.html)
│   ├── payload.b64                base64 extracted from the <script src=...>
│   ├── payload.js                 base64-decoded — JavaScript, still obfuscated
│   └── payload.deobf.js           reaper-rewritten plaintext loader
├── stage2/                      dispatcher (lives in BSC contract 0xA1decFB7...d2e)
│   ├── eth_call-response.json     full JSON-RPC reply from the testnet RPC
│   ├── eth_call-result.hex        raw return bytes
│   ├── dispatcher.b64             ABI-decoded string (still base64)
│   └── dispatcher.js              dispatcher JavaScript in plaintext
├── stage3-windows/              Windows payload (BSC contract 0x46790e2A...3Ff)
│   ├── eth_call-response.json
│   ├── eth_call-result.hex
│   ├── outer.b64                  ABI-decoded base64 layer
│   ├── outer.js                   outer envelope (Yandex Metrika + eval-atob inner)
│   ├── inner.js                   obfuscator.io-encoded inner payload
│   ├── inner.deobf.js             reaper-rewritten plaintext
│   └── clipboard-payload.txt      the single line that lands on victim's clipboard
└── stage3-mac/                  same shape as stage3-windows for macOS branch
    └── ...
```

## Reproducing the analysis end-to-end

Every step below operates on the committed files. No network. No execution of the malware.

### 1. Static scan of the original sample

```sh
npx tsx src/cli.ts examples/etherhiding/sample.html
```

reaper auto-extracts the base64 data URI and runs every analyzer on the decoded JS. Expected output: two findings — a `Direct eval() call` and an `atob() call`. That is the entire visible behaviour at this layer.

### 2. Deobfuscate the stage-1 loader

```sh
npx tsx src/cli.ts examples/etherhiding/sample.html --rewrite /tmp/reaper-out
diff /tmp/reaper-out/examples__etherhiding__sample.data-uri-0.deobf.js \
     examples/etherhiding/artifacts/stage1/payload.deobf.js
```

`--rewrite` runs the obfuscator.io string-array detector against the decoded payload, statically resolves all 28 wrapper calls, and produces the plaintext loader. The `diff` should be empty — the committed `payload.deobf.js` is what reaper produces today on this input.

Read the result. It is roughly 30 lines and does one thing: `fetch` against the BSC testnet RPC, ABI-decode the returned string, `eval(atob(...))`.

### 3. (Optional) Read the next stage from the contract

This step **does make one outbound network call**, to the public BNB testnet RPC, to fetch the dispatcher payload from contract storage. It is a read (`eth_call`, no gas, no signed transaction). You can skip it and use the committed `artifacts/stage2/dispatcher.js` directly.

```sh
./examples/etherhiding/fetch-evm-payload.mjs \
    0xA1decFB75C8C0CA28C10517ce56B710baf727d2e \
    --out /tmp/dispatcher.js
diff /tmp/dispatcher.js examples/etherhiding/artifacts/stage2/dispatcher.js
```

If the diff is empty, the contract has not been updated since the commit. **If it is non-empty, the operator has rotated the payload**, which is a finding in its own right.

### 4. Examine the dispatcher

```sh
cat examples/etherhiding/artifacts/stage2/dispatcher.js
```

The dispatcher defines an identical `load_` function and routes per-OS:

- Windows: fetch from `0x46790e2Ac7F3CA5a7D1bfCe312d11E91d23383Ff`
- macOS: fetch from `0x68DcE15C1002a2689E19D33A3aE509DD1fEb11A5`
- Headless or local browsers: `console.log("stop watching us :)")` and exit.

### 5. Deobfuscate the stage-3 payloads

```sh
npx tsx src/cli.ts examples/etherhiding/artifacts/stage3-windows/inner.js --rewrite /tmp/out
npx tsx src/cli.ts examples/etherhiding/artifacts/stage3-mac/inner.js     --rewrite /tmp/out
```

reaper resolves roughly 95% of wrapper calls. The remaining handful are wrappers whose arguments are not const-evaluable from local scope (passed as parameters, computed at runtime).

### 6. Read the clipboard payloads

```sh
cat examples/etherhiding/artifacts/stage3-windows/clipboard-payload.txt
cat examples/etherhiding/artifacts/stage3-mac/clipboard-payload.txt
```

These are the strings the malware silently puts on the victim's clipboard. The Windows version invokes `rundll32` against a remote DLL over WebDAV-HTTPS. The macOS version is `bash -c "$(curl ...)"` against an attacker-controlled host. Both are intended to be pasted by the victim into Run / Terminal after being prompted by a fake "BotGuard" overlay.

### 7. Dynamic confirmation (optional, Docker required)

```sh
./scripts/analyze.sh examples/etherhiding/artifacts/stage1/payload.deobf.js \
    --dynamic-only --observe-network --timeout 8
```

The sandbox runs the loader inside a `--network none` container with a stub `fetch` responder. You will see a single `[REAPER] {"category":"fetch", ...}` line showing the exact JSON-RPC body the loader would have sent against the live BSC RPC, with the contract address and selector in plaintext. No real egress occurs.

## Verifying integrity

```sh
cd examples/etherhiding && sha256sum -c SHA256SUMS
```

If any artifact has been modified, this will report the mismatch. The `artifacts/` tree is a frozen snapshot; the live contract state can and does rotate, so subsequent re-fetches via step 3 may produce different bytes.

## See also

`REPORT.md` (this directory) — the analysis writeup, indicators, mitigations, and limitations.
