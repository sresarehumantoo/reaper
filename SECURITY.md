# Security policy

## What reaper is

reaper is a static and dynamic analysis tool for triaging suspicious JavaScript.
It is designed to be run **against** untrusted code, not by untrusted code.

This repository ships real, live malware samples under `examples/` (see the warning in the main `README.md`). They are checked in as inert data files so they can be re-analysed reproducibly. They will not execute unless deliberately run.

## Threat model

reaper makes two distinct security claims, with different strengths:

1. **The Docker sandbox at `docker/Dockerfile` + `scripts/analyze.sh` is a real isolation boundary.** It uses kernel namespaces, dropped Linux capabilities, seccomp, a read-only root filesystem, a non-root user, resource caps, no network, and no IPC. Any breakout would be a Docker / kernel vulnerability and should be reported to the corresponding upstream first.

2. **The in-process VM context in `src/analyzers/evalscope.ts` is NOT an isolation boundary.** Node's `vm` module is explicitly documented as not being a security mechanism. A hostile sample analysed via `--reachability` can in principle reach the analyst's process. Mitigations in place (timeouts, stubbed globals, dropped dangerous APIs) are best-effort.

   **Recommendation:** if you are analysing a sample whose authorship you do not trust, run reaper itself inside the Docker sandbox, or use only the dynamic pipeline (`./scripts/analyze.sh ... --dynamic-only`) rather than `--reachability`.

## Supported versions

| Version | Supported |
|---|---|
| 0.x | Latest minor only |

reaper is pre-1.0; API and CLI surface may change between minor versions.

## Reporting a vulnerability

If you find a security issue in reaper itself (not in one of the malware samples), open a private security advisory on GitHub: <https://github.com/sresarehumantoo/reaper/security/advisories/new>.

For findings in the malware samples themselves — please don't. Those are the artifacts being studied, not part of reaper. If a sample turns out to be **misclassified** (i.e., it is not actually malicious), open a regular issue.

Please include:

- the affected file or component
- a minimal reproduction
- the impact (information disclosure, code execution on the analyst host, sandbox escape, etc.)
- any suggested fix

We aim to acknowledge reports within 7 days and ship a fix or a documented mitigation within 30 days, depending on severity. For sandbox escapes, faster.

## Out of scope

- Vulnerabilities in upstream Docker, Node.js, or `@babel/*` — report to those projects.
- The contents of `examples/`. Those files are malware; they are supposed to do bad things if you run them.
- Submitting reaper itself to public malware feeds. It is an analyzer, not malware.

## Responsible use

reaper is intended for: defensive malware analysis, incident response, CTF challenges, academic research, and pre-deployment review of dependencies.

It is **not** intended for: weaponising new malware, removing signatures from existing samples to evade detection, or any use that meaningfully aids attackers.

If your use case sits in a grey area, talk to your legal / ethics review process first.
