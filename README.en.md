[한국어](README.md) | **English**

# trustline

[![npm](https://img.shields.io/npm/v/trustline-scanner?logo=npm)](https://www.npmjs.com/package/trustline-scanner) [![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Trustline-2088FF?logo=github)](https://github.com/marketplace/actions/trustline-off-chain-scan) [![Demo](https://img.shields.io/badge/Demo-YouTube-FF0000?logo=youtube)](https://youtu.be/ACdar3TTPXI)

▶ Demo video: https://youtu.be/ACdar3TTPXI

Off-chain infrastructure security scanner. It finds the configuration mistakes
that turn a single breach into full compromise of a Web3 project's off-chain
stack (frontend, cloud, DNS, secrets).

Built from a real incident: a Next.js app was hit by an unauthenticated RCE
(React2Shell), and the damage could spread only because of a chain of config
mistakes. trustline checks for exactly those mistakes, before deploy.

## Quick start

Run it against your own repo with no install (Node 18+):

```bash
npx trustline-scanner scan .                       # scan the current dir's off-chain config
npx trustline-scanner scan . --html > report.html  # shareable HTML report
npx trustline-scanner scan . --sarif > out.sarif   # SARIF for GitHub code scanning
```

Before it is on npm, or for the latest source, run it straight from GitHub:

```bash
npx github:kyle-park-io/trustline scan .
```

You can hand this to an AI agent as-is: "before deploy, run
`npx trustline-scanner scan .` and fix anything critical/high." A non-zero exit
code means there is something to fix. `scan` is fully offline, so your code never
leaves the machine.

## Why

dApp security attention goes to smart contracts, but real incidents often break
the off-chain stack instead. Each check here maps to a real finding (and its
fix) from that incident.

## Threat model

The Open Security track's four required declarations, stated up front:

- **Threat model.** A remote attacker who gets code execution on the off-chain
  server (this incident's entry point was React2Shell, `CVE-2025-55182`;
  DPRK-linked actors are in scope). They can take over the off-chain
  operations/privilege layer; breaking on-chain contract logic itself is out of
  scope, and belongs to contract audits and on-chain guardrails.
- **Protected asset.** A dApp's keys, secrets, funds, and user data, and the
  off-chain operations layer that holds them.
- **Failure condition.** A single breach spreading past its blast radius into the
  keys, funds, or the whole cloud account.
- **Validation method.** `scan examples/vulnerable` = 18 critical / 34 total
  (exit 1) vs `scan examples/safe` = 0 findings (exit 0); before/after
  measurements from the real server; self-tests 35/35; and live, read-only
  on-chain recovery via `investigate-c2`. See the numbers below.

## Modules (v0.1)

Modules run across three axes: **blast-radius minimization** (keep one breach
from spreading), **detection** (catch the breach and the blind spots that hide
it), and **matching** (is this infra already touching known attacker ground).


- `vulnerable-dependency`: dependencies whose declared version matches a
  known-vulnerable release, checked against a small curated advisory set
  ([`data/advisories.json`](data/advisories.json)). This is not a general
  npm-audit: the set is anchored to this incident's own entry point (React2Shell,
  `CVE-2025-55182`, in the `react-server-dom-*` packages) and to a well-known
  Web3 supply-chain compromise (`@ledgerhq/connect-kit`). The point is to catch,
  before deploy, the exact vulnerable component that let this breach happen.
  Matches the version declared in `package.json`; lockfile-aware range resolution
  is future work.
- `bundle-secrets`: secrets in source or in browser-reachable build output
  (private keys, hard-coded API keys/tokens, JWTs). A secret in the client
  bundle is readable by any visitor.
- `network-exposure`: cloud firewall rules that open management/database ports
  (SSH, RDP, Postgres, Redis, ...) to `0.0.0.0/0`, and origins served directly
  to the internet instead of behind a CDN. Reads exported firewall JSON
  (`gcloud compute firewall-rules list --format=json > firewall.json`).
- `iam-privilege`: cloud IAM over-privilege. Service accounts bound to
  `roles/owner` or `roles/editor`, IAM roles granted to `allUsers`, and
  non-expiring user-managed service-account keys. Reads exported IAM JSON
  (`gcloud projects get-iam-policy PROJECT --format=json > iam-policy.json`,
  `gcloud iam service-accounts keys list --iam-account=SA --format=json > sa-keys.json`).
- `account-wide-credentials`: a single credential whose scope is the whole
  account/project where a resource-scoped one would do. Cloudflare global API
  keys (`X-Auth-Key` / `CLOUDFLARE_API_KEY`), the GCP `cloud-platform` OAuth
  scope, AWS policies granting `*` on `*`, and classic GitHub PATs. One leak of
  any of these hands over the entire account.

- `persistence-artifacts`: backdoor persistence indicators on a host. crontab
  `@reboot` launchers of hidden binaries, systemd units running hidden/temp
  executables, hidden XDG autostart entries, and shell rc files that background
  a hidden process. Point it at a home directory or an exported copy.
- `attack-signals`: attack attempts left in logs (a detection gap). Reverse
  shells, `curl|bash` payload pulls, failed shell commands from the app,
  SSRF-to-metadata probes, and cryptominer references. These are what a monitor
  should alert on: attacks usually leave signals before the damaging step, which
  is a window to detect and respond.
- `audit-telemetry-gap`: telemetry turned off before it becomes a blind spot.
  GCP Data Access audit logs not enabled (or with `exemptedMembers`), VPC flow
  logs disabled, and application logging/monitoring silenced. This was the exact
  blind spot in our incident: with Data Access logs off we could neither confirm
  nor rule out lateral movement after the RCE.
- `known-ioc`: match files against known-bad indicators drawn from this
  incident's on-chain forensics: the EtherRAT C2 contracts and endpoints
  (domains, IPs), the address-poisoning drainer wallets, the WEMIX laundering
  path, the `setString` C2-write selector, and homoglyph spoof-token strings.
  Unlike the other modules (which judge whether a config is dangerous), this asks
  whether infrastructure is already touching attacker-controlled ground; one hit
  is a likely compromise, not a smell. The dataset
  ([`data/iocs.json`](data/iocs.json)) lists attacker-controlled indicators only:
  legitimate services that were abused (exchange hot wallets, swap routers,
  bridges) are deliberately excluded so scanning them raises nothing.

More planned: a broader advisory set with lockfile-aware version matching,
secrets baked into container images, and post-deploy continuous monitoring.

## Usage

```bash
pnpm install       # dev-only deps (typescript); zero runtime dependencies
pnpm build
node dist/src/cli.js scan <dir>          # human-readable
node dist/src/cli.js scan <dir> --json   # machine-readable
node dist/src/cli.js scan <dir> --html  > report.html   # standalone HTML report
node dist/src/cli.js scan <dir> --sarif > trustline.sarif  # SARIF 2.1.0
```

Exit code is non-zero when any critical or high finding is present, so it drops
into CI.

## CI integration

`scan --sarif` emits SARIF 2.1.0, so findings show up in GitHub's Security tab
and as PR annotations. A composite GitHub Action ([`action.yml`](action.yml))
wraps the scan; wire it up with `upload-sarif`:

```yaml
# .github/workflows/trustline.yml
name: trustline
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: kyle-park-io/trustline@v0.1.0
        with:
          path: .
          fail-on-findings: "true"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trustline.sarif
```

This repo's own CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs
`pnpm build && pnpm test` on every push and PR.

## Threat intel: blockchain C2 (needs network)

EtherRAT (seen in the incident) reads its command-and-control address from an
Ethereum smart contract, so blocking a domain cannot kill it. `investigate-c2`
reads that contract's public on-chain data and recovers the C2 values the
operator wrote to it. It is read-only: it sends no transaction and never
interacts with the contract; `eth_call` is a local simulation.

```bash
node dist/src/cli.js investigate-c2                 # defaults to the EtherRAT C2 contract
node dist/src/cli.js investigate-c2 <address> --json
```

### Fleet mode: `--cluster`

From one C2 contract, `--cluster` maps the fleet around it: the deployer (the
contract's creator), the funding hub that gas-funded the deployer, and the
sibling C2 contracts that the hub's operators wrote C2 strings to (via the
`setString` selector). Bounded, best-effort, and read-only.

```bash
node dist/src/cli.js investigate-c2 --cluster       # fleet around the default seed
node dist/src/cli.js investigate-c2 <address> --cluster --json
```

### Address poisoning: `investigate-poison`

Checks an address's public history for address-poisoning: vanity lookalikes (a
counterparty sharing your first-4 and last-4 hex, minted to fool a copy-paste),
value-mimic dust (tiny/zero transfers planted in your history), and
spoof/homoglyph tokens (fake tokens named to imitate ETH/USDC). Read-only.

```bash
node dist/src/cli.js investigate-poison <address>
node dist/src/cli.js investigate-poison <address> --json
```

The `investigate-*` commands are the only ones that use the network (keyless
public RPC + explorer). `scan` stays fully offline. See
[`ONCHAIN-FORENSICS.md`](ONCHAIN-FORENSICS.md) for what these recover (an
EtherRAT multi-C2 campaign and an address-poisoning drainer op), with IOCs and
how to reproduce it.

## Demo

```bash
pnpm build
node dist/src/cli.js scan examples/vulnerable   # findings, exit 1
node dist/src/cli.js scan examples/safe          # clean, exit 0
```

`examples/vulnerable` is the "before" (mistakes present); `examples/safe` is the
"after" (the same stack, fixed). Nothing here touches a real service; it only
reads local files.

## Test

```bash
pnpm test
```

Runs the scanner against both examples and asserts the before/after behaviour.

## TRUST404 submission

This repository is the public, de-identified artifact for a TRUST404 (Track 05,
Open Security) submission. Everything here is v0.1 built for this submission from
a real off-chain incident: the `scan` modules across the three axes (blast-radius
minimization, detection, and IOC matching) including the `vulnerable-dependency`
check anchored to the incident's own entry point, the `investigate-c2` on-chain
command with its fleet (`--cluster`) mode, the `investigate-poison`
address-poisoning check, HTML and SARIF reporting with a GitHub Action for CI, the
synthetic `examples/`, and the self-tests. The most novel pieces are the on-chain
commands, which recover a malware family's command-and-control values (and the
fleet around them) from Ethereum smart contracts using only public, read-only
data, and turn that investigation into the `known-ioc` dataset.

Verified on 2026-09-20: `scan examples/vulnerable` = 18 critical / 34 total
(exit 1), `scan examples/safe` = 0 findings (exit 0), self-tests 35/35 pass.
`investigate-c2 --cluster` and `investigate-poison` were confirmed live against
public chain data.

## AI usage

The author led the incident response, investigation, and design decisions; AI
(Anthropic's Claude) was used as a tool where it helped most: drafting and
refactoring the scanner and tests, analyzing the incident, and the read-only
on-chain forensics behind the checks. Every finding, number, and on-chain claim
was verified against a primary source or live data before inclusion, and the
author reviewed the result.

## Notes

- `scan` runs fully offline and reads only local files (source, build output,
  exported cloud config). It never attacks a live service.
- The `investigate-*` commands are the only ones that use the network, and only
  read public blockchain data (no transaction, no interaction).
- Everything under `examples/` is synthetic. No real secrets or hostnames.
