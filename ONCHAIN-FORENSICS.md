# On-chain forensics with `investigate-c2`

Modern malware can hide its command-and-control (C2) address inside a smart
contract, so a takedown that blocks a domain or an IP does not stop it.
`investigate-c2` turns that against the operator: the C2 configuration written
on-chain is public, read-only data that anyone can recover. This document is the
evidence behind trustline's "recover on-chain threats with on-chain data" claim.

Everything here uses a public RPC + explorer and is **read-only**: no
transaction is ever sent, and `eth_call` is a local simulation. Recovered
domains are treated as inert IOC strings and were never resolved or visited.

## EtherRAT: C2 recovered from a contract

EtherRAT is a React2Shell-delivered implant whose C2 contract address was
disclosed by Sysdig. It reads its C2 endpoint from that Ethereum contract, which
the operator updates with a `setString` call (selector `0x7fcaf666`). Reading
the contract's public data recovered:

- The C2 values the operator wrote and rotated over 2025-12-05 to 12-08: two
  `IP:port` endpoints and an IP-logger link (nine `setString` writes = beacon
  re-tasking).
- That it was not a lone contract. One funding hub deployed and funded **three**
  C2 contracts across 2025-12-04 to 12-20, and two of them served
  **previously-undisclosed C2 domains** recovered from their `setString`
  history. Each contract received `setString` only from its own deployer.

`--cluster` automates that fleet reconstruction: from one seed contract it walks
seed → deployer (creator) → funding hub (earliest ETH in) → the hub's payees,
and reports the C2 contracts each payee wrote to via `setString`. It is
bounded/best-effort (it works within the explorer's recent-transaction pages), so
it may not surface every sibling in one run; it prints its method alongside the
result.

Reproduce: `node dist/src/cli.js investigate-c2` (defaults to the disclosed
contract), or `investigate-c2 --cluster` for the fleet, against any public
Ethereum RPC + explorer.

### IOCs (defanged; on-chain public data)

- C2 contracts (Ethereum): `0x40A7d723F5Df6c88464bC95DBf7D96573fBc4f85`,
  `0x22f96d61cf118efabc7c5bf3384734fad2f6ead4`,
  `0xF1f3Ac96E49F6a71D031444E59268c27B3511914`
- Deployer / funding hub: `0xE941A9b283006F5163EE6B01c1f23AA5951c4C8D`,
  `0x14afdDD627Fb0e039365554f8bbDB881eCb1C708`
- Recovered C2 strings: `hxxp://173.249.8[.]102`, `hxxp://91.215.85[.]42:3000`,
  `hxxps://grabify[.]link/SEFKGU`, `api-gateway-prod[.]com`,
  `api-gateway-softupdate[.]io`
- On-chain C2 write pattern: `setString` selector `0x7fcaf666`

## The same read-only method, applied wider

The identical approach reconstructs money movement the parties never published:

- **A 2026 unauthorized-mint incident** on an EVM chain: recovered the attack
  transaction, the attacker address, and the exact mint/burn mechanism (net
  issuance reconciled to the reported figure), then followed the bridged funds
  on Ethereum to named exchange off-ramps.
- **An active address-poisoning / token-drainer collection cluster**: five
  collector wallets funnel roughly six hundred victim inflows into a master sink
  that liquidates tokens through public swap aggregators and cashes out across
  five centralized exchanges. Still active as of this writing.

`investigate-poison <address>` packages the poisoning half of that analysis: for
any address it reports vanity lookalikes (a counterparty sharing your first-4 and
last-4 hex), value-mimic dust (tiny/zero transfers planted in history), and
spoof/homoglyph tokens named to imitate ETH/USDC. Read-only.

Those two full traces are not shipped in this repository (they name third-party
and victim addresses), but they were produced with nothing more than this tool's
read-only method.

## The investigation, shipped as a dataset

`data/iocs.json` turns the traces above into a matchable IOC set for the
`known-ioc` scan module: the EtherRAT C2 contracts and endpoints, the
address-poisoning drainer wallets, the WEMIX laundering path, the `setString`
selector, and the homoglyph spoof-token strings. It lists **attacker-controlled
indicators only**. Legitimate services that were abused (exchange hot wallets,
swap routers, bridges) are deliberately excluded so scanning them raises nothing.
This is how the read-only on-chain work feeds back into the offline scanner.

## Why it matters for defenders

- C2 that lives on-chain resists domain/IP takedown yet is fully transparent to
  a reader; the operator's own configuration is evidence.
- The recovered C2 strings, contract addresses, and deployer/funding wallets are
  IOCs a defender can block and hunt on.
- Read-only means it is safe to run inside an investigation: no interaction with
  attacker infrastructure, no tip-off.
