// Threat-intel helper: characterise a blockchain command-and-control contract
// from public on-chain data. EtherRAT (seen in the incident) reads its C2
// address from an Ethereum smart contract, so a domain block cannot kill it;
// this reads that contract's public footprint. Read-only: it never sends a
// transaction. eth_call is a local simulation and changes no state.
//
// Needs network. Uses keyless public endpoints and Node's built-in fetch.

import { readFileSync } from "node:fs";
import { findUp } from "./util";

// EtherRAT C2 contract on Ethereum mainnet (published by Sysdig).
export const ETHERRAT_C2 = "0x22f96d61cf118efabc7c5bf3384734fad2f6ead4";

// The selector for setString(string): how an EtherRAT operator writes/rotates
// the C2 value on its contract. Each C2's setString comes from its deployer EOA.
export const SETSTRING_SELECTOR = "0x7fcaf666";

const RPC = "https://ethereum-rpc.publicnode.com";
const BLOCKSCOUT = "https://eth.blockscout.com/api/v2";

async function withTimeout<T>(fn: (signal: AbortSignal) => Promise<T>, ms = 15000): Promise<T> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    return await fn(ac.signal);
  } finally {
    clearTimeout(t);
  }
}

async function rpc(method: string, params: unknown[]): Promise<string | null> {
  try {
    return await withTimeout(async (signal) => {
      const res = await fetch(RPC, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal,
      });
      const j = (await res.json()) as { result?: string };
      return j.result ?? null;
    });
  } catch {
    return null;
  }
}

async function blockscout(path: string): Promise<any | null> {
  try {
    return await withTimeout(async (signal) => {
      const res = await fetch(`${BLOCKSCOUT}${path}`, { headers: { accept: "application/json" }, signal });
      if (!res.ok) return null;
      return res.json();
    });
  } catch {
    return null;
  }
}

/** Interpret 32 bytes as an address and/or a short (in-slot) Solidity string. */
function decode32(hex: string): { address?: string; text?: string } {
  const out: { address?: string; text?: string } = {};
  const clean = hex.replace(/^0x/, "").padStart(64, "0");
  if (/^0{24}[0-9a-f]{40}$/.test(clean) && !/^0{64}$/.test(clean)) {
    out.address = "0x" + clean.slice(24);
  }
  const buf = Buffer.from(clean, "hex");
  const lenByte = buf[31];
  if (lenByte > 0 && lenByte % 2 === 0 && lenByte / 2 <= 31) {
    const s = buf.subarray(0, lenByte / 2).toString("utf8");
    if (/^[\x20-\x7e]+$/.test(s)) out.text = s;
  }
  return out;
}

/** Decode an eth_call return value: a 32-byte word, or an ABI dynamic string. */
function decodeReturn(hex: string): { address?: string; text?: string } {
  const clean = hex.replace(/^0x/, "");
  if (clean.length === 64) return decode32(hex);
  if (clean.length >= 128) {
    const offset = parseInt(clean.slice(0, 64), 16);
    if (offset === 0x20) {
      const len = parseInt(clean.slice(64, 128), 16);
      if (len > 0 && len <= 1024 && 128 + len * 2 <= clean.length) {
        const s = Buffer.from(clean.slice(128, 128 + len * 2), "hex").toString("utf8");
        if (/^[\x09\x0a\x0d\x20-\x7e]+$/.test(s)) return { text: s };
      }
    }
  }
  return {};
}

/** Decode the string argument of a setter call from its raw calldata. */
function decodeStringArg(rawInput: string): string | undefined {
  const clean = rawInput.replace(/^0x/, "").slice(8); // drop the 4-byte selector
  const dec = decodeReturn("0x" + clean);
  return dec.text;
}

export interface C2Report {
  address: string;
  reachable: boolean;
  isContract: boolean;
  info?: {
    creator?: string;
    creationTx?: string;
    balanceEth?: string;
    txCount?: number;
    verified?: boolean;
    name?: string;
  };
  activity?: { firstSeen?: string; lastSeen?: string; sampled: number; uniqueSenders: number; methods: string[] };
  /** C2 values written on-chain by the operator, newest first. */
  c2History: { when?: string; value: string }[];
  storage: { slot: number; raw: string; address?: string; text?: string }[];
}

export async function investigateC2(address: string): Promise<C2Report> {
  const addr = address.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(addr)) throw new Error(`not an Ethereum address: ${address}`);

  const code = await rpc("eth_getCode", [addr, "latest"]);
  const reachable = code !== null;
  const isContract = !!code && code !== "0x";
  const report: C2Report = { address: addr, reachable, isContract, c2History: [], storage: [] };

  const info = await blockscout(`/addresses/${addr}`);
  const counters = await blockscout(`/addresses/${addr}/counters`);
  if (info) {
    const balWei = BigInt(info.coin_balance ?? "0");
    report.info = {
      creator: info.creator_address_hash ?? undefined,
      creationTx: info.creation_transaction_hash ?? info.creation_tx_hash ?? undefined,
      balanceEth: (Number(balWei) / 1e18).toFixed(6),
      txCount: counters ? Number(counters.transactions_count ?? 0) : undefined,
      verified: info.is_verified ?? undefined,
      name: info.name ?? undefined,
    };
  }

  const txs = await blockscout(`/addresses/${addr}/transactions`);
  if (txs && Array.isArray(txs.items) && txs.items.length) {
    const items = txs.items;
    const times = items.map((t: any) => t.timestamp).filter(Boolean).sort();
    const senders = new Set(items.map((t: any) => t.from?.hash).filter(Boolean));
    const methods = new Set(items.map((t: any) => t.method).filter((x: unknown) => typeof x === "string"));
    report.activity = {
      firstSeen: times[0],
      lastSeen: times[times.length - 1],
      sampled: items.length,
      uniqueSenders: senders.size,
      methods: [...methods] as string[],
    };

    // The operator writes the C2 on-chain via a string setter. Decode the value
    // from each such transaction's calldata to recover the C2 history.
    const seen = new Set<string>();
    for (const t of items.slice(0, 8)) {
      if (typeof t.method !== "string") continue;
      const detail = await blockscout(`/transactions/${t.hash}`);
      let value: string | undefined;
      const param = detail?.decoded_input?.parameters?.find((p: any) => p?.type === "string");
      if (param && typeof param.value === "string") value = param.value;
      else if (detail?.raw_input) value = decodeStringArg(detail.raw_input);
      if (value && !seen.has(value)) {
        seen.add(value);
        report.c2History.push({ when: t.timestamp, value });
      }
    }
  }

  for (let slot = 0; slot < 5; slot++) {
    const raw = await rpc("eth_getStorageAt", [addr, "0x" + slot.toString(16), "latest"]);
    if (raw && raw !== "0x" && !/^0x0+$/.test(raw)) report.storage.push({ slot, raw, ...decode32(raw) });
  }

  return report;
}

export function printC2Report(r: C2Report): void {
  console.log(`\ntrustline investigate-c2  ${r.address}\n`);
  if (!r.reachable) {
    console.log("  Could not reach the Ethereum RPC (offline or endpoint down). Nothing to report.\n");
    return;
  }
  console.log(`  is contract:     ${r.isContract ? "yes" : "no (EOA)"}`);
  if (r.info) {
    if (r.info.name) console.log(`  name:            ${r.info.name}`);
    console.log(`  verified source: ${r.info.verified ? "yes" : "no"}`);
    if (r.info.creator) console.log(`  deployed by:     ${r.info.creator}`);
    if (r.info.creationTx) console.log(`  creation tx:     ${r.info.creationTx}`);
    if (r.info.txCount !== undefined) console.log(`  total txs:       ${r.info.txCount}`);
    console.log(`  balance:         ${r.info.balanceEth} ETH`);
  }
  if (r.activity) {
    console.log(`  first seen:      ${r.activity.firstSeen ?? "?"}`);
    console.log(`  last seen:       ${r.activity.lastSeen ?? "?"}`);
    console.log(`  sampled txs:     ${r.activity.sampled} (unique senders: ${r.activity.uniqueSenders})`);
    if (r.activity.methods.length) console.log(`  methods:         ${r.activity.methods.join(", ")}`);
  }
  if (r.c2History.length) {
    console.log(`  C2 values written on-chain (newest first):`);
    for (const h of r.c2History) {
      console.log(`    ${h.when ?? "?"}  ${h.value}`);
    }
  }
  if (r.storage.length) {
    console.log(`  storage slots with data:`);
    for (const s of r.storage) {
      const notes: string[] = [];
      if (s.address) notes.push(`address=${s.address}`);
      if (s.text) notes.push(`text="${s.text}"`);
      console.log(`    [${s.slot}] ${s.raw.slice(0, 26)}...${notes.length ? "  (" + notes.join(", ") + ")" : ""}`);
    }
  }
  console.log(
    `\n  Read-only public chain data (no transaction sent). This confirms the C2\n` +
      `  contract is live and characterises it; a returned address/URL is the C2 the\n` +
      `  malware would fetch. A domain block cannot remove an on-chain C2.\n`,
  );
}

// ------------------------------------------------------------------
// Cluster mode: from one C2 contract, map the fleet around it.
// seed -> deployer (creator) -> funder (the hub) -> the hub's payees;
// each payee's setString calls point at the C2 contracts it operates.
// ------------------------------------------------------------------

function safeBig(v: unknown): bigint {
  try {
    return BigInt(String(v ?? "0"));
  } catch {
    return 0n;
  }
}

async function addressTxs(addr: string): Promise<any[]> {
  const j = await blockscout(`/addresses/${addr}/transactions`);
  return j && Array.isArray(j.items) ? j.items : [];
}

/** The EOA that created a contract, from public chain data. */
async function creatorOf(addr: string): Promise<string | undefined> {
  const info = await blockscout(`/addresses/${addr}`);
  const c = info?.creator_address_hash;
  return typeof c === "string" ? c.toLowerCase() : undefined;
}

/** The earliest address that sent this account ETH (its funder). */
async function earliestFunder(addr: string): Promise<string | undefined> {
  const items = await addressTxs(addr);
  const incoming = items
    .filter((t) => t?.to?.hash?.toLowerCase() === addr && safeBig(t.value) > 0n && t?.from?.hash)
    .sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp)));
  return incoming[0]?.from?.hash?.toLowerCase();
}

/** Contracts an account wrote a C2 string to (its setString targets). */
async function setStringTargets(op: string): Promise<string[]> {
  const items = await addressTxs(op);
  const targets = new Set<string>();
  for (const t of items) {
    const isSet =
      t?.method === "setString" ||
      (typeof t?.raw_input === "string" && t.raw_input.toLowerCase().startsWith(SETSTRING_SELECTOR));
    if (isSet && t?.to?.hash) targets.add(t.to.hash.toLowerCase());
  }
  return [...targets];
}

export interface ClusterReport {
  seed: string;
  reachable: boolean;
  deployer?: string;
  hub?: string;
  operators: { address: string; c2Contracts: string[] }[];
  c2Contracts: string[];
  notes: string[];
}

export async function investigateCluster(seed: string): Promise<ClusterReport> {
  const addr = seed.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(addr)) throw new Error(`not an Ethereum address: ${seed}`);
  const report: ClusterReport = { seed: addr, reachable: false, operators: [], c2Contracts: [], notes: [] };

  const probe = await rpc("eth_getCode", [addr, "latest"]);
  report.reachable = probe !== null;
  if (!report.reachable) {
    report.notes.push("Could not reach the Ethereum RPC/API (offline or endpoint down).");
    return report;
  }

  report.deployer = await creatorOf(addr);
  if (!report.deployer) report.notes.push("No creator on record for the seed (an EOA, or not indexed).");

  if (report.deployer) {
    report.hub = await earliestFunder(report.deployer);
    if (!report.hub) report.notes.push("Could not identify a funder for the deployer.");
  }

  // Candidate operators: the deployer, the hub, and everyone the hub paid.
  const candidates = new Set<string>();
  if (report.deployer) candidates.add(report.deployer);
  if (report.hub) {
    candidates.add(report.hub);
    const hubTxs = await addressTxs(report.hub);
    const paid = hubTxs
      .filter((t) => t?.from?.hash?.toLowerCase() === report.hub && safeBig(t.value) > 0n && t?.to?.hash)
      .map((t) => t.to.hash.toLowerCase());
    for (const p of paid.slice(0, 12)) candidates.add(p);
  }

  const seen = new Set<string>();
  for (const op of candidates) {
    if (seen.size >= 12) break;
    seen.add(op);
    const c2s = await setStringTargets(op);
    if (c2s.length) {
      report.operators.push({ address: op, c2Contracts: c2s });
      for (const c of c2s) if (!report.c2Contracts.includes(c)) report.c2Contracts.push(c);
    }
  }
  if (!report.c2Contracts.includes(addr)) report.c2Contracts.unshift(addr);

  report.notes.push(
    `Method: seed -> deployer (creator) -> funder (earliest ETH in) -> the hub's payees; ` +
      `each payee's setString (${SETSTRING_SELECTOR}) calls point at the C2 contracts it operates. ` +
      `Bounded, best-effort, read-only.`,
  );
  return report;
}

export function printClusterReport(r: ClusterReport): void {
  console.log(`\ntrustline investigate-c2 --cluster  ${r.seed}\n`);
  if (!r.reachable) {
    console.log("  " + (r.notes[0] ?? "unreachable") + "\n");
    return;
  }
  console.log(`  seed C2:         ${r.seed}`);
  if (r.deployer) console.log(`  deployed by:     ${r.deployer}`);
  if (r.hub) console.log(`  funding hub:     ${r.hub}`);
  console.log(`  operators found: ${r.operators.length}`);
  for (const o of r.operators) {
    console.log(`    ${o.address}`);
    for (const c of o.c2Contracts) console.log(`      -> C2 ${c}`);
  }
  console.log(`  C2 contracts in cluster (${r.c2Contracts.length}):`);
  for (const c of r.c2Contracts) console.log(`    ${c}`);
  for (const n of r.notes) console.log(`\n  ${n}`);
  console.log();
}

// ------------------------------------------------------------------
// Address-poisoning check: does this address's history carry vanity
// lookalikes, value-mimic dust, or spoof/homoglyph tokens?
// ------------------------------------------------------------------

export function first4last4(addr: string): { first4: string; last4: string } {
  const h = addr.toLowerCase().replace(/^0x/, "");
  return { first4: h.slice(0, 4), last4: h.slice(-4) };
}

/** Two addresses that share first-4 and last-4 hex but are not equal: the
 *  vanity lookalike an address-poisoning attacker mints to fool a copy-paste. */
export function isLookalike(victim: string, other: string): boolean {
  const re = /^0x[0-9a-f]{40}$/i;
  if (!re.test(victim) || !re.test(other)) return false;
  const v = victim.toLowerCase();
  const o = other.toLowerCase();
  if (v === o) return false;
  const a = first4last4(v);
  const b = first4last4(o);
  return a.first4 === b.first4 && a.last4 === b.last4;
}

// Dust threshold: 0.0001 ETH. Poisoning transfers are 0-value or tiny.
const DUST_WEI = 100000000000000n;

function loadSpoofNames(): string[] {
  try {
    const p = findUp("data/iocs.json");
    if (!p) return [];
    const data = JSON.parse(readFileSync(p, "utf8"));
    const bait: string[] = Array.isArray(data.baitTokens) ? data.baitTokens : [];
    const homo: string[] = Array.isArray(data.spoofStrings)
      ? data.spoofStrings.map((s: any) => s.value).filter((x: unknown) => typeof x === "string")
      : [];
    return [...bait, ...homo];
  } catch {
    return [];
  }
}

export interface PoisonReport {
  address: string;
  reachable: boolean;
  lookalikes: { address: string; via: string; when?: string }[];
  dust: { from: string; count: number; valueEth: string; lookalike: boolean }[];
  spoofTokens: { token: string; from?: string; when?: string }[];
  notes: string[];
}

export async function investigatePoisoning(address: string): Promise<PoisonReport> {
  const addr = address.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(addr)) throw new Error(`not an Ethereum address: ${address}`);
  const report: PoisonReport = { address: addr, reachable: false, lookalikes: [], dust: [], spoofTokens: [], notes: [] };

  const probe = await rpc("eth_getCode", [addr, "latest"]);
  report.reachable = probe !== null;
  if (!report.reachable) {
    report.notes.push("Could not reach the Ethereum RPC/API (offline or endpoint down).");
    return report;
  }

  const spoof = loadSpoofNames();
  const seenLook = new Set<string>();
  // Aggregate dust by sender so one spammer does not flood the report.
  const dustBy = new Map<string, { count: number; minWei: bigint; lookalike: boolean }>();

  // Native transfers: vanity lookalikes and value-mimic dust.
  for (const t of await addressTxs(addr)) {
    const from = t?.from?.hash?.toLowerCase();
    const to = t?.to?.hash?.toLowerCase();
    const other = from === addr ? to : from;
    if (other && isLookalike(addr, other) && !seenLook.has(other)) {
      seenLook.add(other);
      report.lookalikes.push({ address: other, via: "native tx", when: t.timestamp });
    }
    const val = safeBig(t.value);
    if (from && from !== addr && val < DUST_WEI) {
      const cur = dustBy.get(from) ?? { count: 0, minWei: val, lookalike: isLookalike(addr, from) };
      cur.count += 1;
      if (val < cur.minWei) cur.minWei = val;
      dustBy.set(from, cur);
    }
  }
  report.dust = [...dustBy.entries()]
    .map(([from, d]) => ({ from, count: d.count, valueEth: (Number(d.minWei) / 1e18).toFixed(8), lookalike: d.lookalike }))
    // lookalike dust first (the strongest signal), then the noisiest senders
    .sort((a, b) => Number(b.lookalike) - Number(a.lookalike) || b.count - a.count)
    .slice(0, 15);

  // Token transfers: vanity lookalikes and spoof/homoglyph token symbols.
  const tt = await blockscout(`/addresses/${addr}/token-transfers`);
  const items = tt && Array.isArray(tt.items) ? tt.items : [];
  for (const it of items) {
    const from = it?.from?.hash?.toLowerCase();
    const to = it?.to?.hash?.toLowerCase();
    const other = from === addr ? to : from;
    if (other && isLookalike(addr, other) && !seenLook.has(other)) {
      seenLook.add(other);
      report.lookalikes.push({ address: other, via: "token transfer", when: it.timestamp });
    }
    const sym = it?.token?.symbol ?? it?.token?.name;
    if (typeof sym === "string" && spoof.some((s) => sym.includes(s))) {
      report.spoofTokens.push({ token: sym, from, when: it.timestamp });
    }
  }

  report.notes.push(
    "Vanity lookalike = an address sharing your first-4 and last-4 hex, minted to fool a copy-paste. " +
      "Value-mimic dust = tiny/zero transfers planted in your history. Read-only.",
  );
  return report;
}

export function printPoisonReport(r: PoisonReport): void {
  console.log(`\ntrustline investigate-poison  ${r.address}\n`);
  if (!r.reachable) {
    console.log("  " + (r.notes[0] ?? "unreachable") + "\n");
    return;
  }
  console.log(`  vanity lookalikes:      ${r.lookalikes.length}`);
  for (const l of r.lookalikes) console.log(`    ${l.address}  (${l.via}${l.when ? ", " + l.when : ""})`);
  console.log(`  value-mimic dust:       ${r.dust.length} sender(s)`);
  for (const d of r.dust) console.log(`    from ${d.from}  ${d.valueEth} ETH x${d.count}${d.lookalike ? "  [lookalike]" : ""}`);
  console.log(`  spoof/homoglyph tokens: ${r.spoofTokens.length}`);
  for (const s of r.spoofTokens) console.log(`    "${s.token}"${s.from ? "  from " + s.from : ""}`);
  if (!r.lookalikes.length && !r.dust.length && !r.spoofTokens.length) {
    console.log("\n  No poisoning indicators in the sampled history.");
  }
  for (const n of r.notes) console.log(`\n  ${n}`);
  console.log(
    `\n  Guidance: never copy a counterparty address from transaction history; use a\n` +
      `  saved address book or verify the full string. A matching first/last 4 is the\n` +
      `  poison, not a coincidence.\n`,
  );
}
