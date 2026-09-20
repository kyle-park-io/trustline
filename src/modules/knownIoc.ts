import { readFileSync } from "node:fs";
import { relative, basename } from "node:path";
import { Finding, ScanModule, Severity } from "../types";
import { walk, readText, isTextFile, findUp } from "../util";

// Match files against a set of known-bad indicators (IOCs) pulled from this
// incident's on-chain forensics: EtherRAT C2 contracts and endpoints, the
// address-poisoning drainer wallets, the WEMIX laundering path, the setString
// C2-write selector, and homoglyph spoof-token strings.
//
// The point of this module is different from the others: they judge whether a
// config is dangerous, this one asks whether infrastructure is already touching
// attacker-controlled ground. A single hit is a likely compromise, not a smell.
//
// The dataset lists attacker-controlled indicators only. Legitimate services
// that were abused (exchange hot wallets, swap routers, bridges) are left out on
// purpose so scanning them raises nothing. Fully offline: this reads local files
// and a bundled JSON dataset, and never contacts any endpoint.

interface AddressIoc { value: string; chain?: string; severity: Severity; role: string }
interface EndpointIoc { value: string; kind: string; severity: Severity; role: string }
interface StringIoc { value: string; severity: Severity; role: string }
interface IocFile {
  meta?: { name?: string };
  addresses?: AddressIoc[];
  endpoints?: EndpointIoc[];
  selectors?: StringIoc[];
  spoofStrings?: StringIoc[];
}

interface Matcher {
  needle: string; // what we search for
  compare: string; // needle, lowercased when case-insensitive
  caseInsensitive: boolean;
  severity: Severity;
  kind: string; // for the finding title
  role: string;
}

/** Find the bundled IOC dataset next to the build, or under the cwd. */
function loadIocs(): IocFile | null {
  const p = findUp("data/iocs.json");
  if (!p) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as IocFile;
  } catch {
    return null;
  }
}

/** Flatten the dataset into a single list of string matchers. */
function buildMatchers(data: IocFile): Matcher[] {
  const out: Matcher[] = [];
  // Addresses are hex and case-insensitive; they are globally unique, so a bare
  // substring match is safe.
  for (const a of data.addresses ?? []) {
    out.push({ needle: a.value, compare: a.value.toLowerCase(), caseInsensitive: true, severity: a.severity, kind: "attacker address", role: a.role });
  }
  // Domains match case-insensitively; IPs and URLs match as written.
  for (const e of data.endpoints ?? []) {
    const ci = e.kind === "domain";
    out.push({ needle: e.value, compare: ci ? e.value.toLowerCase() : e.value, caseInsensitive: ci, severity: e.severity, kind: `C2 ${e.kind}`, role: e.role });
  }
  for (const s of data.selectors ?? []) {
    out.push({ needle: s.value, compare: s.value.toLowerCase(), caseInsensitive: true, severity: s.severity, kind: "C2 write selector", role: s.role });
  }
  // Homoglyph strings are non-ASCII lookalikes; match exactly (never lowercased).
  for (const s of data.spoofStrings ?? []) {
    out.push({ needle: s.value, compare: s.value, caseInsensitive: false, severity: s.severity, kind: "homoglyph spoof token", role: s.role });
  }
  return out;
}

export const knownIoc: ScanModule = {
  id: "known-ioc",
  title: "Known attacker indicators (IOC match)",
  async run(targetDir: string): Promise<Finding[]> {
    const data = loadIocs();
    if (!data) return []; // no dataset available: stay silent rather than guess
    const matchers = buildMatchers(data);
    if (!matchers.length) return [];

    const findings: Finding[] = [];
    const setName = data.meta?.name ?? "incident IOC set";

    for (const path of walk(targetDir)) {
      if (!isTextFile(path)) continue;
      if (basename(path) === "iocs.json") continue; // don't flag a vendored copy of the dataset
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);
      const lines = text.split(/\r?\n/);
      const hitCount: Record<string, number> = {};

      lines.forEach((line, i) => {
        const hay = line.toLowerCase();
        for (const m of matchers) {
          const found = m.caseInsensitive ? hay.includes(m.compare) : line.includes(m.compare);
          if (!found) continue;
          hitCount[m.needle] = (hitCount[m.needle] ?? 0) + 1;
          if (hitCount[m.needle] > 3) continue; // cap noise: same indicator, same file
          findings.push({
            module: "known-ioc",
            severity: m.severity,
            title: `Known attacker IOC in file (${m.kind})`,
            file: rel,
            line: i + 1,
            detail: `Line references a known attacker indicator: "${m.needle}" (${m.role}).`,
            fix: "Treat this as an active compromise indicator, not a smell: isolate the host, rotate any credentials it touched, and remove the reference. Confirm against the incident's on-chain forensics before restoring.",
            chain: `This exact value is attacker-controlled infrastructure from the EtherRAT incident (${setName}). One hit usually means a planted callback or a compromised host, not a coincidence.`,
          });
        }
      });
    }

    return findings;
  },
};
