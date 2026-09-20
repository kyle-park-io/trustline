import { readFileSync } from "node:fs";
import { relative, basename } from "node:path";
import { Finding, ScanModule, Severity } from "../types";
import { walk, readText, findUp } from "../util";

// Flag dependencies whose declared version matches a known-vulnerable release,
// checked against a small curated advisory set. This is not a general npm-audit:
// the dataset is anchored to this incident's own entry point (React2Shell,
// CVE-2025-55182, in the react-server-dom-* packages) and to a well-known Web3
// supply-chain compromise (@ledgerhq/connect-kit). The point is to catch, before
// deploy, the exact vulnerable component that let this breach happen.
//
// Fully offline: reads local package.json files and a bundled JSON dataset, and
// never contacts a registry.

interface Advisory {
  id: string;
  title: string;
  prefix?: string;
  packages: string[];
  versions: string[];
  severity: Severity;
  fix: string;
  chain: string;
}
interface AdvisoryFile {
  meta?: { name?: string };
  advisories?: Advisory[];
}

// peerDependencies is intentionally excluded: a peer's actually-installed version
// is chosen by the consumer, so matching its declared range floor against an exact
// vulnerable version would be misleading. We check what this package ships.
const DEP_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
] as const;

export function loadAdvisories(): Advisory[] {
  const p = findUp("data/advisories.json");
  if (!p) return [];
  try {
    const data = JSON.parse(readFileSync(p, "utf8")) as AdvisoryFile;
    return data.advisories ?? [];
  } catch {
    return [];
  }
}

/** Strip leading range operators so "^19.1.1" / ">=19.1.1" -> "19.1.1". */
export function normalizeVersion(spec: string): string {
  const t = spec.trim().replace(/^[\^~>=<v\s]+/, "");
  return t.split(/[\s|]/)[0];
}

export function matchAdvisory(name: string, advisories: Advisory[]): Advisory | undefined {
  return advisories.find(
    (a) =>
      a.packages.includes(name) ||
      (a.prefix !== undefined && name.startsWith(a.prefix)),
  );
}

/** 1-indexed line of the first occurrence of `"<name>"` in the file text. */
function lineOf(text: string, name: string): number | undefined {
  const lines = text.split(/\r?\n/);
  const needle = `"${name}"`;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle)) return i + 1;
  }
  return undefined;
}

export const vulnerableDependency: ScanModule = {
  id: "vulnerable-dependency",
  title: "Known-vulnerable dependency",
  async run(targetDir: string): Promise<Finding[]> {
    const advisories = loadAdvisories();
    if (advisories.length === 0) return [];

    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      if (basename(path) !== "package.json") continue;
      const text = readText(path);
      if (!text) continue;
      let pkg: Record<string, unknown>;
      try {
        pkg = JSON.parse(text) as Record<string, unknown>;
      } catch {
        continue;
      }
      const rel = relative(targetDir, path);

      for (const section of DEP_SECTIONS) {
        const deps = pkg[section];
        if (!deps || typeof deps !== "object") continue;
        for (const [name, rawSpec] of Object.entries(deps as Record<string, unknown>)) {
          if (typeof rawSpec !== "string") continue;
          const adv = matchAdvisory(name, advisories);
          if (!adv) continue;
          const version = normalizeVersion(rawSpec);
          if (!adv.versions.includes(version)) continue;

          findings.push({
            module: "vulnerable-dependency",
            severity: adv.severity,
            title: `Known-vulnerable dependency: ${name}@${version}`,
            file: rel,
            line: lineOf(text, name),
            detail: `${name}@${rawSpec} matches ${adv.id} (${adv.title}).`,
            fix: adv.fix,
            chain: adv.chain,
          });
        }
      }
    }

    return findings;
  },
};
