import { relative, basename } from "node:path";
import { Finding, ScanModule, Severity } from "../types";
import { walk, readText } from "../util";

// Ports that should never be open to the whole internet.
const SENSITIVE_PORTS: Record<string, string> = {
  "22": "SSH",
  "3389": "RDP",
  "3306": "MySQL",
  "5432": "PostgreSQL",
  "6379": "Redis",
  "27017": "MongoDB",
  "9200": "Elasticsearch",
};

const OPEN_TO_WORLD = new Set(["0.0.0.0/0", "::/0"]);

interface FirewallRule {
  name?: string;
  direction?: string;
  sourceRanges?: string[];
  allowed?: { IPProtocol?: string; ports?: string[] }[];
  targetTags?: string[];
}

/** Expand a rule's allowed ports into a flat list; "tcp" with no ports means all ports. */
function portsOf(rule: FirewallRule): { proto: string; ports: string[] }[] {
  return (rule.allowed ?? []).map((a) => ({
    proto: (a.IPProtocol ?? "all").toLowerCase(),
    ports: a.ports ?? ["ALL"],
  }));
}

function looksLikeFirewallFile(name: string): boolean {
  return /firewall/i.test(name) && name.endsWith(".json");
}

export const networkExposure: ScanModule = {
  id: "network-exposure",
  title: "Cloud firewall exposure",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      if (!looksLikeFirewallFile(basename(path))) continue;
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);

      let rules: FirewallRule[];
      try {
        const parsed = JSON.parse(text);
        rules = Array.isArray(parsed) ? parsed : [parsed];
      } catch {
        continue;
      }

      for (const rule of rules) {
        const dir = (rule.direction ?? "INGRESS").toUpperCase();
        if (dir !== "INGRESS") continue;
        const src = rule.sourceRanges ?? [];
        const openToWorld = src.some((r) => OPEN_TO_WORLD.has(r));
        if (!openToWorld) continue;

        for (const { proto, ports } of portsOf(rule)) {
          const allPorts = ports.includes("ALL") || proto === "all";

          // sensitive management/database ports open to the world
          const hits = allPorts
            ? Object.keys(SENSITIVE_PORTS)
            : ports.filter((p) => SENSITIVE_PORTS[p]);

          for (const p of hits) {
            findings.push({
              module: "network-exposure",
              severity: "critical",
              title: `${SENSITIVE_PORTS[p]} (port ${p}) open to the whole internet`,
              file: rel,
              detail: `Firewall rule "${rule.name ?? "(unnamed)"}" allows ${proto}:${p} from 0.0.0.0/0.`,
              fix:
                p === "22"
                  ? "Remove the public rule; reach SSH through IAP or a bastion (allow only the IAP range 35.235.240.0/20)."
                  : p === "3389"
                    ? "Delete the public RDP rule; RDP should never face the internet."
                    : `Restrict ${SENSITIVE_PORTS[p]} to internal ranges only; databases must not be world-reachable.`,
              chain:
                "A management or database port open to the world is a direct door: brute force, known CVEs, or a leaked key gets an attacker straight in.",
            });
          }

          // web ports open to the world: not wrong per se, but flag as a hardening step
          const webPorts = allPorts ? [] : ports.filter((p) => p === "80" || p === "443");
          for (const p of webPorts) {
            const sev: Severity = "low";
            findings.push({
              module: "network-exposure",
              severity: sev,
              title: `Web port ${p} open directly to the internet`,
              file: rel,
              detail: `Firewall rule "${rule.name ?? "(unnamed)"}" serves ${p} to 0.0.0.0/0, exposing the origin directly.`,
              fix: "Put the origin behind a CDN/WAF and allow 80/443 only from the CDN's IP ranges, so the origin IP cannot be hit directly.",
              chain:
                "A directly reachable origin can be scanned and exploited (e.g. an app RCE) without ever passing the CDN's protections.",
            });
          }
        }
      }
    }

    return findings;
  },
};
