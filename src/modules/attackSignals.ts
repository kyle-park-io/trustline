import { relative, extname, basename } from "node:path";
import { Finding, ScanModule, Severity } from "../types";
import { walk, readText } from "../util";

// Signals that an attack was attempted, left in logs. Their presence is not a
// config mistake by itself; the point is that these are exactly what a monitor
// should alert on. Attacks usually leave precursor signals (failed attempts,
// probes) before the damaging step, which is a window to detect and respond.
const SIGNALS: { re: RegExp; severity: Severity; title: string }[] = [
  { re: /rm\s+\/tmp\/\w+;\s*mkfifo|\bnc\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+|bash\s+-i\b|sh\s+-i\s+2>&1|\/dev\/tcp\//i,
    severity: "high", title: "Reverse shell attempt in logs" },
  { re: /(?:curl|wget)\s+[^\n|]*\|\s*(?:ba)?sh\b|wget\s+https?:\/\/[^\s;]+;\s*chmod/i,
    severity: "high", title: "Remote script execution (curl|bash) in logs" },
  { re: /Command failed:.*(?:curl|wget|nc |mkfifo|chmod|\/dev\/tcp)/i,
    severity: "high", title: "Failed shell command from the app process" },
  { re: /169\.254\.169\.254|\/latest\/meta-data\/|computeMetadata\/v1/i,
    severity: "medium", title: "SSRF-to-cloud-metadata probe in logs" },
  { re: /stratum\+tcp:|xmrig|\bminerd\b/i,
    severity: "high", title: "Cryptominer reference in logs" },
];

function isLogFile(path: string): boolean {
  const base = basename(path).toLowerCase();
  return (
    extname(path).toLowerCase() === ".log" ||
    /(^|\/)(logs|\.pm2)\//.test(path) ||
    /(access|error|syslog|auth|nextjs)/.test(base)
  );
}

export const attackSignals: ScanModule = {
  id: "attack-signals",
  title: "Attack signals in logs (detection gap)",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      if (!isLogFile(path)) continue;
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);
      const lines = text.split(/\r?\n/);
      const perFile: Record<string, number> = {};

      lines.forEach((line, i) => {
        for (const sig of SIGNALS) {
          if (!sig.re.test(line)) continue;
          perFile[sig.title] = (perFile[sig.title] ?? 0) + 1;
          if (perFile[sig.title] > 3) break; // cap noise per signal per file
          findings.push({
            module: "attack-signals",
            severity: sig.severity,
            title: sig.title,
            file: rel,
            line: i + 1,
            detail: `Log line looks like an attack attempt: ${line.trim().slice(0, 100)}`,
            fix: "Wire this log into monitoring/alerting so such attempts page someone, and confirm the attempt failed. Repeated attempts are a window to detect and respond before the damaging step.",
            chain:
              "Attacks usually leave signals before the fatal step (here: failed exploit commands, reverse-shell probes, SSRF-to-metadata hits). Monitoring that catches them buys time to pause or revoke before the damaging step.",
          });
          break; // one finding per line: the most specific signal wins
        }
      });
    }

    return findings;
  },
};
