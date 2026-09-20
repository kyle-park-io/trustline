import { Finding, Severity } from "./types";
import { sortFindings } from "./report";
import { MODULES } from "./modules";

// SARIF 2.1.0 output, so scan results can be uploaded to GitHub code scanning
// (Security tab and PR annotations) or any SARIF-aware tool. Same Finding[] as
// the other outputs; this only maps them onto the SARIF shape.

const TOOL_URI = "https://github.com/kyle-park-io/trustline";

// SARIF result levels. GitHub renders error/warning/note; critical and high both
// map to error, and the GitHub Security-tab ordering uses security-severity.
function level(sev: Severity): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

// A numeric 0-10 score GitHub uses to sort and to place a result in
// critical/high/medium/low buckets independently of the SARIF level.
function securitySeverity(sev: Severity): string {
  switch (sev) {
    case "critical": return "9.5";
    case "high": return "8.0";
    case "medium": return "5.0";
    case "low": return "2.0";
  }
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  properties: { "security-severity": string };
}

interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: unknown[];
}

/** Render a SARIF 2.1.0 document string for a set of findings. */
export function renderSarif(findings: Finding[], target: string): string {
  const sorted = sortFindings(findings);

  // One rule per module, so every result references a declared rule. The
  // per-rule security-severity is the worst severity that module produced in
  // this run (falling back to a module default), which is what GitHub buckets on.
  const worstBySev = new Map<string, Severity>();
  const order: Severity[] = ["low", "medium", "high", "critical"];
  for (const f of sorted) {
    const cur = worstBySev.get(f.module);
    if (!cur || order.indexOf(f.severity) > order.indexOf(cur)) {
      worstBySev.set(f.module, f.severity);
    }
  }

  const rules: SarifRule[] = MODULES.map((m) => ({
    id: m.id,
    name: m.title,
    shortDescription: { text: m.title },
    properties: { "security-severity": securitySeverity(worstBySev.get(m.id) ?? "medium") },
  }));

  const results: SarifResult[] = sorted.map((f) => ({
    ruleId: f.module,
    level: level(f.severity),
    message: {
      text: `${f.title}. ${f.detail} why: ${f.chain} fix: ${f.fix}`,
    },
    locations: f.file
      ? [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.line ?? 1 },
            },
          },
        ]
      : [],
  }));

  const doc = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "trustline",
            informationUri: TOOL_URI,
            version: "0.1.0",
            rules,
          },
        },
        results,
        originalUriBaseIds: {
          SRCROOT: { uri: `file://${target}/` },
        },
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}
