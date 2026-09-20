import { relative, extname } from "node:path";
import { Finding, ScanModule } from "../types";
import { walk, readText } from "../util";

// Flow logs turned off on a subnet/network config.
const FLOW_LOGS_OFF = /(?:enable)?flow[_-]?logs["'\s]*[:=]\s*["']?(?:false|disabled|off)\b/i;
// Application/host logging or monitoring switched off.
const LOG_LEVEL_OFF = /\bLOG_LEVEL\s*[:=]\s*["']?(?:silent|off|none)\b/i;
const DISABLE_MARKER = /\bDISABLE[_-]?(?:LOGGING|AUDIT|MONITORING)\b\s*[:=]\s*["']?(?:true|1|yes)\b/i;
const MON_OFF = /["']?(?:logging|monitoring)["']?\s*[:=]\s*(?:false|"disabled"|"off"|disabled|off)\b/i;

interface AuditLogConfig {
  logType?: string;
  exemptedMembers?: string[];
}
interface AuditConfig {
  service?: string;
  auditLogConfigs?: AuditLogConfig[];
}

// You can only detect and investigate what you log. Our incident's blind spot
// was exactly this: Data Access audit logs were off, so we could not confirm or
// rule out lateral movement after the RCE. This module flags telemetry that is
// switched off before it becomes a blind spot.
export const auditTelemetryGap: ScanModule = {
  id: "audit-telemetry-gap",
  title: "Audit logging or monitoring turned off (blind spot)",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);

      // 1) GCP Data Access audit logging off, from an IAM/audit policy's auditConfigs.
      if (extname(path).toLowerCase() === ".json") {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          parsed = null;
        }
        const configs = (parsed as { auditConfigs?: AuditConfig[] } | null)?.auditConfigs;
        if (Array.isArray(configs) && configs.length > 0) {
          const enabled = new Set<string>();
          let exempted = false;
          for (const c of configs) {
            for (const lc of c.auditLogConfigs ?? []) {
              if (lc.logType) enabled.add(lc.logType.toUpperCase());
              if ((lc.exemptedMembers ?? []).length > 0) exempted = true;
            }
          }
          const dataLogged = enabled.has("DATA_READ") && enabled.has("DATA_WRITE");
          if (!dataLogged) {
            findings.push({
              module: "audit-telemetry-gap",
              severity: "high",
              title: "Data Access audit logs not enabled",
              file: rel,
              detail: "auditConfigs enable only admin logging; DATA_READ/DATA_WRITE are off, so reads and writes to data are not recorded.",
              fix: "Enable DATA_READ and DATA_WRITE audit logs (for allServices, or at least the sensitive ones), and remove exemptedMembers.",
              chain:
                "This is the exact blind spot from our incident: with Data Access logs off we could neither confirm nor rule out lateral movement after the RCE.",
            });
          } else if (exempted) {
            findings.push({
              module: "audit-telemetry-gap",
              severity: "high",
              title: "Audit logging exempts some members",
              file: rel,
              detail: "auditConfigs list exemptedMembers, so those principals' data access is not logged.",
              fix: "Remove exemptedMembers so every principal's data access is recorded.",
              chain:
                "An exempted principal is an unlogged path: a breach that lands on it leaves no audit trail to detect or investigate.",
            });
          }
        }
      }

      // 2) VPC flow logs / app logging / monitoring switched off, line by line.
      const lines = text.split(/\r?\n/);
      lines.forEach((line, i) => {
        const lineNo = i + 1;
        if (FLOW_LOGS_OFF.test(line)) {
          findings.push(mk(rel, lineNo,
            "VPC flow logs disabled",
            "A subnet/network config disables flow logs, so network connections are not recorded.",
            "Enable VPC flow logs so lateral movement and exfiltration leave a trace.",
            "Without flow logs there is no record of who talked to what, so east-west movement after a breach is invisible."));
          return;
        }
        if (LOG_LEVEL_OFF.test(line) || DISABLE_MARKER.test(line) || MON_OFF.test(line)) {
          findings.push(mk(rel, lineNo,
            "Application logging or monitoring disabled",
            "A config silences application logs or monitoring, so runtime events (including attacks) are not recorded.",
            "Keep logging at an informative level and ship it to monitoring/alerting; do not disable it in production.",
            "Silenced logs mean the attack signals a monitor would page on (failed exploit commands, probes) are never written down."));
        }
      });
    }

    return findings;
  },
};

function mk(file: string, line: number, title: string, detail: string, fix: string, chain: string): Finding {
  return { module: "audit-telemetry-gap", severity: "medium", title, file, line, detail, fix, chain };
}
