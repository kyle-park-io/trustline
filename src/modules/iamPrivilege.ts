import { relative, extname } from "node:path";
import { Finding, ScanModule, Severity } from "../types";
import { walk, readText } from "../util";

// Roles that give a workload far more than it needs.
const BROAD_ROLES: Record<string, Severity> = {
  "roles/owner": "critical",
  "roles/editor": "high",
};

const PUBLIC_MEMBERS = new Set(["allUsers", "allAuthenticatedUsers"]);

interface IamBinding {
  role?: string;
  members?: string[];
}
interface IamPolicy {
  bindings?: IamBinding[];
}
interface SaKey {
  name?: string;
  keyType?: string;
  validBeforeTime?: string;
}

function isNonExpiring(validBeforeTime?: string): boolean {
  if (!validBeforeTime) return true;
  const year = Number(validBeforeTime.slice(0, 4));
  return Number.isNaN(year) || year >= 9999;
}

export const iamPrivilege: ScanModule = {
  id: "iam-privilege",
  title: "Over-privileged cloud IAM",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      if (extname(path).toLowerCase() !== ".json") continue;
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);

      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        continue;
      }

      // Shape 1: an IAM policy ({ bindings: [...] }).
      const policy = parsed as IamPolicy;
      if (policy && Array.isArray(policy.bindings)) {
        for (const b of policy.bindings) {
          const role = b.role ?? "";
          for (const member of b.members ?? []) {
            const shortMember = member.replace(/^serviceAccount:|^user:|^group:/, "");

            if (PUBLIC_MEMBERS.has(member)) {
              findings.push({
                module: "iam-privilege",
                severity: "critical",
                title: "IAM role granted to the public",
                file: rel,
                detail: `${role} is granted to ${member}.`,
                fix: "Remove the allUsers/allAuthenticatedUsers binding; grant access to specific principals only.",
                chain: "A public IAM binding lets anyone on the internet use that role against your project.",
              });
              continue;
            }

            if (member.startsWith("serviceAccount:") && BROAD_ROLES[role]) {
              findings.push({
                module: "iam-privilege",
                severity: BROAD_ROLES[role],
                title: `Service account has ${role}`,
                file: rel,
                detail: `${shortMember} is bound to ${role} at the project level.`,
                fix: "Replace with a least-privilege custom role holding only the permissions the workload needs.",
                chain:
                  role === "roles/owner"
                    ? "If any workload using this service account is breached, the attacker gets owner of the whole project (VMs, IAM, storage, everything)."
                    : "Editor lets a breached workload change most resources in the project, a big step from one host to many.",
              });
            }
          }
        }
      }

      // Shape 2: a service-account key listing (array of { keyType, validBeforeTime }).
      if (Array.isArray(parsed) && parsed.some((k) => k && typeof k === "object" && "keyType" in k)) {
        for (const key of parsed as SaKey[]) {
          if (key.keyType !== "USER_MANAGED") continue;
          const nonExpiring = isNonExpiring(key.validBeforeTime);
          findings.push({
            module: "iam-privilege",
            severity: nonExpiring ? "high" : "medium",
            title: nonExpiring
              ? "Non-expiring user-managed service-account key"
              : "User-managed service-account key",
            file: rel,
            detail: nonExpiring
              ? "A user-managed key with no expiry exists; it works forever unless manually revoked."
              : "A user-managed key exists (prefer short-lived credentials).",
            fix: "Avoid downloaded keys; use workload identity or short-lived credentials. If a key is required, set an expiry and rotate it.",
            chain: "A long-lived key that leaks (in a repo, image, or breached host) is usable indefinitely from anywhere.",
          });
        }
      }
    }

    return findings;
  },
};
