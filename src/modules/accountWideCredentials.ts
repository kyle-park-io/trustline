import { relative, extname } from "node:path";
import { Finding, ScanModule, Severity } from "../types";
import { walk, isTextFile, readText, mask } from "../util";

// Cloudflare's *global* API key authenticates with these headers and can do
// anything the account can. Scoped API tokens use `Authorization: Bearer`.
const CF_GLOBAL_HEADER = /X-Auth-Key\b/i;
// Env var name for the global key (not the scoped *_API_TOKEN).
const CF_GLOBAL_ENV = /\b(?:CLOUDFLARE|CF)_(?:GLOBAL_)?API_KEY\b/;
// GCP full-access OAuth scope: the credential can call every GCP API.
const GCP_FULL_SCOPE = /auth\/cloud-platform\b/;
// GitHub *classic* PAT (account-wide by design). Fine-grained is github_pat_.
const GH_CLASSIC_PAT = /\bgh[pousr]_[A-Za-z0-9]{36,}\b/;

interface AwsStatement {
  Effect?: string;
  Action?: string | string[];
  Resource?: string | string[];
}
interface AwsPolicy {
  Version?: string;
  Statement?: AwsStatement | AwsStatement[];
}

function hasStar(v?: string | string[]): boolean {
  if (!v) return false;
  return (Array.isArray(v) ? v : [v]).includes("*");
}

// A single credential whose scope is the whole account/project, where a
// resource-scoped one would do the same job. The lesson from our incident:
// account-global keys (GoDaddy, a Cloudflare global key, an owner service
// account) turn one leak into total control, so we replaced them with scoped
// tokens and a least-privilege role.
export const accountWideCredentials: ScanModule = {
  id: "account-wide-credentials",
  title: "Account-wide credential where a scoped one would do",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      const rel = relative(targetDir, path);

      // JSON: an AWS admin policy (Action "*" on Resource "*") on a credential.
      if (extname(path).toLowerCase() === ".json") {
        const jtext = readText(path);
        if (jtext) {
          let parsed: unknown;
          try {
            parsed = JSON.parse(jtext);
          } catch {
            parsed = null;
          }
          const pol = parsed as AwsPolicy;
          if (pol && pol.Statement) {
            const stmts = Array.isArray(pol.Statement) ? pol.Statement : [pol.Statement];
            for (const s of stmts) {
              if ((s.Effect ?? "").toLowerCase() === "allow" && hasStar(s.Action) && hasStar(s.Resource)) {
                findings.push({
                  module: "account-wide-credentials",
                  severity: "critical",
                  title: "AWS credential with admin (*:*) policy",
                  file: rel,
                  detail: 'An IAM policy grants Action "*" on Resource "*" (full administrator).',
                  fix: "Scope the policy to the exact actions and resources the workload needs; never attach *:* to a programmatic credential.",
                  chain:
                    "A credential with *:* is the whole account in one key: if it leaks (repo, image, breached host), the attacker owns everything at once.",
                });
                break; // one admin-policy finding per file is enough
              }
            }
          }
        }
      }

      if (!isTextFile(path)) continue;
      const text = readText(path);
      if (!text) continue;
      const lines = text.split(/\r?\n/);

      lines.forEach((line, i) => {
        const lineNo = i + 1;

        if (CF_GLOBAL_HEADER.test(line) || CF_GLOBAL_ENV.test(line)) {
          findings.push(mk(rel, lineNo, "high",
            "Cloudflare global API key in use",
            "Code uses Cloudflare's global API key (X-Auth-Key / CLOUDFLARE_API_KEY), which controls the entire account.",
            "Replace it with a scoped API token (Authorization: Bearer) limited to the zones and permissions actually needed, then revoke the global key.",
            "The global key can edit every zone, DNS record, and setting on the account, so one leak is a full DNS/domain takeover."));
        }

        if (GCP_FULL_SCOPE.test(line)) {
          findings.push(mk(rel, lineNo, "high",
            "GCP full-access OAuth scope (cloud-platform)",
            "A credential or instance is granted the cloud-platform scope, which permits every GCP API the account allows.",
            "Grant only the specific scopes the workload needs; prefer a least-privilege service account over the cloud-platform scope.",
            "cloud-platform means 'call any Google Cloud API', so it widens what a breached workload can reach far beyond its job."));
        }

        const gh = GH_CLASSIC_PAT.exec(line);
        if (gh) {
          findings.push(mk(rel, lineNo, "high",
            "GitHub classic personal access token",
            `A classic GitHub PAT (${mask(gh[0])}) is present; classic PATs reach every repo and org the user can access.`,
            "Revoke it; use a fine-grained token (github_pat_) or a short-lived GitHub App / OIDC token scoped to one repo.",
            "A classic PAT is the whole account's git access in one string: it reads and writes every repo the user can touch."));
        }
      });
    }

    return findings;
  },
};

function mk(
  file: string,
  line: number,
  severity: Severity,
  title: string,
  detail: string,
  fix: string,
  chain: string,
): Finding {
  return { module: "account-wide-credentials", severity, title, file, line, detail, fix, chain };
}
