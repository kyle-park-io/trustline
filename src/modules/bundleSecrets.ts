import { relative } from "node:path";
import { Finding, ScanModule } from "../types";
import { walk, isTextFile, readText, mask, entropy } from "../util";

// Values that look like a secret assignment but are clearly placeholders.
const PLACEHOLDER = /^(x{3,}|changeme|your[-_ ]|<.*>|\$\{|process\.env|todo|example|dummy|test|placeholder|redacted|masked)/i;

// name = "value"  /  name: "value"  for secret-ish names
const NAMED_SECRET =
  /(api[_-]?key|apikey|secret|token|passwd|password|authkey|access[_-]?key|private[_-]?key|client[_-]?secret)["'\s]*[:=]\s*["'`]([^"'`]{12,})["'`]/gi;

// PEM private key block
const PEM = /-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----/;

// JWT-ish: three base64url segments
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/;

/** A file that ships to the browser: its contents are public to any visitor. */
function clientReachable(rel: string): boolean {
  return (
    /(^|\/)(public|dist|build|out)\//.test(rel) ||
    /\.next\/static\//.test(rel) ||
    /\.min\.js$/.test(rel) ||
    /\.(js|mjs|css)\.map$/.test(rel)
  );
}

export const bundleSecrets: ScanModule = {
  id: "bundle-secrets",
  title: "Secrets in source or client bundle",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      if (!isTextFile(path)) continue;
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);
      const inBundle = clientReachable(rel);
      const lines = text.split(/\r?\n/);

      lines.forEach((line, i) => {
        const lineNo = i + 1;

        if (PEM.test(line)) {
          findings.push({
            module: "bundle-secrets",
            severity: "critical",
            title: "Private key committed to the repo",
            file: rel,
            line: lineNo,
            detail: "A PEM private key block is present in a tracked file.",
            fix: "Remove the key, rotate it, and load it from a secret store or env var at runtime.",
            chain:
              "A leaked private key lets an attacker impersonate the server, or pivot into whatever it unlocks (SSH, TLS, signing).",
          });
          return;
        }

        if (JWT.test(line)) {
          findings.push({
            module: "bundle-secrets",
            severity: inBundle ? "high" : "medium",
            title: "Hard-coded JWT / bearer token",
            file: rel,
            line: lineNo,
            detail: "A JWT-shaped token is embedded in the code.",
            fix: "Do not embed tokens; mint them server-side and keep them out of client code.",
            chain: "A valid token is a ready-made session an attacker can replay.",
          });
          return;
        }

        NAMED_SECRET.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = NAMED_SECRET.exec(line))) {
          const value = m[2];
          if (PLACEHOLDER.test(value)) continue;
          if (entropy(value) < 2.5) continue; // skip low-entropy junk like "aaaaaaa"
          findings.push({
            module: "bundle-secrets",
            severity: inBundle ? "critical" : "high",
            title: inBundle
              ? "Secret shipped in a browser-reachable file"
              : "Hard-coded credential in source",
            file: rel,
            line: lineNo,
            detail: `${m[1]} = ${mask(value)}${inBundle ? " (this file is served to the browser)" : ""}.`,
            fix: inBundle
              ? "Move the secret to a server-only module (server-only import) or env var so it never enters the client bundle, then rotate it."
              : "Load the secret from an env var or secret store, and rotate the exposed value.",
            chain: inBundle
              ? "Any visitor can read the browser bundle, so the secret is effectively public and grants whatever it protects."
              : "A credential in source leaks with the repo and to anyone who reads the code path.",
          });
        }
      });
    }

    return findings;
  },
};
