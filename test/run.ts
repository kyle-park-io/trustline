import { resolve } from "node:path";
import { scan } from "../src/scanner";
import { counts } from "../src/report";
import { isLookalike, first4last4 } from "../src/investigate";
import {
  normalizeVersion,
  matchAdvisory,
  loadAdvisories,
} from "../src/modules/vulnerableDependency";

// dist/test/run.js -> ../../ is the trustline root
const ROOT = resolve(__dirname, "..", "..");

let failures = 0;
function check(name: string, cond: boolean, extra = ""): void {
  const mark = cond ? "PASS" : "FAIL";
  if (!cond) failures++;
  console.log(`  [${mark}] ${name}${extra ? "  " + extra : ""}`);
}

async function main(): Promise<void> {
  console.log("trustline self-test\n");

  const vuln = await scan(resolve(ROOT, "examples/vulnerable"));
  const vc = counts(vuln);
  console.log("vulnerable example:");
  check("finds at least one critical", vc.critical >= 1, `(critical=${vc.critical})`);
  check(
    "flags the client-bundle secrets",
    vuln.some(
      (f) => f.module === "bundle-secrets" && !!f.file && f.file.includes("app.bundle.js"),
    ),
  );
  check(
    "flags the private key",
    vuln.some((f) => /private key/i.test(f.title)),
  );
  check(
    "flags SSH open to the world",
    vuln.some((f) => f.module === "network-exposure" && /SSH/.test(f.title)),
  );
  check(
    "flags RDP open to the world",
    vuln.some((f) => /RDP/.test(f.title)),
  );
  check(
    "flags a service account with owner",
    vuln.some((f) => f.module === "iam-privilege" && /roles\/owner/.test(f.title)),
  );
  check(
    "flags a non-expiring service-account key",
    vuln.some((f) => f.module === "iam-privilege" && /non-expiring/i.test(f.title)),
  );
  check(
    "flags crontab @reboot persistence",
    vuln.some((f) => f.module === "persistence-artifacts" && /crontab/i.test(f.title)),
  );
  check(
    "flags hidden autostart persistence",
    vuln.some((f) => f.module === "persistence-artifacts" && /autostart/i.test(f.title)),
  );
  check(
    "flags a reverse-shell attempt in logs",
    vuln.some((f) => f.module === "attack-signals" && /reverse shell/i.test(f.title)),
  );
  check(
    "flags an SSRF-to-metadata probe in logs",
    vuln.some((f) => f.module === "attack-signals" && /ssrf/i.test(f.title)),
  );
  check(
    "flags the GCP cloud-platform full-access scope",
    vuln.some((f) => f.module === "account-wide-credentials" && /cloud-platform/i.test(f.title)),
  );
  check(
    "flags the Cloudflare global API key",
    vuln.some((f) => f.module === "account-wide-credentials" && /cloudflare global/i.test(f.title)),
  );
  check(
    "flags the AWS admin (*:*) policy",
    vuln.some((f) => f.module === "account-wide-credentials" && /admin \(\*:\*\)/.test(f.title)),
  );
  check(
    "flags the classic GitHub PAT",
    vuln.some((f) => f.module === "account-wide-credentials" && /classic/i.test(f.title)),
  );
  check(
    "flags Data Access audit logs not enabled",
    vuln.some((f) => f.module === "audit-telemetry-gap" && /data access/i.test(f.title)),
  );
  check(
    "flags VPC flow logs disabled",
    vuln.some((f) => f.module === "audit-telemetry-gap" && /flow logs/i.test(f.title)),
  );
  check(
    "matches a known C2 domain IOC",
    vuln.some((f) => f.module === "known-ioc" && /api-gateway-prod\.com/.test(f.detail)),
  );
  check(
    "matches a known attacker contract IOC",
    vuln.some((f) => f.module === "known-ioc" && /0x22f96d61cf118efabc7c5bf3384734fad2f6ead4/i.test(f.detail)),
  );
  check(
    "matches a known C2 IP IOC",
    vuln.some((f) => f.module === "known-ioc" && /173\.249\.8\.102/.test(f.detail)),
  );
  check(
    "matches a homoglyph spoof-token IOC",
    vuln.some((f) => f.module === "known-ioc" && /homoglyph/i.test(f.title)),
  );
  check(
    "flags the React2Shell vulnerable dependency (CVE-2025-55182)",
    vuln.some(
      (f) =>
        f.module === "vulnerable-dependency" &&
        /react-server-dom/.test(f.title) &&
        /CVE-2025-55182/.test(f.detail),
    ),
  );
  check(
    "flags the Ledger Connect Kit supply-chain dependency",
    vuln.some(
      (f) => f.module === "vulnerable-dependency" && /@ledgerhq\/connect-kit/.test(f.title),
    ),
  );

  const safe = await scan(resolve(ROOT, "examples/safe"));
  const sc = counts(safe);
  console.log("\nsafe example:");
  check("no critical findings", sc.critical === 0, `(critical=${sc.critical})`);
  check("no high findings", sc.high === 0, `(high=${sc.high})`);

  // Offline unit tests for the address-poisoning lookalike logic (no network).
  console.log("\naddress-poisoning logic:");
  const victim = "0xC921a66E30745F11f8c7a7870e95640607Ae7Ea2";
  check(
    "first4last4 splits an address",
    (() => {
      const p = first4last4(victim);
      return p.first4 === "c921" && p.last4 === "7ea2";
    })(),
  );
  check(
    "matching first-4 and last-4 is a lookalike",
    isLookalike(victim, "0xC921ffffffffffffffffffffffffffffffff7Ea2"),
  );
  check(
    "an unrelated address is not a lookalike",
    !isLookalike(victim, "0x1234ffffffffffffffffffffffffffffffff5678"),
  );
  check("the same address is not its own lookalike", !isLookalike(victim, victim));

  // Offline unit tests for the vulnerable-dependency version-matching logic.
  console.log("\nvulnerable-dependency logic:");
  check(
    "normalizeVersion strips a caret range",
    normalizeVersion("^19.1.1") === "19.1.1",
    `(got ${normalizeVersion("^19.1.1")})`,
  );
  check(
    "normalizeVersion strips a >= comparator",
    normalizeVersion(">=1.1.5") === "1.1.5",
  );
  check(
    "normalizeVersion leaves a pinned version unchanged",
    normalizeVersion("19.2.0") === "19.2.0",
  );
  const advisories = loadAdvisories();
  check(
    "matchAdvisory matches a sibling package by prefix",
    matchAdvisory("react-server-dom-turbopack", advisories)?.id === "CVE-2025-55182",
  );
  check(
    "matchAdvisory matches an exact package name",
    !!matchAdvisory("@ledgerhq/connect-kit", advisories),
  );
  check(
    "matchAdvisory returns undefined for an unrelated package",
    matchAdvisory("express", advisories) === undefined,
  );

  console.log(
    `\n${failures === 0 ? "ALL TESTS PASSED" : failures + " TEST(S) FAILED"}\n`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
