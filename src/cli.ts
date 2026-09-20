#!/usr/bin/env node
import { resolve } from "node:path";
import { statSync } from "node:fs";
import { scan } from "./scanner";
import { printHuman, printJson, counts } from "./report";
import { renderHtml } from "./reportHtml";
import { renderSarif } from "./reportSarif";
import { MODULES } from "./modules";
import {
  investigateC2,
  printC2Report,
  investigateCluster,
  printClusterReport,
  investigatePoisoning,
  printPoisonReport,
  ETHERRAT_C2,
} from "./investigate";

function usage(): void {
  console.log(`trustline - off-chain infrastructure security scanner

Usage:
  trustline scan <dir> [--json|--html|--sarif]
                                          scan a repo/build/config dir (offline)
  trustline investigate-c2 [address] [--cluster] [--json]
                                          characterise a blockchain C2 contract
                                          from public chain data. --cluster maps
                                          the fleet around it (deployer, funding
                                          hub, sibling C2s). Needs network;
                                          defaults to the EtherRAT C2 contract.
  trustline investigate-poison <address> [--json]
                                          check an address for address-poisoning:
                                          vanity lookalikes, value-mimic dust, and
                                          spoof/homoglyph tokens in its history.
                                          Needs network.

Options:
  --cluster  (investigate-c2) map the whole C2 fleet, not just the one contract
  --json     machine-readable output (scan, investigate-*)
  --html     (scan) standalone HTML report to stdout
  --sarif    (scan) SARIF 2.1.0 for GitHub code scanning / CI
  -h,--help  show this help

Scan modules:
${MODULES.map((m) => `  - ${m.id}: ${m.title}`).join("\n")}

scan runs fully offline. The investigate-* commands use the network, and only
read public data (no transactions, no interaction).
Exit code is non-zero when scan finds any critical or high issue (CI-friendly).
`);
}

async function runInvestigate(rest: string[]): Promise<never> {
  const json = rest.includes("--json");
  const address = rest.find((a) => !a.startsWith("-")) ?? ETHERRAT_C2;
  if (rest.includes("--cluster")) {
    const report = await investigateCluster(address);
    if (json) console.log(JSON.stringify(report, null, 2));
    else printClusterReport(report);
    process.exit(0);
  }
  const report = await investigateC2(address);
  if (json) console.log(JSON.stringify(report, null, 2));
  else printC2Report(report);
  process.exit(0);
}

async function runPoison(rest: string[]): Promise<never> {
  const json = rest.includes("--json");
  const address = rest.find((a) => !a.startsWith("-"));
  if (!address) {
    console.error("investigate-poison needs an address\n");
    usage();
    process.exit(2);
  }
  const report = await investigatePoisoning(address);
  if (json) console.log(JSON.stringify(report, null, 2));
  else printPoisonReport(report);
  process.exit(0);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("-h") || argv.includes("--help")) {
    usage();
    process.exit(0);
  }

  const [cmd, ...rest] = argv;

  if (cmd === "investigate-c2") {
    await runInvestigate(rest);
  }

  if (cmd === "investigate-poison") {
    await runPoison(rest);
  }

  if (cmd !== "scan") {
    console.error(`unknown command: ${cmd}\n`);
    usage();
    process.exit(2);
  }

  const json = rest.includes("--json");
  const dirArg = rest.find((a) => !a.startsWith("-"));
  if (!dirArg) {
    console.error("scan needs a target directory\n");
    usage();
    process.exit(2);
  }

  const target = resolve(process.cwd(), dirArg);
  try {
    if (!statSync(target).isDirectory()) throw new Error("not a directory");
  } catch {
    console.error(`target is not a directory: ${target}`);
    process.exit(2);
  }

  const findings = await scan(target);
  if (rest.includes("--sarif")) console.log(renderSarif(findings, target));
  else if (rest.includes("--html")) console.log(renderHtml(findings, target));
  else if (json) printJson(findings, target);
  else printHuman(findings, target);

  const c = counts(findings);
  process.exit(c.critical > 0 || c.high > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
