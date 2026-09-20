import { Finding, Severity, SEVERITY_ORDER } from "./types";

const COLOR: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[97m", // white on red
  high: "\x1b[31m", // red
  medium: "\x1b[33m", // yellow
  low: "\x1b[36m", // cyan
};
const RESET = "\x1b[0m";
const DIM = "\x1b[2m";
const BOLD = "\x1b[1m";

function useColor(): boolean {
  return process.stdout.isTTY === true && !process.env.NO_COLOR;
}

function tag(sev: Severity): string {
  const label = sev.toUpperCase().padEnd(8);
  return useColor() ? `${COLOR[sev]} ${label}${RESET}` : `[${label.trim()}]`;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}

export function counts(findings: Finding[]): Record<Severity, number> {
  const c: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity]++;
  return c;
}

export function printHuman(findings: Finding[], target: string): void {
  const b = useColor() ? BOLD : "";
  const d = useColor() ? DIM : "";
  const r = useColor() ? RESET : "";

  console.log(`\n${b}trustline${r} ${d}off-chain infra scan${r}  ${target}\n`);

  if (findings.length === 0) {
    console.log("  No findings. \n");
    return;
  }

  for (const f of sortFindings(findings)) {
    const loc = f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : "(config)";
    console.log(`${tag(f.severity)} ${b}${f.title}${r}`);
    console.log(`  ${d}${loc}  [${f.module}]${r}`);
    console.log(`  ${f.detail}`);
    console.log(`  ${d}why:${r} ${f.chain}`);
    console.log(`  ${d}fix:${r} ${f.fix}\n`);
  }

  const c = counts(findings);
  console.log(
    `${b}Summary${r}: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low  ` +
      `(${findings.length} total)\n`,
  );
}

export function printJson(findings: Finding[], target: string): void {
  console.log(
    JSON.stringify(
      { target, summary: counts(findings), findings: sortFindings(findings) },
      null,
      2,
    ),
  );
}
