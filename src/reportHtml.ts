import { Finding, Severity } from "./types";
import { sortFindings, counts } from "./report";

// A self-contained HTML report: inline CSS, no external requests, safe to open
// straight from disk or attach to a ticket. Same Finding[] the terminal and
// JSON outputs use, so nothing here re-derives severity or ordering.

const SEV_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

/** Escape text for safe interpolation into HTML element content/attributes. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function loc(f: Finding): string {
  if (!f.file) return "(config)";
  return f.line ? `${f.file}:${f.line}` : f.file;
}

function findingCard(f: Finding): string {
  return `      <article class="finding ${f.severity}">
        <div class="head">
          <span class="badge ${f.severity}">${SEV_LABEL[f.severity]}</span>
          <h3>${esc(f.title)}</h3>
        </div>
        <p class="loc">${esc(loc(f))} <span class="mod">[${esc(f.module)}]</span></p>
        <p class="detail">${esc(f.detail)}</p>
        <p class="meta"><span class="k">why</span> ${esc(f.chain)}</p>
        <p class="meta"><span class="k">fix</span> ${esc(f.fix)}</p>
      </article>`;
}

/** Render a full standalone HTML report string for a set of findings. */
export function renderHtml(findings: Finding[], target: string): string {
  const c = counts(findings);
  const sorted = sortFindings(findings);
  const generated = new Date().toISOString();
  const worst = c.critical > 0 || c.high > 0;
  const verdict = findings.length === 0
    ? "No findings"
    : `${findings.length} finding${findings.length === 1 ? "" : "s"}`;

  const body = findings.length === 0
    ? `      <div class="empty">
        <p class="ok">No findings. Off-chain surface is clean for the checks that ran.</p>
        <p class="sub">Exit code 0.</p>
      </div>`
    : sorted.map(findingCard).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>trustline report</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 32px;
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    color: #1a1c22; background: #f6f7f9;
  }
  .wrap { max-width: 900px; margin: 0 auto; }
  header.top { border-bottom: 2px solid #e4e6eb; padding-bottom: 16px; margin-bottom: 24px; }
  header.top h1 { margin: 0; font-size: 22px; letter-spacing: -0.01em; }
  header.top h1 .dim { color: #8a8f98; font-weight: 400; font-size: 15px; }
  header.top .target { margin: 6px 0 0; color: #4a4f57; font-size: 13px; word-break: break-all; }
  header.top .gen { color: #8a8f98; font-size: 12px; margin-top: 2px; }
  .summary { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0 4px; }
  .chip { font-size: 13px; font-weight: 600; padding: 4px 10px; border-radius: 999px; border: 1px solid transparent; }
  .chip.total { background: #eceef1; color: #3a3f47; }
  .chip.critical { background: #fdecec; color: #b91c1c; border-color: #f5c2c2; }
  .chip.high { background: #fdefe6; color: #c2410c; border-color: #f6cfb4; }
  .chip.medium { background: #fbf3d9; color: #92660a; border-color: #eeddaa; }
  .chip.low { background: #e2f3f6; color: #0e6f83; border-color: #bfe3ea; }
  .verdict { font-size: 13px; color: #4a4f57; margin: 10px 0 24px; }
  .verdict b.fail { color: #b91c1c; }
  .verdict b.pass { color: #0e7a2e; }
  .finding { background: #fff; border: 1px solid #e4e6eb; border-left-width: 4px; border-radius: 8px; padding: 14px 16px; margin: 0 0 12px; }
  .finding.critical { border-left-color: #b91c1c; }
  .finding.high { border-left-color: #c2410c; }
  .finding.medium { border-left-color: #a16207; }
  .finding.low { border-left-color: #0e7490; }
  .finding .head { display: flex; align-items: baseline; gap: 10px; }
  .finding h3 { margin: 0; font-size: 15px; }
  .badge { font-size: 11px; font-weight: 700; letter-spacing: 0.03em; padding: 2px 7px; border-radius: 4px; color: #fff; white-space: nowrap; }
  .badge.critical { background: #b91c1c; }
  .badge.high { background: #c2410c; }
  .badge.medium { background: #a16207; }
  .badge.low { background: #0e7490; }
  .loc { margin: 8px 0 6px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #5a5f67; }
  .loc .mod { color: #9aa0a8; }
  .detail { margin: 0 0 8px; }
  .meta { margin: 4px 0; font-size: 13px; color: #40454d; }
  .meta .k { display: inline-block; min-width: 30px; font-weight: 700; color: #8a8f98; text-transform: uppercase; font-size: 11px; }
  .empty { background: #fff; border: 1px solid #e4e6eb; border-radius: 8px; padding: 28px; text-align: center; }
  .empty .ok { font-size: 16px; font-weight: 600; color: #0e7a2e; margin: 0 0 4px; }
  .empty .sub { color: #8a8f98; font-size: 13px; margin: 0; }
  footer { margin-top: 28px; padding-top: 14px; border-top: 1px solid #e4e6eb; color: #9aa0a8; font-size: 12px; }
  @media (prefers-color-scheme: dark) {
    body { color: #e6e8ec; background: #16181d; }
    header.top { border-color: #2a2d34; }
    header.top h1 .dim, header.top .gen { color: #8a8f98; }
    header.top .target { color: #b4b8c0; }
    .finding, .empty { background: #1e2127; border-color: #2a2d34; }
    .verdict, .meta { color: #b4b8c0; }
    footer { border-color: #2a2d34; }
  }
</style>
</head>
<body>
  <div class="wrap">
    <header class="top">
      <h1>trustline <span class="dim">off-chain infra scan</span></h1>
      <p class="target">${esc(target)}</p>
      <p class="gen">generated ${esc(generated)}</p>
      <div class="summary">
        <span class="chip total">${findings.length} total</span>
        <span class="chip critical">${c.critical} critical</span>
        <span class="chip high">${c.high} high</span>
        <span class="chip medium">${c.medium} medium</span>
        <span class="chip low">${c.low} low</span>
      </div>
      <p class="verdict">${verdict} &middot; ${
        worst
          ? '<b class="fail">exit 1</b> (critical or high present)'
          : '<b class="pass">exit 0</b>'
      }</p>
    </header>
${body}
    <footer>trustline &middot; off-chain infrastructure security scanner &middot; findings are static heuristics, review before acting</footer>
  </div>
</body>
</html>
`;
}
