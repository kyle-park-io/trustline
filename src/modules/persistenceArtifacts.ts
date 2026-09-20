import { relative, basename } from "node:path";
import { Finding, ScanModule } from "../types";
import { walk, readText } from "../util";

// A path component that starts with a dot, e.g. /.system-monitor or /.r0qsv8h1.
// Malware hides its files this way.
const HIDDEN_PATH = /\/\.[A-Za-z0-9]/;
// Backgrounding a process, the classic "run quietly and detach" pattern.
const BACKGROUND = /(nohup\b|&\s*\)\s*2>\/dev\/null|>\s*\/dev\/null\s+2>&1\s*&)/;

const RC_FILES = new Set([".bashrc", ".profile", ".bash_profile", ".zshrc", ".zprofile"]);

export const persistenceArtifacts: ScanModule = {
  id: "persistence-artifacts",
  title: "Backdoor persistence indicators",
  async run(targetDir: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const path of walk(targetDir)) {
      const base = basename(path);
      const text = readText(path);
      if (!text) continue;
      const rel = relative(targetDir, path);
      const lines = text.split(/\r?\n/);

      // 1) crontab @reboot launching a hidden binary
      if (base === "crontab" || /(^|\/)cron/i.test(rel) || text.includes("@reboot")) {
        lines.forEach((line, i) => {
          if (/@reboot/.test(line) && (HIDDEN_PATH.test(line) || BACKGROUND.test(line))) {
            findings.push(mk(rel, i + 1,
              "crontab @reboot autostart of a hidden binary",
              "A crontab @reboot entry launches a hidden/background process on every boot.",
              "Remove the entry, then treat the host as compromised: investigate and rebuild from a clean image."));
          }
        });
        continue;
      }

      // 2) systemd user service that keeps a hidden binary alive
      if (path.endsWith(".service")) {
        const restart = /Restart\s*=\s*always/i.test(text);
        const execLine = lines.find((l) => /ExecStart\s*=/.test(l)) ?? "";
        if (HIDDEN_PATH.test(execLine) || (restart && /\/tmp\//.test(execLine))) {
          findings.push(mk(rel, undefined,
            "systemd service runs a hidden binary",
            "A systemd unit runs an executable from a hidden or temp path" + (restart ? " and restarts it forever." : "."),
            "Disable and remove the unit; investigate the host for compromise."));
        }
        continue;
      }

      // 3) XDG autostart entry deliberately hidden from the user
      if (path.endsWith(".desktop")) {
        if (/Hidden\s*=\s*true/i.test(text) || /NoDisplay\s*=\s*true/i.test(text)) {
          const exec = (lines.find((l) => /^Exec\s*=/.test(l)) ?? "").replace(/^Exec\s*=\s*/, "");
          findings.push(mk(rel, undefined,
            "hidden autostart entry",
            `An autostart .desktop entry is marked hidden/no-display and runs: ${exec.slice(0, 80) || "(exec)"}.`,
            "Remove the autostart entry; investigate the host for compromise."));
        }
        continue;
      }

      // 4) shell rc file injected with a background launcher
      if (RC_FILES.has(base)) {
        lines.forEach((line, i) => {
          if (BACKGROUND.test(line) && HIDDEN_PATH.test(line)) {
            findings.push(mk(rel, i + 1,
              "shell startup file launches a hidden binary",
              "A login shell rc file backgrounds a process from a hidden path on every shell start.",
              "Remove the injected line; investigate the host for compromise."));
          }
        });
      }
    }

    return findings;
  },
};

function mk(file: string, line: number | undefined, title: string, detail: string, fix: string): Finding {
  return {
    module: "persistence-artifacts",
    severity: "critical",
    title,
    file,
    line,
    detail,
    fix,
    chain:
      "Persistence is how one exploit becomes a lasting foothold: it survives reboots and lets the attacker return long after the initial breach.",
  };
}
