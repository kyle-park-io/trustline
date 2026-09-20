import { readdirSync, statSync, readFileSync } from "node:fs";
import { join, extname, dirname } from "node:path";

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  ".next/cache",
  ".turbo",
  "coverage",
]);

const TEXT_EXT = new Set([
  ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
  ".json", ".html", ".htm", ".css", ".map",
  ".env", ".ini", ".yaml", ".yml", ".toml", ".sh", ".txt", ".md",
  ".pem", ".key", ".crt", ".cer", ".p8",
]);

/** Walk a directory recursively, yielding absolute file paths, skipping noise dirs. */
export function* walk(dir: string): Generator<string> {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (e.name.startsWith(".git")) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      yield* walk(full);
    } else if (e.isFile()) {
      yield full;
    }
  }
}

/** Is this a text file we should scan? By extension, or dotfiles like .env. */
export function isTextFile(path: string): boolean {
  const ext = extname(path).toLowerCase();
  if (TEXT_EXT.has(ext)) return true;
  const base = path.split("/").pop() ?? "";
  return base.startsWith(".env");
}

/** Read a file as text, returning "" on any error or if it looks binary. */
export function readText(path: string): string {
  try {
    const buf = readFileSync(path);
    // crude binary sniff: a NUL byte in the first 8KB
    const slice = buf.subarray(0, 8192);
    if (slice.includes(0)) return "";
    return buf.toString("utf8");
  } catch {
    return "";
  }
}

/** Shannon entropy (bits per char) of a string. */
export function entropy(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  let h = 0;
  const n = s.length;
  for (const c in freq) {
    const p = freq[c] / n;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Show only the first few chars of a secret so reports never leak the value. */
export function mask(s: string): string {
  const t = s.trim();
  if (t.length <= 8) return "****";
  return `${t.slice(0, 4)}...(${t.length} chars)`;
}

export function isFile(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Find a bundled data file (e.g. "data/iocs.json") by walking up from this
 * build directory, then falling back to the current working directory. Lets a
 * module load its dataset no matter how deep under dist/ it was compiled.
 */
export function findUp(relPath: string): string | null {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    const cand = join(dir, relPath);
    if (isFile(cand)) return cand;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  const cwdCand = join(process.cwd(), relPath);
  if (isFile(cwdCand)) return cwdCand;
  const nested = join(process.cwd(), "trustline", relPath);
  return isFile(nested) ? nested : null;
}
