import { Finding } from "./types";
import { MODULES } from "./modules";

/** Run every module against a target directory and return all findings. */
export async function scan(targetDir: string): Promise<Finding[]> {
  const all: Finding[] = [];
  for (const mod of MODULES) {
    const found = await mod.run(targetDir);
    all.push(...found);
  }
  return all;
}
