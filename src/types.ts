export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export interface Finding {
  /** id of the module that produced the finding */
  module: string;
  severity: Severity;
  title: string;
  /** path (relative to the scanned dir) the finding is in, if any */
  file?: string;
  /** 1-indexed line, if applicable */
  line?: number;
  /** what was found, in one sentence */
  detail: string;
  /** how to fix it */
  fix: string;
  /** why this matters: how it helps turn one breach into full compromise */
  chain: string;
}

export interface ScanModule {
  id: string;
  title: string;
  /** run the module against an absolute target directory */
  run(targetDir: string): Promise<Finding[]>;
}
