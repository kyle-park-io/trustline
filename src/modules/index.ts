import { ScanModule } from "../types";
import { vulnerableDependency } from "./vulnerableDependency";
import { bundleSecrets } from "./bundleSecrets";
import { networkExposure } from "./networkExposure";
import { iamPrivilege } from "./iamPrivilege";
import { accountWideCredentials } from "./accountWideCredentials";
import { persistenceArtifacts } from "./persistenceArtifacts";
import { attackSignals } from "./attackSignals";
import { auditTelemetryGap } from "./auditTelemetryGap";
import { knownIoc } from "./knownIoc";

/** All scanner modules. Add new ones here. */
export const MODULES: ScanModule[] = [
  // minimize blast radius: keep one breach from spreading
  vulnerableDependency,
  bundleSecrets,
  networkExposure,
  iamPrivilege,
  accountWideCredentials,
  // detect: catch the breach and the blind spots that hide it
  persistenceArtifacts,
  attackSignals,
  auditTelemetryGap,
  // match: is this infra already touching known attacker ground?
  knownIoc,
];
