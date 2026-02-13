/**
 * Postinstall script - ensures ~/.config/openbotauth directory exists
 */

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const OBA_DIR = join(homedir(), ".config", "openbotauth");

try {
  mkdirSync(OBA_DIR, { recursive: true, mode: 0o700 });
  console.log(`clawauth: Initialized config at ${OBA_DIR}`);
} catch {
  // Ignore errors during postinstall
}
