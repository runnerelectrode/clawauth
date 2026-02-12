/**
 * Postinstall script - ensures ~/.openbotauth directory exists
 */

import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const OBA_DIR = join(homedir(), ".openbotauth");
const KEYS_DIR = join(OBA_DIR, "keys");
const SUBKEYS_DIR = join(OBA_DIR, "subkeys");

try {
  mkdirSync(KEYS_DIR, { recursive: true });
  mkdirSync(SUBKEYS_DIR, { recursive: true });
  console.log(`clawauth: Initialized key store at ${OBA_DIR}`);
} catch {
  // Ignore errors during postinstall
}
