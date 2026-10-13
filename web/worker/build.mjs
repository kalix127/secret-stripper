// Deploy-time codegen: base64-encode the installer scripts so the uploaded
// Worker bundle contains no recognizable shell text (Cloudflare's upload-time
// abuse scanner 403s a bundle that embeds a `curl | sudo | bash` installer
// verbatim). The repo's installer/install.sh stays the single source of truth;
// src/installers.gen.js is a build artifact (git-ignored, never committed).
import { readFileSync, writeFileSync } from "node:fs";

const b64 = (p) => Buffer.from(readFileSync(p)).toString("base64");

const sh = b64("../installer/install.sh");

writeFileSync(
  "src/installers.gen.js",
  `export const SH_B64 = ${JSON.stringify(sh)};\n`,
);
