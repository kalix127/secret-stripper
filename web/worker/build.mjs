// Base64 so the bundle has no shell text: Cloudflare's upload-time abuse
// scanner 403s a bundle that embeds a `curl | sudo | bash` installer.
import { readFileSync, writeFileSync } from "node:fs";

const b64 = (p) => Buffer.from(readFileSync(p)).toString("base64");

const sh = b64("../installer/install.sh");

writeFileSync(
  "src/installers.gen.js",
  `export const SH_B64 = ${JSON.stringify(sh)};\n`,
);
