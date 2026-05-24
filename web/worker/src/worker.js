import { SH_B64, PS1_B64 } from "./installers.gen.js";

// Scripts are ASCII (enforced repo-wide), so base64 -> bytes -> UTF-8 is exact.
const decode = (b64) =>
  new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));

const INSTALL_SH = decode(SH_B64);
const INSTALL_PS1 = decode(PS1_B64);

const HEADERS = {
  "content-type": "text/plain; charset=utf-8",
  "x-content-type-options": "nosniff",
  "cache-control": "public, max-age=300",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
};

export default {
  fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/install.ps1") {
      return new Response(INSTALL_PS1, { headers: HEADERS });
    }
    if (path === "/" || path === "/install.sh") {
      return new Response(INSTALL_SH, { headers: HEADERS });
    }
    return new Response("Not found\n", { status: 404, headers: HEADERS });
  },
};
