import { SH_B64 } from "./installers.gen.js";

// Scripts are ASCII (enforced repo-wide), so base64 -> bytes -> UTF-8 is exact.
const decode = (b64) =>
  new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));

const INSTALL_SH = decode(SH_B64);

// 1.x documented this URL; 2.x has no Windows build.
const INSTALL_PS1 = `Write-Host "Secret Stripper 2.x supports Linux only."
Write-Host "The last Windows release is 1.5.2:"
Write-Host "https://github.com/kalix127/secret-stripper/releases/tag/v1.5.2"
`;

const HEADERS = {
  "content-type": "text/plain; charset=utf-8",
  "x-content-type-options": "nosniff",
  "cache-control": "public, max-age=300",
  "strict-transport-security": "max-age=63072000; includeSubDomains",
};

export default {
  fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/" || path === "/install.sh") {
      return new Response(INSTALL_SH, { headers: HEADERS });
    }
    if (path === "/install.ps1") {
      return new Response(INSTALL_PS1, { headers: HEADERS });
    }
    return new Response("Not found\n", { status: 404, headers: HEADERS });
  },
};
