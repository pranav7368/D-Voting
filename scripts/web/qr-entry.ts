/**
 * QR codes for the voter page, bundled by scripts/build-web.ts.
 *
 * The encoder is qrcode-generator (MIT, pinned in package.json); this file only
 * turns its module matrix into an SVG path. Drawing the SVG here, rather than
 * using the library's own HTML output, keeps every attribute a presentation
 * attribute, so the code renders under the page's strict CSP (no style="").
 */

import qrcode from "qrcode-generator";

/**
 * SVG markup for `text` as a QR code, error-correction level M.
 *
 * Level M survives a smudged or glare-washed screen photographed by a phone,
 * which is how this code will be read.
 */
export function qrSvg(text: string, label = "QR code"): string {
  const qr = qrcode(0, "M");
  qr.addData(text, "Byte");
  qr.make();

  const count = qr.getModuleCount();
  const quiet = 4; // the standard quiet zone, in modules
  const size = count + quiet * 2;
  let path = "";
  for (let row = 0; row < count; row++) {
    for (let col = 0; col < count; col++) {
      if (qr.isDark(row, col)) path += `M${col + quiet} ${row + quiet}h1v1h-1z`;
    }
  }

  const safeLabel = label.replace(/[&<>"]/g, (ch) => `&#${ch.charCodeAt(0)};`);
  return (
    `<svg role="img" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges" xmlns="http://www.w3.org/2000/svg">` +
    `<title>${safeLabel}</title><rect width="${size}" height="${size}" fill="#fff"/>` +
    `<path d="${path}" fill="#000"/></svg>`
  );
}
