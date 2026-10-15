/**
 * Ballot symbols, drawn by the voter's own browser.
 *
 * The sealed election record names a symbol ("tree"); this file is the only
 * place that decides what "tree" looks like. Keeping the drawings here rather
 * than accepting uploaded images means the record carries no markup, and the
 * set is deliberately neutral: none of these is any real party's registered
 * symbol. The list must match BALLOT_SYMBOLS in src/election-record.ts.
 *
 * Every icon is a 24x24 outline using presentation attributes only, so it
 * renders under the page's strict Content-Security-Policy (no style="").
 */

const PATHS = {
  lamp: '<path d="M9 18h6M10 21h4"/><path d="M8 14c-1.5-1.3-2.5-3-2.5-5a6.5 6.5 0 0 1 13 0c0 2-1 3.7-2.5 5-.6.5-1 1.3-1 2v2h-6v-2c0-.7-.4-1.5-1-2z"/>',
  tree: '<path d="M12 22v-6"/><path d="M12 2 5 12h4l-3 4h12l-3-4h4z"/>',
  star: '<path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9z"/>',
  book: '<path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15H6.5A2.5 2.5 0 0 0 4 20.5z"/><path d="M4 20.5A2.5 2.5 0 0 0 6.5 23H20v-5"/>',
  bicycle: '<circle cx="5.5" cy="16.5" r="3.5"/><circle cx="18.5" cy="16.5" r="3.5"/><path d="M5.5 16.5 9 9h6l3.5 7.5M9 9l3 7.5L15 9M8 6h3"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  boat: '<path d="M3 16h18l-2.5 4h-13z"/><path d="M12 3v13M12 4l6 9h-6"/>',
  key: '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M16 7l3 3M19 4l2 2"/>',
  kite: '<path d="M12 2 19 10l-7 10-7-10z"/><path d="M5 10h14M12 2v18M12 20c0 1.5-1 2.5-2.5 2"/>',
  umbrella: '<path d="M12 3a9 9 0 0 1 9 9H3a9 9 0 0 1 9-9z"/><path d="M12 12v7a2 2 0 0 1-4 0"/>',
  flower: '<circle cx="12" cy="9" r="2.5"/><path d="M12 6.5a2.5 2.5 0 1 1 2.4-3.2M14.4 8.3a2.5 2.5 0 1 1 1 4.3M13.8 11.3a2.5 2.5 0 1 1-3.6 0M8.6 12.6a2.5 2.5 0 1 1 1-4.3M9.6 3.3A2.5 2.5 0 1 1 12 6.5"/><path d="M12 11.5V22M12 18c-2 0-3.5-1.2-4-3M12 16c1.6 0 3-.8 3.6-2.4"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
};

/** The mark shown for "None of the Above": an empty box, struck through. */
const NOTA = '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="m4.5 19.5 15-15"/>';

function svg(inner, label) {
  const title = label ? `<title>${label}</title>` : "";
  const aria = label ? 'role="img"' : 'aria-hidden="true"';
  return `<svg ${aria} viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${title}${inner}</svg>`;
}

/** Markup for a candidate's symbol, or "" when none was sealed. */
export function symbolSvg(detail, label = "") {
  if (detail?.nota) return svg(NOTA, label);
  const inner = detail?.symbol ? PATHS[detail.symbol] : null;
  return inner ? svg(inner, label) : "";
}

export const SYMBOL_NAMES = Object.keys(PATHS);
