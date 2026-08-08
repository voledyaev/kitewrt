// The GLYPHS lookup ships alongside the components it indexes on purpose — a
// separate module for one Record would let the map and the drawings drift.
// Fast refresh of an icon file is not worth that.
/* eslint-disable react-refresh/only-export-components */
/* Icons.
 *
 * Hand-drawn inline SVG on a 24-unit grid, 1.75 stroke, currentColor. No icon
 * font, no sprite fetch, no package: an icon library that tree-shakes to 30
 * icons still costs 4-6 KB gzipped and, more importantly, a router behind the
 * censorship this tool exists to defeat cannot be trusted to fetch anything.
 * The whole set below is ~1.4 KB of source and it replaces the emoji the UI
 * used (🪁 ⚡ ✕ ● ↓ ↑ 🇳🇱), which render at a different size, weight and colour
 * on every platform and cannot be tinted.
 *
 * The five STATE glyphs are drawn to have five different silhouettes, so they
 * are still distinguishable at 12px, in greyscale, and by a reader who cannot
 * separate the hues.
 */
import type { ReactElement, ReactNode } from "react";

type P = { className?: string; size?: number; title?: string };

function Svg({
  className = "",
  size = 16,
  title,
  children,
}: P & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
      focusable="false"
    >
      {title && <title>{title}</title>}
      {children}
    </svg>
  );
}

/* --- the mark -------------------------------------------------------------
 * A kite is only yours while the line holds — the product in one shape. Kite
 * up and to the right, tether running down to where you stand. Deliberately
 * static: a logo that changes with state is one more thing to misread, and the
 * status component is already saying it louder. */
export function KiteMark({ className = "", size = 24 }: P) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden
      focusable="false"
    >
      {/* The line has to be long: with a short tail the silhouette collapses
          into a map pin at 16px. Body 12 units wide by 13.5 tall, tether 13
          across — the diagonal is what makes it read as a kite, not a gem. */}
      <path d="M15.5 2 21.5 8 15.5 15.5 9.5 8Z" />
      <path d="M9.5 8h12M15.5 2v13.5" strokeWidth={0.9} opacity={0.5} />
      <path d="M15.5 15.5 2.5 22" strokeWidth={1.5} />
    </svg>
  );
}

export function Wordmark({
  className = "",
  markSize = 22,
}: {
  className?: string;
  markSize?: number;
}) {
  return (
    <span className={`inline-flex items-center gap-2 ${className}`}>
      <KiteMark size={markSize} className="text-secure" />
      <span className="text-[1.0625rem] font-semibold tracking-[-0.01em]">
        Kite
        {/* "Wrt" is the OpenWrt lineage, and it is the part that says this runs
            on your router rather than in someone's cloud. Mono + a step down in
            weight makes it read as a suffix rather than half a compound word. */}
        <span className="font-mono text-[0.9375rem] font-medium tracking-[0.02em] txt-muted">
          Wrt
        </span>
      </span>
    </span>
  );
}

/* --- state glyphs: five silhouettes --------------------------------------- */

/** secure — a closed link. Continuous, symmetrical, quiet. */
export const GlyphLinked = (p: P) => (
  <Svg {...p}>
    <path d="M9 12H15" />
    <circle cx="12" cy="12" r="7.5" />
  </Svg>
);

/** alarm — a severed line, the two ends sprung apart. Nothing closes.
 *  Deliberately a straight rule with a bite out of it rather than a zigzag: at
 *  12px a zigzag reads as "lightning / fast", which is the opposite. */
export const GlyphBroken = (p: P) => (
  <Svg {...p}>
    <path d="M2.5 12h5.5l1.6-3.4" />
    <path d="M21.5 12H16l-1.6 3.4" />
  </Svg>
);

/** caution — diverted into a wall. Traffic arrives, nothing leaves. */
export const GlyphBlocked = (p: P) => (
  <Svg {...p}>
    <path d="M3 12h9" />
    <path d="M9 8.5 12.5 12 9 15.5" />
    <path d="M17 4v16" strokeWidth={2.5} />
  </Svg>
);

/** unknown — we looked and got nothing back. Dashed ring, hollow centre. */
export const GlyphQuery = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="8.5" strokeDasharray="3 3.2" />
    <path d="M12 11.5v.01M12 15.5v.01" strokeWidth={2.5} />
    <path d="M9.5 9.2a2.6 2.6 0 1 1 3.1 3.3" />
  </Svg>
);

/** off — a flat line. Inert, not an absence of information. */
export const GlyphFlat = (p: P) => (
  <Svg {...p}>
    <path d="M3 12h18" />
  </Svg>
);

export const GLYPHS: Record<string, (p: P) => ReactElement> = {
  linked: GlyphLinked,
  broken: GlyphBroken,
  blocked: GlyphBlocked,
  query: GlyphQuery,
  flat: GlyphFlat,
};

/* --- utility -------------------------------------------------------------- */

export const IconRefresh = (p: P) => (
  <Svg {...p}>
    <path d="M20 5.5v5h-5" />
    <path d="M19.4 10.5A7.8 7.8 0 1 0 20 14.2" />
  </Svg>
);

export const IconCheck = (p: P) => (
  <Svg {...p}>
    <path d="M4.5 12.5 9.5 17.5 19.5 6.5" />
  </Svg>
);

export const IconCross = (p: P) => (
  <Svg {...p}>
    <path d="M6 6l12 12M18 6 6 18" />
  </Svg>
);

export const IconDash = (p: P) => (
  <Svg {...p}>
    <path d="M6 12h12" strokeDasharray="2.5 3" />
  </Svg>
);

export const IconAlert = (p: P) => (
  <Svg {...p}>
    <path d="M12 3.8 22 20.2H2Z" />
    <path d="M12 10v4.2M12 17.4v.01" strokeWidth={2.2} />
  </Svg>
);

export const IconArrowDown = (p: P) => (
  <Svg {...p}>
    <path d="M12 4.5v15M6 13.5 12 19.5 18 13.5" />
  </Svg>
);

export const IconArrowUp = (p: P) => (
  <Svg {...p}>
    <path d="M12 19.5v-15M6 10.5 12 4.5 18 10.5" />
  </Svg>
);
