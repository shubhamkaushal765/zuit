/**
 * WCAG 2.1 contrast verification for the zuit design system.
 *
 * Zero external dependencies. Implements relative luminance and contrast-ratio
 * math as specified in WCAG 2.1 § 1.4.3.
 *
 * Exit 0 = all assertions pass (AA compliant).
 * Exit 1 = one or more pairs fail.
 */

// ---------------------------------------------------------------------------
// Palette — mirrors custom.css exactly (same hex values)
// ---------------------------------------------------------------------------

const PALETTE = {
  light: {
    // 60% dominant surfaces
    bgCanvas:        '#f7f9fc',
    bgDefault:       '#ffffff',
    bgSubtle:        '#eef2f8',

    // 30% secondary surfaces
    surfaceSidebar:  '#f4f7fb',
    surfaceCode:     '#f1f4f9',
    surfaceCard:     '#eef2f8',

    // 10% accent
    accentPrimary:   '#1a4480',  // darkened from #1e4d8c for AA on white
    accentSecondary: '#9a6200',  // darkened amber for AA on white

    // Typography
    textPrimary:     '#111827',
    textSecondary:   '#374151',
    textMuted:       '#4b5563',
    textLink:        '#1a4480',

    // Button
    buttonPrimaryBg:   '#1a4480',
    buttonPrimaryText: '#ffffff',

    // Dimension sub-palette (10% accent, UI-element 3:1)
    dimMaintainability: '#0369a1',
    dimSecurity:        '#b91c1c',
    dimComplexity:      '#6d28d9',
    dimDocumentation:   '#047857',
    dimTest:            '#b45309',
  },

  dark: {
    // 60% dominant surfaces
    bgCanvas:        '#0a0e15',
    bgDefault:       '#0d1117',
    bgSubtle:        '#111827',

    // 30% secondary surfaces
    surfaceSidebar:  '#11161f',
    surfaceCode:     '#0f141d',
    surfaceCard:     '#161c28',

    // 10% accent
    accentPrimary:   '#7aa7f5',  // lifted for AA on dark canvas
    accentSecondary: '#e0a93a',  // amber lifted for AA on dark

    // Typography
    textPrimary:     '#e6edf3',
    textSecondary:   '#b0bec5',
    textMuted:       '#8b949e',
    textLink:        '#7aa7f5',

    // Button
    buttonPrimaryBg:   '#1a4480',
    buttonPrimaryText: '#ffffff',

    // Dimension sub-palette (lifted for dark canvas, UI-element 3:1)
    dimMaintainability: '#38bdf8',
    dimSecurity:        '#f87171',
    dimComplexity:      '#c4b5fd',
    dimDocumentation:   '#6ee7b7',
    dimTest:            '#fcd34d',
  },
};

// ---------------------------------------------------------------------------
// WCAG 2.1 math
// ---------------------------------------------------------------------------

/**
 * Parse a 6-digit hex color to [r, g, b] in [0, 255].
 */
function hexToRgb(hex) {
  const h = hex.replace('#', '');
  if (h.length !== 6) throw new Error(`Invalid hex: ${hex}`);
  return [
    parseInt(h.slice(0, 2), 16),
    parseInt(h.slice(2, 4), 16),
    parseInt(h.slice(4, 6), 16),
  ];
}

/**
 * Linearize an 8-bit sRGB channel to [0, 1].
 * WCAG 2.1 formula: https://www.w3.org/TR/WCAG21/#dfn-relative-luminance
 */
function linearize(c8) {
  const c = c8 / 255;
  return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}

/**
 * Relative luminance of a hex color, per WCAG 2.1.
 */
function luminance(hex) {
  const [r, g, b] = hexToRgb(hex).map(linearize);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/**
 * Contrast ratio between two hex colors.
 */
function contrastRatio(hex1, hex2) {
  const l1 = luminance(hex1);
  const l2 = luminance(hex2);
  const lighter = Math.max(l1, l2);
  const darker  = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

// ---------------------------------------------------------------------------
// Assertion table
// ---------------------------------------------------------------------------

// threshold: 4.5 for body text (AA normal), 3.0 for large text / UI elements
const PAIRINGS = [
  // Light mode
  {
    mode:       'light',
    label:      'body text on page background',
    fg:         PALETTE.light.textPrimary,
    bg:         PALETTE.light.bgDefault,
    threshold:  4.5,
  },
  {
    mode:       'light',
    label:      'body text on secondary surface (sidebar)',
    fg:         PALETTE.light.textPrimary,
    bg:         PALETTE.light.surfaceSidebar,
    threshold:  4.5,
  },
  {
    mode:       'light',
    label:      'body text on code-block background',
    fg:         PALETTE.light.textPrimary,
    bg:         PALETTE.light.surfaceCode,
    threshold:  4.5,
  },
  {
    mode:       'light',
    label:      'link color on page background',
    fg:         PALETTE.light.textLink,
    bg:         PALETTE.light.bgDefault,
    threshold:  4.5,
  },
  {
    mode:       'light',
    label:      'link color on secondary surface',
    fg:         PALETTE.light.textLink,
    bg:         PALETTE.light.surfaceSidebar,
    threshold:  4.5,
  },
  {
    mode:       'light',
    label:      'primary button text on button background',
    fg:         PALETTE.light.buttonPrimaryText,
    bg:         PALETTE.light.buttonPrimaryBg,
    threshold:  4.5,
  },
  {
    mode:       'light',
    label:      'accent on page background (UI element, 3:1)',
    fg:         PALETTE.light.accentPrimary,
    bg:         PALETTE.light.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'light',
    label:      'muted/meta text on page background',
    fg:         PALETTE.light.textMuted,
    bg:         PALETTE.light.bgDefault,
    threshold:  4.5,
  },

  // Dark mode
  {
    mode:       'dark',
    label:      'body text on page background',
    fg:         PALETTE.dark.textPrimary,
    bg:         PALETTE.dark.bgDefault,
    threshold:  4.5,
  },
  {
    mode:       'dark',
    label:      'body text on secondary surface (sidebar)',
    fg:         PALETTE.dark.textPrimary,
    bg:         PALETTE.dark.surfaceSidebar,
    threshold:  4.5,
  },
  {
    mode:       'dark',
    label:      'body text on code-block background',
    fg:         PALETTE.dark.textPrimary,
    bg:         PALETTE.dark.surfaceCode,
    threshold:  4.5,
  },
  {
    mode:       'dark',
    label:      'link color on page background',
    fg:         PALETTE.dark.textLink,
    bg:         PALETTE.dark.bgDefault,
    threshold:  4.5,
  },
  {
    mode:       'dark',
    label:      'link color on secondary surface',
    fg:         PALETTE.dark.textLink,
    bg:         PALETTE.dark.surfaceSidebar,
    threshold:  4.5,
  },
  {
    mode:       'dark',
    label:      'primary button text on button background',
    fg:         PALETTE.dark.buttonPrimaryText,
    bg:         PALETTE.dark.buttonPrimaryBg,
    threshold:  4.5,
  },
  {
    mode:       'dark',
    label:      'accent on page background (UI element, 3:1)',
    fg:         PALETTE.dark.accentPrimary,
    bg:         PALETTE.dark.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'dark',
    label:      'muted/meta text on page background',
    fg:         PALETTE.dark.textMuted,
    bg:         PALETTE.dark.bgDefault,
    threshold:  4.5,
  },

  // Dimension sub-palette — UI element band on dimension-coded cards/rule pages.
  {
    mode:       'light',
    label:      'dimension/maintainability on page bg (UI, 3:1)',
    fg:         PALETTE.light.dimMaintainability,
    bg:         PALETTE.light.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'light',
    label:      'dimension/security on page bg (UI, 3:1)',
    fg:         PALETTE.light.dimSecurity,
    bg:         PALETTE.light.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'light',
    label:      'dimension/complexity on page bg (UI, 3:1)',
    fg:         PALETTE.light.dimComplexity,
    bg:         PALETTE.light.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'light',
    label:      'dimension/documentation on page bg (UI, 3:1)',
    fg:         PALETTE.light.dimDocumentation,
    bg:         PALETTE.light.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'light',
    label:      'dimension/test on page bg (UI, 3:1)',
    fg:         PALETTE.light.dimTest,
    bg:         PALETTE.light.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'dark',
    label:      'dimension/maintainability on page bg (UI, 3:1)',
    fg:         PALETTE.dark.dimMaintainability,
    bg:         PALETTE.dark.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'dark',
    label:      'dimension/security on page bg (UI, 3:1)',
    fg:         PALETTE.dark.dimSecurity,
    bg:         PALETTE.dark.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'dark',
    label:      'dimension/complexity on page bg (UI, 3:1)',
    fg:         PALETTE.dark.dimComplexity,
    bg:         PALETTE.dark.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'dark',
    label:      'dimension/documentation on page bg (UI, 3:1)',
    fg:         PALETTE.dark.dimDocumentation,
    bg:         PALETTE.dark.bgDefault,
    threshold:  3.0,
  },
  {
    mode:       'dark',
    label:      'dimension/test on page bg (UI, 3:1)',
    fg:         PALETTE.dark.dimTest,
    bg:         PALETTE.dark.bgDefault,
    threshold:  3.0,
  },
];

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const COL_MODE   = 6;
const COL_LABEL  = 46;
const COL_FG     = 9;
const COL_BG     = 9;
const COL_RATIO  = 8;
const COL_THRESH = 8;
const COL_RESULT = 6;

function pad(str, len) {
  return String(str).padEnd(len);
}

function fmtRatio(r) {
  return `${r.toFixed(2)}:1`;
}

console.log('');
console.log('zuit design system — WCAG AA contrast verification');
console.log('='.repeat(100));
console.log(
  pad('Mode',  COL_MODE) +
  pad('Pairing', COL_LABEL) +
  pad('FG hex', COL_FG) +
  pad('BG hex', COL_BG) +
  pad('Ratio', COL_RATIO) +
  pad('Min', COL_THRESH) +
  'Result'
);
console.log('-'.repeat(100));

let failures = 0;

for (const p of PAIRINGS) {
  const ratio  = contrastRatio(p.fg, p.bg);
  const pass   = ratio >= p.threshold;
  if (!pass) failures++;
  const result = pass ? 'PASS' : 'FAIL';

  console.log(
    pad(p.mode,        COL_MODE) +
    pad(p.label,       COL_LABEL) +
    pad(p.fg,          COL_FG) +
    pad(p.bg,          COL_BG) +
    pad(fmtRatio(ratio), COL_RATIO) +
    pad(`>= ${p.threshold}:1`, COL_THRESH) +
    result
  );
}

console.log('='.repeat(100));

if (failures === 0) {
  console.log(`All ${PAIRINGS.length} pairings pass WCAG AA.`);
  process.exit(0);
} else {
  console.log(`${failures} of ${PAIRINGS.length} pairings FAIL. Fix palette before shipping.`);
  process.exit(1);
}
