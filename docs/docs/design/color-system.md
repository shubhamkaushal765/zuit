---
title: Color system
description: The 60-30-10 design system, palette, semantic tokens, and usage guidelines for the zuit documentation UI.
---

# Color system

This page documents the visual design system for the zuit documentation site: the palette, token hierarchy, 60-30-10 balance, WCAG contrast pairings, and usage rules. Follow it whenever you add or modify UI styles.

---

## Overview

The zuit docs UI uses a **60-30-10 color system** grounded in professional developer documentation precedents (Stripe, Vercel, Linear, GitHub Docs). All colors flow through a three-level token hierarchy so that every component picks up theme changes automatically and WCAG AA compliance is verifiable by script.

Three design objectives drove every palette decision:

- **Long-read comfort** — low-saturation surfaces, 1.65 line height, text contrast well above the 4.5:1 minimum.
- **Information hierarchy** — the 60-30-10 split makes it visually obvious which elements are background, which are structural chrome, and which demand attention.
- **Maintainability** — components consume semantic `--cl-*` tokens, never raw hex. Changing a color in one place propagates everywhere.

---

## The 60-30-10 balance

The rule distributes visual weight so that the dominant tone carries the space, a secondary tone defines structure, and the accent creates intentional focus.

| Layer | % | UI elements | Tokens |
|---|---|---|---|
| 60% dominant | 60 | Page background, main content area, reading surface, body text container | `--cl-bg-canvas`, `--cl-bg-default`, `--cl-bg-subtle` |
| 30% secondary | 30 | Navbar, sidebar, TOC rail, code blocks, cards, admonition surfaces, table backgrounds | `--cl-surface-*`, `--cl-border-*` |
| 10% accent | 10 | Links, primary buttons, active sidebar items, focus rings, CTAs, highlighted code lines | `--cl-accent-*`, `--cl-text-link*`, `--cl-focus-ring` |

:::note
The 60-30-10 split is a visual weight guide, not a pixel-count rule. A sidebar that spans 20% of the viewport still represents the 30% structural layer — it's about tone dominance, not area.
:::

### How the split maps to a documentation layout

- **Top band — navbar:** 30% surface (`--cl-surface-nav`), 10% accent on active links.
- **Left rail — sidebar:** 30% surface (`--cl-surface-sidebar`), active item gets 10% accent border + text.
- **Center — content area:** 60% canvas (`--cl-bg-default` / `--cl-bg-canvas`), with 30% surfaces nested inside (code blocks, admonitions, cards) and 10% accent on links / buttons.
- **Right rail — TOC:** 30% surface, separated by a `--cl-border-default` left border.
- **Bottom band — footer:** 30% surface (`--ifm-footer-background-color`).

---

## Palette

### Raw ramps

Raw ramp tokens are **not consumed in components**. They exist only to derive semantic tokens.

| Token | Hex |
|---|---|
| `--zuit-blue-50` | `#eef4ff` |
| `--zuit-blue-100` | `#d9e8ff` |
| `--zuit-blue-200` | `#b3d1ff` |
| `--zuit-blue-300` | `#7aacf7` |
| `--zuit-blue-400` | `#4d88e8` |
| `--zuit-blue-500` | `#2860c8` |
| `--zuit-blue-600` | `#1e4d8c` |
| `--zuit-blue-700` | `#1a4480` |
| `--zuit-blue-800` | `#163c6e` |
| `--zuit-blue-900` | `#102d54` |
| `--zuit-amber-400` | `#e0a93a` |
| `--zuit-amber-500` | `#c8881a` |
| `--zuit-amber-600` | `#9a6200` |

### Dimension sub-palette

Five tokens, one per zuit dimension. They are used on dimension-coded UI surfaces — homepage cards, the dimension-colored top band on rule pages, and finding-summary stripes. Treated as 10% accent, so contrast is verified at the UI-element 3:1 minimum.

| Token | Light | Dark | Used on |
|---|---|---|---|
| `--cl-dimension-maintainability` | `#0369a1` | `#38bdf8` | MAINT* rules, homepage maintainability card |
| `--cl-dimension-security` | `#b91c1c` | `#f87171` | SEC* / CHAIN* rules, security card |
| `--cl-dimension-complexity` | `#6d28d9` | `#c4b5fd` | CPLX* rules, complexity card |
| `--cl-dimension-documentation` | `#047857` | `#6ee7b7` | DOC* rules, documentation card |
| `--cl-dimension-test` | `#b45309` | `#fcd34d` | TEST* rules, test smell card |

`--cl-rule-band` resolves to one of these per page on `/rules/<id>` (set on the leading metadata table by `src/theme/Root.tsx`) and defaults to `--cl-accent-primary` otherwise. Never consume dimension tokens for general body text — they are tuned for UI elements, not 4.5:1 reading.

### Semantic tokens — light mode

| Token | Hex | Role | WCAG ratio (on bg-default) |
|---|---|---|---|
| `--cl-bg-canvas` | `#f7f9fc` | Outer wrap, page shell | — |
| `--cl-bg-default` | `#ffffff` | Main content surface | — |
| `--cl-bg-subtle` | `#eef2f8` | Hover, selected bg | — |
| `--cl-surface-nav` | `#ffffff` | Navbar background | — |
| `--cl-surface-sidebar` | `#f4f7fb` | Sidebar background | — |
| `--cl-surface-card` | `#eef2f8` | Cards, admonition fills | — |
| `--cl-surface-code` | `#f1f4f9` | Code block background | — |
| `--cl-border-default` | `#dbe2ec` | Default border | — |
| `--cl-border-muted` | `#eef2f8` | Subtle dividers | — |
| `--cl-accent-primary` | `#1a4480` | Links, buttons, active | 9.62:1 |
| `--cl-accent-secondary` | `#9a6200` | Amber CTA, highlights | 5.47:1 |
| `--cl-text-primary` | `#111827` | Body text | 17.74:1 |
| `--cl-text-secondary` | `#374151` | Meta, captions | 12.63:1 |
| `--cl-text-muted` | `#4b5563` | Placeholders, disabled | 7.56:1 |
| `--cl-text-link` | `#1a4480` | Link color | 9.62:1 |

### Semantic tokens — dark mode

| Token | Hex | Role | WCAG ratio (on bg-default) |
|---|---|---|---|
| `--cl-bg-canvas` | `#0a0e15` | Outer wrap | — |
| `--cl-bg-default` | `#0d1117` | Main content surface | — |
| `--cl-bg-subtle` | `#111827` | Hover, selected bg | — |
| `--cl-surface-nav` | `#0d1117` | Navbar | — |
| `--cl-surface-sidebar` | `#11161f` | Sidebar | — |
| `--cl-surface-card` | `#161c28` | Cards, admonition fills | — |
| `--cl-surface-code` | `#0f141d` | Code block background | — |
| `--cl-border-default` | `#222a38` | Default border | — |
| `--cl-border-muted` | `#1a2030` | Subtle dividers | — |
| `--cl-accent-primary` | `#7aa7f5` | Links, buttons, active | 7.82:1 |
| `--cl-accent-secondary` | `#e0a93a` | Amber CTA, highlights | 5.63:1 |
| `--cl-text-primary` | `#e6edf3` | Body text | 16.02:1 |
| `--cl-text-secondary` | `#b0bec5` | Meta, captions | 9.48:1 |
| `--cl-text-muted` | `#8b949e` | Placeholders, disabled | 6.15:1 |
| `--cl-text-link` | `#7aa7f5` | Link color | 7.82:1 |

---

## Light vs dark theme

| Surface | Light | Dark |
|---|---|---|
| Page background | `#ffffff` | `#0d1117` |
| Canvas / shell | `#f7f9fc` | `#0a0e15` |
| Navbar | `#ffffff` | `#0d1117` |
| Sidebar | `#f4f7fb` | `#11161f` |
| Code block | `#f1f4f9` | `#0f141d` |
| Card / admonition | `#eef2f8` | `#161c28` |
| Default border | `#dbe2ec` | `#222a38` |
| Body text | `#111827` | `#e6edf3` |
| Link / accent | `#1a4480` | `#7aa7f5` |

---

## Typography contrast pairings

All pairings verified by `node scripts/verify-contrast.mjs`.

| Mode | Pairing | FG | BG | Ratio | AA |
|---|---|---|---|---|---|
| light | body text on page background | `#111827` | `#ffffff` | 17.74:1 | PASS |
| light | body text on sidebar | `#111827` | `#f4f7fb` | 16.51:1 | PASS |
| light | body text on code block | `#111827` | `#f1f4f9` | 16.09:1 | PASS |
| light | link on page background | `#1a4480` | `#ffffff` | 9.62:1 | PASS |
| light | link on sidebar | `#1a4480` | `#f4f7fb` | 8.95:1 | PASS |
| light | button text on button bg | `#ffffff` | `#1a4480` | 9.62:1 | PASS |
| light | accent on page bg (3:1 UI) | `#1a4480` | `#ffffff` | 9.62:1 | PASS |
| light | muted text on page background | `#4b5563` | `#ffffff` | 7.56:1 | PASS |
| dark | body text on page background | `#e6edf3` | `#0d1117` | 16.02:1 | PASS |
| dark | body text on sidebar | `#e6edf3` | `#11161f` | 15.34:1 | PASS |
| dark | body text on code block | `#e6edf3` | `#0f141d` | 15.62:1 | PASS |
| dark | link on page background | `#7aa7f5` | `#0d1117` | 7.82:1 | PASS |
| dark | link on sidebar | `#7aa7f5` | `#11161f` | 7.49:1 | PASS |
| dark | button text on button bg | `#ffffff` | `#1a4480` | 9.62:1 | PASS |
| dark | accent on page bg (3:1 UI) | `#7aa7f5` | `#0d1117` | 7.82:1 | PASS |
| dark | muted text on page background | `#8b949e` | `#0d1117` | 6.15:1 | PASS |

:::tip
Run `node scripts/verify-contrast.mjs` any time you change a palette color. The script exits non-zero on failure, so it can be wired into CI.
:::

---

## Usage guidelines

### Do

- Consume only `--cl-*` semantic tokens (or `--ifm-*` variables we map onto them) in component styles.
- Use `--cl-accent-primary` for interactive elements that need to stand out (links, focused inputs, primary buttons, active sidebar items).
- Use `--cl-surface-*` for structural chrome (navbar, sidebar, code blocks, cards).
- Use `--cl-text-muted` for metadata, timestamps, captions — not for body text.
- Keep hover and focus transitions at `150ms ease`.

### Do not

- Hardcode hex values in component CSS — always use a token.
- Use `--zuit-blue-N` or `--zuit-slate-N` ramp tokens in components — those are for deriving semantic tokens only.
- Add `outline: none` or `outline: 0` — use `--cl-focus-ring` instead.
- Use `transition` durations longer than `150ms` on interactive elements.
- Use the amber `--cl-accent-secondary` for body links — reserve it for call-to-action elements and the secondary button variant.

---

## Links, buttons, alerts

- **Links** consume `--cl-text-link` (mapped onto `--ifm-link-color`) with a `150ms ease` color transition to `--cl-text-link-hover`.
- **Primary button** uses `--cl-accent-primary` (bg) + `--cl-text-inverse` (text), hovering to `--cl-accent-primary-hover`.
- **Admonitions** consume their `--cl-state-{type}-{bg,border,text}` triplet — see custom.css.

---

## Code syntax highlighting

Prism syntax tokens map to the semantic `--cl-syntax-*` variables. The code block background is `--cl-surface-code`, with a `1px solid --cl-code-border` border.

| Token | Light | Dark | Purpose |
|---|---|---|---|
| `--cl-syntax-keyword` | `#1a4480` | `#7aa7f5` | `if`, `fn`, `let`, `const` |
| `--cl-syntax-string` | `#16a34a` | `#86efac` | String literals |
| `--cl-syntax-number` | `#9a6200` | `#f4c04a` | Numeric literals |
| `--cl-syntax-comment` | `#6b7890` | `#6b7890` | Inline and block comments |
| `--cl-syntax-function` | `#7c3aed` | `#c4b5fd` | Function and method names |
| `--cl-syntax-type` | `#0369a1` | `#67c3f3` | Type annotations, structs |
| `--cl-syntax-operator` | `#374151` | `#b0bec5` | Operators, punctuation |
| `--cl-syntax-variable` | `#1f2937` | `#e6edf3` | Variable names |

---

## Sidebar and navbar

**Navbar** uses `--cl-surface-nav` as its background. A single `1px solid --cl-border-default` bottom edge replaces the default Docusaurus drop shadow. Active navbar links receive `--cl-accent-primary`.

**Sidebar** background is `--cl-surface-sidebar` with a `1px solid --cl-border-default` right border. Active items get a `2px solid --cl-accent-primary` left border and `font-weight: 600` — the only place where the 10% accent and a structural cue appear together.

---

## Callouts / admonitions

Admonitions use a `4px solid` left border and a tinted background from the `--cl-state-*` token family. Five types ship with both light and dark mode values:

- **`:::info`** — `--cl-state-info-*` (blue). Version notes, scope, availability.
- **`:::tip`** — `--cl-state-tip-*` (green). Practical advice.
- **`:::note`** — `--cl-state-note-*` (slate). Side information.
- **`:::caution`** — `--cl-state-caution-*` (amber). Mildly surprising behavior.
- **`:::warning`** — `--cl-state-warning-*` / `--cl-state-danger-*` (red). Data-loss risk.

---

## Tabs

Tabs use a bottom-border highlight pattern. The inactive state shows a transparent border; the active state fills it with `--cl-accent-primary`.

```css
.tabs__item {
  border-bottom: 2px solid transparent;
  color: var(--ifm-tabs-color);
  transition: color 150ms ease, border-color 150ms ease;
}

.tabs__item--active {
  border-bottom-color: var(--ifm-tabs-color-active-border);
  color: var(--ifm-tabs-color-active);
}
```

The tokens involved: `--ifm-tabs-color`, `--ifm-tabs-color-active`, `--ifm-tabs-color-active-border` — all mapped from `--cl-text-secondary` and `--cl-accent-primary` respectively.

---

## Search UI

The search bar (DocSearch) is styled via scoped `.DocSearch-*` class overrides rather than the `--docsearch-*` CSS variables, to keep parity with the rest of the semantic system:

| Element | Token |
|---|---|
| Button background | `--cl-surface-card` |
| Button border | `--cl-border-default` |
| Button text | `--cl-text-muted` |
| Button hover border | `--cl-accent-primary` |
| Modal background | `--cl-bg-default` |
| Modal border | `--cl-border-default` |
| Result text | `--cl-text-primary` |
| Result path | `--cl-text-muted` |

---

## API reference styling

The `.api-method` badge is a small `inline-block` element with monospace type, uppercase lettering, and a state-colored fill:

| Class | State tokens | Method |
|---|---|---|
| `.api-method--get` | `--cl-state-tip-*` (green) | GET |
| `.api-method--post` | `--cl-state-info-*` (blue) | POST |
| `.api-method--put` | `--cl-state-caution-*` (amber) | PUT |
| `.api-method--patch` | `--cl-state-note-*` (slate) | PATCH |
| `.api-method--delete` | `--cl-state-danger-*` (red) | DELETE |

```html
<span class="api-method api-method--get">GET</span>
<span class="api-method api-method--post">POST</span>
<span class="api-method api-method--delete">DELETE</span>
```

Use these badges in API reference pages next to endpoint headings, not inline in prose.

---

## Gradients and hover states

### Hero gradient

One gradient utility is defined for hero/CTA panels only:

```css
.cl-hero-gradient {
  background: linear-gradient(
    135deg,
    var(--cl-accent-primary) 0%,
    var(--zuit-slate-700) 100%
  );
}
```

Do not use this class for anything other than full-bleed hero or CTA sections.

### Hover transitions

All interactive elements use `150ms ease` — no longer. Longer transitions feel sluggish on documentation sites where readers click frequently.

```css
/* Canonical hover pattern */
.element {
  transition: color 150ms ease, background 150ms ease;
}
```

---

## CSS variable naming convention

Token names follow the pattern: `--cl-{layer}-{role}-{variant}`

| Segment | Values | Meaning |
|---|---|---|
| `--cl-` | fixed prefix | Identifies a zuit semantic token |
| `{layer}` | `bg`, `surface`, `border`, `accent`, `text`, `state`, `code`, `syntax` | Design layer |
| `{role}` | `default`, `primary`, `secondary`, `muted`, `nav`, `sidebar`, `card`, etc. | Specific role within the layer |
| `{variant}` | `hover`, `active`, `muted`, `inverse`, `-bg`, `-border`, `-text` | State or sub-role variant |

**Hierarchy:**

```
--zuit-blue-700        (raw ramp — never in components)
  ↓ derived into
--cl-accent-primary        (semantic token — components use this)
  ↓ mapped onto
--ifm-color-primary        (Infima variable — Docusaurus uses this)
```

The mapping from `--cl-*` → `--ifm-*` lives in `:root` and `[data-theme='dark']`. Never skip a level — do not map a raw ramp token directly onto an Infima variable.

The full `:root` and `[data-theme='dark']` blocks live in `src/css/custom.css`.

---

## Verification

Run this command to validate WCAG AA compliance for all 26 contrast pairings (light + dark, including the 5 dimension tokens per mode):

```bash
node scripts/verify-contrast.mjs
```

The script exits non-zero if any pairing fails, making it suitable for CI. It checks:

- Body text on page background (4.5:1 min)
- Body text on sidebar surface (4.5:1 min)
- Body text on code block background (4.5:1 min)
- Link color on page background (4.5:1 min)
- Link color on sidebar (4.5:1 min)
- Button text on button background (4.5:1 min)
- Accent on page background as UI element (3:1 min)
- Muted text on page background (4.5:1 min)

All pairings are checked for both light and dark mode.

The build also enforces link integrity: `onBrokenLinks: 'throw'` in `docusaurus.config.ts` causes `npm run build` to fail on any broken internal link.
