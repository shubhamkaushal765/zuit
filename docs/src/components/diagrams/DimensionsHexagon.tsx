import React, { useState } from 'react';
import styles from './Diagram.module.css';

interface Dimension {
  id: string;
  name: string;
  serialised: string;
  ruleCount: number;
  tagline: string;
  examples: string[];
}

const DIMENSIONS: Dimension[] = [
  { id: 'sec',    name: 'Security',        serialised: 'security',         ruleCount: 16, tagline: 'exploited patterns',          examples: ['SEC001-hardcoded-secret', 'SEC002-eval-sink', 'SEC101-rust-unsafe'] },
  { id: 'maint',  name: 'Maintainability', serialised: 'maintainability',  ruleCount: 14, tagline: 'length · nesting · branching', examples: ['MAINT001-cyclomatic', 'MAINT003-fn-length', 'MAINT005-deep-nesting'] },
  { id: 'cplx',   name: 'Complexity',      serialised: 'complexity',       ruleCount: 3,  tagline: 'structural · cross-file',      examples: ['CPLX001-fan-out', 'CPLX002-cyclic-deps', 'CPLX003-duplicate-code'] },
  { id: 'doc',    name: 'Documentation',   serialised: 'documentation',    ruleCount: 4,  tagline: 'doc coverage · TODO/FIXME',    examples: ['DOC001-public-api-undoc', 'DOC002-todo-fixme', 'DOC003-empty-doc'] },
  { id: 'test',   name: 'Test smell',      serialised: 'test_smell',       ruleCount: 6,  tagline: 'tests that lie or skip',       examples: ['TEST001-test-ratio', 'TEST002-no-asserts', 'TEST005-assert-count'] },
  { id: 'chain',  name: 'Supply chain',    serialised: 'supply_chain',     ruleCount: 8,  tagline: 'lockfiles · provenance',       examples: ['CHAIN001-no-lockfile', 'CHAIN002-typosquat-suspicion', 'DEP001-vulnerable-deps'] },
  { id: 'pkg',    name: 'Packaging',       serialised: 'packaging',        ruleCount: 23, tagline: 'metadata · consumer UX',       examples: ['PKG002-missing-types', 'PKG004-unpinned-deps', 'PKG005-engines-missing'] },
  { id: 'perf',   name: 'Performance',     serialised: 'performance',      ruleCount: 8,  tagline: 'bundle size · heavy imports',  examples: ['PERF001-bundle-size', 'PERF002-heavy-import', 'PERF003-arc-mutex-density'] },
  { id: 'sound',  name: 'Soundness',       serialised: 'unsafe_soundness', ruleCount: 6,  tagline: 'unsafe · transmute · FFI',     examples: ['SOUND001-unsafe-block-missing-safety-comment', 'SOUND003-transmute-usage', 'SOUND006-ffi-without-safety-doc'] },
  { id: 'health', name: 'Project health',  serialised: 'project_health',   ruleCount: 5,  tagline: 'bus factor · release cadence', examples: ['HEALTH001-single-author', 'HEALTH002-stale-release', 'HEALTH005-changelog-missing'] },
  { id: 'ci',     name: 'CI / release',    serialised: 'ci_release',       ruleCount: 5,  tagline: 'pipeline completeness',        examples: ['CI001-no-ci-config', 'CI002-no-msrv-test-job', 'CI005-no-dependabot'] },
  { id: 'eco',    name: 'Ecosystem',       serialised: 'ecosystem',        ruleCount: 4,  tagline: 'no_std · async runtime',       examples: ['ECO001-no-no-std-feature', 'ECO002-async-runtime-coupling', 'ECO004-feature-graph-fragmented'] },
  { id: 'api',    name: 'API stability',   serialised: 'api_stability',    ruleCount: 3,  tagline: 'semver drift',                 examples: ['API001-public-symbol-removed', 'API002-signature-arity-changed', 'API003-semver-alignment'] },
];

// Grid layout constants
const VB_W = 880;
const VB_H = 560;

const COLS = 4;
const CARD_W = 188;
const CARD_H = 102;
const CARD_RX = 9;
const GAP_X = 24;
const GAP_Y = 20;

// Top-left origin of the 4×3 block (rows 0-2 have 4 cards each; row 3 has 1 centred)
const GRID_TOP = 20;
const GRID_LEFT = (VB_W - (COLS * CARD_W + (COLS - 1) * GAP_X)) / 2;

// Badge for rule count
const BADGE_H = 16;
const BADGE_RX = 8;

// Tooltip
const TIP_W = 260;
const TIP_H = 72;
const TIP_PAD = 10;
const TIP_LINE_H = 11;

interface ActiveCard {
  id: string;
  cx: number; // card centre x
  cy: number; // card centre y
}

/** Returns the top-left corner of card at index i (0-based). */
function cardOrigin(i: number): [number, number] {
  const totalCards = DIMENSIONS.length; // 13
  const fullRows = Math.floor(totalCards / COLS); // 3 full rows
  const remainder = totalCards % COLS; // 1

  if (i < fullRows * COLS) {
    const row = Math.floor(i / COLS);
    const col = i % COLS;
    const x = GRID_LEFT + col * (CARD_W + GAP_X);
    const y = GRID_TOP + row * (CARD_H + GAP_Y);
    return [x, y];
  }

  // Last partial row: centre the remaining card(s)
  const row = fullRows;
  const col = i - fullRows * COLS;
  const rowW = remainder * CARD_W + (remainder - 1) * GAP_X;
  const rowLeft = (VB_W - rowW) / 2;
  const x = rowLeft + col * (CARD_W + GAP_X);
  const y = GRID_TOP + row * (CARD_H + GAP_Y);
  return [x, y];
}

export default function DimensionsHexagon(): React.ReactElement {
  const [active, setActive] = useState<ActiveCard | null>(null);

  const titleId = 'dim-hex-title';
  const descId = 'dim-hex-desc';

  return (
    <div className={styles.dimensionsWrapper}>
      <svg
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        width="100%"
        role="img"
        aria-labelledby={`${titleId} ${descId}`}
        className={styles.svg}
        onKeyDown={(e) => { if (e.key === 'Escape') setActive(null); }}
      >
        <title id={titleId}>Thirteen zuit quality dimensions</title>
        <desc id={descId}>
          Grid of 13 quality dimension cards: Security (16 rules), Maintainability (14 rules),
          Complexity (3 rules), Documentation (4 rules), Test smell (6 rules), Supply chain (8 rules),
          Packaging (23 rules), Performance (8 rules), Soundness (6 rules), Project health (5 rules),
          CI / release (5 rules), Ecosystem (4 rules), API stability (3 rules).
          Hover or focus a card to see example rule IDs.
        </desc>

        {DIMENSIONS.map((dim, i) => {
          const [ox, oy] = cardOrigin(i);
          const cx = ox + CARD_W / 2;
          const cy = oy + CARD_H / 2;
          const isActive = active?.id === dim.id;

          // Badge width: measure roughly — 7px per char + padding
          const badgeLabel = `${dim.ruleCount} ${dim.ruleCount === 1 ? 'rule' : 'rules'}`;
          const badgeW = Math.max(badgeLabel.length * 5.8 + 14, 36);

          // Monospace token for serialised name
          const monoLabel = dim.serialised;

          return (
            <g
              key={dim.id}
              tabIndex={0}
              role="button"
              aria-label={`${dim.name}: ${dim.ruleCount} ${dim.ruleCount === 1 ? 'rule' : 'rules'} — ${dim.tagline}. Examples: ${dim.examples.join(', ')}`}
              className={styles.pill}
              style={{ transformOrigin: `${cx}px ${cy}px` }}
              onMouseEnter={() => setActive({ id: dim.id, cx, cy })}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive({ id: dim.id, cx, cy })}
              onBlur={() => setActive(null)}
              onKeyDown={(e) => { if (e.key === 'Escape') setActive(null); }}
            >
              {/* Card background */}
              <rect
                x={ox}
                y={oy}
                width={CARD_W}
                height={CARD_H}
                rx={CARD_RX}
                fill="var(--cl-surface-card)"
                stroke={isActive ? 'var(--cl-accent-primary)' : 'var(--cl-border-default)'}
                strokeWidth={isActive ? 2 : 1.5}
              />

              {/* Dimension name — bold */}
              <text
                x={cx}
                y={oy + 22}
                textAnchor="middle"
                fontFamily="inherit"
                fontSize={13}
                fontWeight={700}
                fill="var(--cl-text-primary)"
              >
                {dim.name}
              </text>

              {/* Rule count badge */}
              <rect
                x={cx - badgeW / 2}
                y={oy + 30}
                width={badgeW}
                height={BADGE_H}
                rx={BADGE_RX}
                fill="var(--cl-accent-primary)"
                opacity={0.15}
              />
              <text
                x={cx}
                y={oy + 42}
                textAnchor="middle"
                fontFamily="inherit"
                fontSize={10}
                fontWeight={600}
                fill="var(--cl-accent-primary)"
              >
                {badgeLabel}
              </text>

              {/* Tagline */}
              <text
                x={cx}
                y={oy + 62}
                textAnchor="middle"
                fontFamily="inherit"
                fontSize={10}
                fill="var(--cl-text-muted)"
              >
                {dim.tagline}
              </text>

              {/* Serialised name — monospace token */}
              <rect
                x={cx - monoLabel.length * 3.5 - 6}
                y={oy + 71}
                width={monoLabel.length * 7 + 12}
                height={15}
                rx={3}
                fill="var(--cl-surface-elevated)"
                stroke="var(--cl-border-default)"
                strokeWidth={0.75}
              />
              <text
                x={cx}
                y={oy + 82}
                textAnchor="middle"
                fontFamily="'SFMono-Regular', 'Consolas', 'Menlo', monospace"
                fontSize={9}
                fill="var(--cl-text-muted)"
              >
                {monoLabel}
              </text>
            </g>
          );
        })}

        {/* Inline tooltip — rendered inside the SVG to remain SSR-safe (no document/portals) */}
        {active && (() => {
          const dim = DIMENSIONS.find((d) => d.id === active.id);
          if (!dim) return null;

          // Position tooltip below card; flip above when it would clip bottom edge
          const cardBot = active.cy + CARD_H / 2;
          const cardTop = active.cy - CARD_H / 2;
          const tipBelowY = cardBot + 8;
          const tipAboveY = cardTop - TIP_H - 8;
          const tipY = tipBelowY + TIP_H > VB_H - 4 ? tipAboveY : tipBelowY;

          // Clamp horizontally
          const tipX = Math.min(Math.max(active.cx - TIP_W / 2, 4), VB_W - TIP_W - 4);

          return (
            <g aria-hidden="true" pointerEvents="none">
              <rect
                x={tipX}
                y={tipY}
                width={TIP_W}
                height={TIP_H}
                rx={6}
                fill="var(--cl-surface-elevated)"
                stroke="var(--cl-border-default)"
                strokeWidth={1}
              />
              <text
                x={tipX + TIP_PAD}
                y={tipY + 16}
                fontFamily="inherit"
                fontSize={9.5}
                fontWeight={600}
                fill="var(--cl-text-muted)"
              >
                Example rules:
              </text>
              {dim.examples.map((ex, ei) => (
                <text
                  key={ex}
                  x={tipX + TIP_PAD}
                  y={tipY + 28 + ei * TIP_LINE_H}
                  fontFamily="'SFMono-Regular', 'Consolas', 'Menlo', monospace"
                  fontSize={9}
                  fill="var(--cl-accent-primary)"
                >
                  {ex}
                </text>
              ))}
            </g>
          );
        })()}
      </svg>
    </div>
  );
}
