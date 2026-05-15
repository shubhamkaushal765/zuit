import React, { useState } from 'react';
import styles from './Diagram.module.css';

interface Dimension {
  id: string;
  name: string;
  ruleCount: number;
  tagline: string;
  examples: string[];
}

const DIMENSIONS: Dimension[] = [
  {
    id: 'maint',
    name: 'Maintainability',
    ruleCount: 7,
    tagline: 'length, nesting, branching',
    examples: ['MAINT001-cyclomatic', 'MAINT003-fn-length', 'MAINT005-deep-nesting'],
  },
  {
    id: 'sec',
    name: 'Security',
    ruleCount: 8,
    tagline: 'patterns commonly exploited',
    examples: ['SEC001-hardcoded-secret', 'SEC003-shell-injection', 'SEC101-rust-unsafe'],
  },
  {
    id: 'cplx',
    name: 'Complexity',
    ruleCount: 3,
    tagline: 'structural beyond per-fn metrics',
    examples: ['CPLX001-fan-out', 'CPLX002-cyclic-deps', 'CPLX003-duplicate-code'],
  },
  {
    id: 'doc',
    name: 'Documentation',
    ruleCount: 3,
    tagline: 'API doc coverage, TODO/FIXME',
    examples: ['DOC001-public-api-undoc', 'DOC002-todo-fixme', 'DOC003-empty-doc'],
  },
  {
    id: 'test',
    name: 'Test smell',
    ruleCount: 5,
    tagline: 'tests that lie or skip',
    examples: ['TEST001-test-ratio', 'TEST002-no-asserts', 'TEST003-skipped'],
  },
];

const VB_W = 720;
const VB_H = 520;

// Pentagon layout: 5 points around a center
const CX = VB_W / 2;
const CY = VB_H / 2 + 10;
const RADIUS = 170; // distance from center to pill center

// Pentagon: start at top, go clockwise
// Angle offset: -90deg so first point is at top
function pentagonPoint(i: number): [number, number] {
  const angle = (i * 2 * Math.PI) / 5 - Math.PI / 2;
  return [CX + RADIUS * Math.cos(angle), CY + RADIUS * Math.sin(angle)];
}

// Hub circle
const HUB_R = 48;

// Pill dimensions
const PILL_W = 152;
const PILL_H = 72;
const PILL_RX = 10;

// Tooltip
interface TooltipState {
  id: string;
  x: number;
  y: number;
}

export default function DimensionsHexagon(): React.ReactElement {
  const [active, setActive] = useState<TooltipState | null>(null);

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
      >
        <title id={titleId}>Five quality dimensions arranged around zuit hub</title>
        <desc id={descId}>
          Pentagon layout with zuit at center. The five dimensions — Maintainability (7 rules),
          Security (8 rules), Complexity (3 rules), Documentation (3 rules), Test smell (5 rules) —
          are arranged radially. Hover or focus a pill to see example rule IDs.
        </desc>

        {/* Spoke lines from hub to each pill */}
        {DIMENSIONS.map((dim, i) => {
          const [px, py] = pentagonPoint(i);
          // Shorten the line: stop at hub edge and pill edge
          const dx = px - CX;
          const dy = py - CY;
          const dist = Math.sqrt(dx * dx + dy * dy);
          const ux = dx / dist;
          const uy = dy / dist;
          const x1 = CX + ux * (HUB_R + 2);
          const y1 = CY + uy * (HUB_R + 2);
          // Stop at pill border (rough approximation)
          const pillHalfW = PILL_W / 2;
          const pillHalfH = PILL_H / 2;
          const tW = Math.abs(ux) > 0.01 ? pillHalfW / Math.abs(ux) : Infinity;
          const tH = Math.abs(uy) > 0.01 ? pillHalfH / Math.abs(uy) : Infinity;
          const t = Math.min(tW, tH);
          const x2 = px - ux * t;
          const y2 = py - uy * t;
          return (
            <line
              key={dim.id}
              x1={x1} y1={y1} x2={x2} y2={y2}
              stroke="var(--cl-border-default)"
              strokeWidth={1.5}
              strokeDasharray="4 3"
            />
          );
        })}

        {/* Hub */}
        <circle
          cx={CX} cy={CY} r={HUB_R}
          fill="var(--cl-surface-card)"
          stroke="var(--cl-accent-primary)"
          strokeWidth={3}
        />
        <text
          x={CX} y={CY - 6}
          textAnchor="middle"
          fontFamily="inherit" fontSize={11} fontWeight={700}
          fill="var(--cl-accent-primary)"
        >
          code
        </text>
        <text
          x={CX} y={CY + 9}
          textAnchor="middle"
          fontFamily="inherit" fontSize={11} fontWeight={700}
          fill="var(--cl-accent-primary)"
        >
          lens
        </text>

        {/* Dimension pills */}
        {DIMENSIONS.map((dim, i) => {
          const [px, py] = pentagonPoint(i);
          const isActive = active?.id === dim.id;
          return (
            <g
              key={dim.id}
              tabIndex={0}
              role="button"
              aria-label={`${dim.name}: ${dim.ruleCount} rules — ${dim.tagline}. Examples: ${dim.examples.join(', ')}`}
              className={styles.pill}
              style={{ transformOrigin: `${px}px ${py}px` }}
              onMouseEnter={() => setActive({ id: dim.id, x: px, y: py })}
              onMouseLeave={() => setActive(null)}
              onFocus={() => setActive({ id: dim.id, x: px, y: py })}
              onBlur={() => setActive(null)}
              onKeyDown={(e) => {
                if (e.key === 'Escape') setActive(null);
              }}
            >
              <rect
                x={px - PILL_W / 2}
                y={py - PILL_H / 2}
                width={PILL_W}
                height={PILL_H}
                rx={PILL_RX}
                fill="var(--cl-surface-card)"
                stroke={isActive ? 'var(--cl-accent-primary)' : 'var(--cl-border-default)'}
                strokeWidth={isActive ? 2 : 1.5}
              />
              {/* Dimension name */}
              <text
                x={px}
                y={py - 16}
                textAnchor="middle"
                fontFamily="inherit" fontSize={12} fontWeight={700}
                fill="var(--cl-text-primary)"
              >
                {dim.name}
              </text>
              {/* Rule count badge */}
              <rect
                x={px - 18} y={py - 8}
                width={36} height={16}
                rx={8}
                fill="var(--cl-accent-primary)"
                opacity={0.15}
              />
              <text
                x={px} y={py + 4}
                textAnchor="middle"
                fontFamily="inherit" fontSize={10} fontWeight={600}
                fill="var(--cl-accent-primary)"
              >
                {dim.ruleCount} rules
              </text>
              {/* Tagline */}
              <text
                x={px}
                y={py + 22}
                textAnchor="middle"
                fontFamily="inherit" fontSize={9.5}
                fill="var(--cl-text-muted)"
              >
                {dim.tagline}
              </text>
            </g>
          );
        })}

        {/* Inline tooltip — shown inside the SVG to stay SSR-safe */}
        {active && (() => {
          const dim = DIMENSIONS.find(d => d.id === active.id);
          if (!dim) return null;
          const [px, py] = pentagonPoint(DIMENSIONS.indexOf(dim));
          // Position tooltip below the pill unless it would clip bottom
          const tipW = 220;
          const tipH = 58;
          const tipX = Math.min(Math.max(px - tipW / 2, 8), VB_W - tipW - 8);
          const tipY = py + PILL_H / 2 + 8 > VB_H - tipH - 8
            ? py - PILL_H / 2 - tipH - 8
            : py + PILL_H / 2 + 8;
          return (
            <g aria-hidden="true" pointerEvents="none">
              <rect
                x={tipX} y={tipY}
                width={tipW} height={tipH}
                rx={6}
                fill="var(--cl-surface-elevated)"
                stroke="var(--cl-border-default)"
                strokeWidth={1}
              />
              <text
                x={tipX + 10} y={tipY + 16}
                fontFamily="inherit" fontSize={9.5} fontWeight={600}
                fill="var(--cl-text-muted)"
              >
                Example rules:
              </text>
              {dim.examples.map((ex, ei) => (
                <text
                  key={ex}
                  x={tipX + 10} y={tipY + 28 + ei * 11}
                  fontFamily="inherit" fontSize={9}
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
