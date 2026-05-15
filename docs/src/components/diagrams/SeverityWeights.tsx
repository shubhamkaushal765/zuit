import React, { useState } from 'react';
import styles from './Diagram.module.css';

interface SeverityRow {
  label: string;
  weight: number;
  example: string;
}

const SEVERITIES: SeverityRow[] = [
  { label: 'info',     weight: 0,  example: 'info → DOC002 inline TODO comment' },
  { label: 'low',      weight: 1,  example: 'low → MAINT006 too many parameters' },
  { label: 'medium',   weight: 4,  example: 'medium → MAINT001 cyclomatic > threshold' },
  { label: 'high',     weight: 12, example: 'high → SEC003 shell injection risk' },
  { label: 'critical', weight: 30, example: 'critical → SEC001 hardcoded AWS key' },
];

const VB_W = 720;
const VB_H = 320;

const BAR_HEIGHT = 32;
const BAR_GAP = 14;
const LABEL_W = 72;
const VALUE_W = 36;
const CHART_LEFT = LABEL_W + 12;
const CHART_RIGHT = VB_W - VALUE_W - 16;
const CHART_W = CHART_RIGHT - CHART_LEFT;
const TOP_PAD = 24;
const MAX_WEIGHT = 30;

function barY(i: number): number {
  return TOP_PAD + i * (BAR_HEIGHT + BAR_GAP);
}

export default function SeverityWeights(): React.ReactElement {
  const [activeIdx, setActiveIdx] = useState<number | null>(null);

  const titleId = 'sev-weights-title';
  const descId  = 'sev-weights-desc';

  const chartH = SEVERITIES.length * (BAR_HEIGHT + BAR_GAP) - BAR_GAP;
  const captionY = TOP_PAD + chartH + 28;

  return (
    <div className={styles.severityWrapper}>
      <svg
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        width="100%"
        role="img"
        aria-labelledby={`${titleId} ${descId}`}
        className={styles.svg}
      >
        <title id={titleId}>Severity weights bar chart</title>
        <desc id={descId}>
          Horizontal bar chart. info=0, low=1, medium=4, high=12, critical=30.
          Hover or focus a bar to see an example finding for that severity.
        </desc>

        {SEVERITIES.map((sev, i) => {
          const y = barY(i);
          // info gets a special zero-width outlined bar
          const isInfo = sev.weight === 0;
          const barW = isInfo ? 0 : (sev.weight / MAX_WEIGHT) * CHART_W;
          const isActive = activeIdx === i;

          return (
            <g
              key={sev.label}
              tabIndex={0}
              role="button"
              aria-label={`${sev.label}: weight ${sev.weight}. ${sev.example}`}
              className={styles.pill}
              onMouseEnter={() => setActiveIdx(i)}
              onMouseLeave={() => setActiveIdx(null)}
              onFocus={() => setActiveIdx(i)}
              onBlur={() => setActiveIdx(null)}
              onKeyDown={(e) => { if (e.key === 'Escape') setActiveIdx(null); }}
            >
              {/* Row label */}
              <text
                x={LABEL_W}
                y={y + BAR_HEIGHT / 2 + 4}
                textAnchor="end"
                fontFamily="inherit" fontSize={12} fontWeight={500}
                fill={isActive ? 'var(--cl-text-primary)' : 'var(--cl-text-muted)'}
              >
                {sev.label}
              </text>

              {/* Track */}
              <rect
                x={CHART_LEFT}
                y={y}
                width={CHART_W}
                height={BAR_HEIGHT}
                rx={4}
                fill="var(--cl-surface-card)"
                stroke="var(--cl-border-muted)"
                strokeWidth={1}
              />

              {/* Bar fill — info gets a thin outline placeholder */}
              {isInfo ? (
                <rect
                  x={CHART_LEFT}
                  y={y}
                  width={28}
                  height={BAR_HEIGHT}
                  rx={4}
                  fill="none"
                  stroke="var(--cl-border-default)"
                  strokeWidth={1.5}
                  strokeDasharray="4 3"
                />
              ) : (
                <rect
                  x={CHART_LEFT}
                  y={y}
                  width={barW}
                  height={BAR_HEIGHT}
                  rx={4}
                  fill="var(--cl-accent-secondary)"
                  opacity={isActive ? 1 : 0.82}
                  className={styles.barAnimated}
                  style={{ transformOrigin: `${CHART_LEFT}px ${y + BAR_HEIGHT / 2}px` }}
                />
              )}

              {/* Weight label on right */}
              <text
                x={CHART_RIGHT + 8}
                y={y + BAR_HEIGHT / 2 + 4}
                fontFamily="inherit" fontSize={12} fontWeight={700}
                fill={isActive ? 'var(--cl-accent-secondary)' : 'var(--cl-text-muted)'}
              >
                {sev.weight}
              </text>

              {/* Hover tooltip inside SVG */}
              {isActive && (
                <g pointerEvents="none" aria-hidden="true">
                  <rect
                    x={CHART_LEFT}
                    y={y - 36}
                    width={380}
                    height={28}
                    rx={6}
                    fill="var(--cl-surface-elevated)"
                    stroke="var(--cl-border-default)"
                    strokeWidth={1}
                  />
                  <text
                    x={CHART_LEFT + 10}
                    y={y - 16}
                    fontFamily="inherit" fontSize={10}
                    fill="var(--cl-text-primary)"
                  >
                    {sev.example}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Caption */}
        <text
          x={CHART_LEFT}
          y={captionY}
          fontFamily="inherit" fontSize={10.5}
          fill="var(--cl-text-muted)"
        >
          critical (30×) ≈ 30 low findings — one hardcoded secret outweighs a page of style nits.
        </text>
      </svg>
    </div>
  );
}
