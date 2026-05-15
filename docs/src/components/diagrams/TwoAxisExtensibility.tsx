import React from 'react';
import styles from './Diagram.module.css';

// viewBox: 0 0 840 420
// Layout:
//   CLI at top center
//   Middle row: lang crates on left, analyzers on right, divider in center
//   core at bottom center

const VB_W = 840;
const VB_H = 420;

const BOX_W = 148;
const BOX_H = 48;
const BOX_RX = 8;

// CLI box
const CLI_X = VB_W / 2 - BOX_W / 2;
const CLI_Y = 30;

// Core box
const CORE_X = VB_W / 2 - BOX_W / 2;
const CORE_Y = VB_H - 80;

// Middle row Y center
const MID_Y = 200;

// Lang crates on left: 3 boxes
const LANG_BOXES = [
  { id: 'rust', label: 'zuit-lang-rust' },
  { id: 'python', label: 'zuit-lang-python' },
  { id: 'js', label: 'zuit-lang-js' },
];

// Left group x-center (centered in left half minus divider gap)
const LEFT_CENTER = 200;
const LANG_Y_START = MID_Y - BOX_H - 16;
const LANG_Y_STEP = BOX_H + 16;

// Analyzers box on right
const AN_X = 550;
const AN_Y = MID_Y - BOX_H / 2;

function boxCenterX(x: number) { return x + BOX_W / 2; }
function boxCenterY(y: number) { return y + BOX_H / 2; }
function boxBottom(y: number) { return y + BOX_H; }

// Arrow from (x1,y1) to (x2,y2) with arrowhead marker
interface ArrowProps {
  x1: number; y1: number; x2: number; y2: number;
  markerId: string;
}
function Arrow({ x1, y1, x2, y2, markerId }: ArrowProps) {
  return (
    <line
      x1={x1} y1={y1} x2={x2} y2={y2}
      stroke="var(--cl-text-muted)"
      strokeWidth={1.5}
      markerEnd={`url(#${markerId})`}
    />
  );
}

export default function TwoAxisExtensibility(): React.ReactElement {
  const titleId = 'two-axis-title';
  const descId = 'two-axis-desc';

  return (
    <div className={styles.twoAxisWrapper}>
      <svg
        viewBox={`0 0 ${VB_W} ${VB_H}`}
        width="100%"
        role="img"
        aria-labelledby={`${titleId} ${descId}`}
        className={styles.svg}
      >
        <title id={titleId}>Two-axis extensibility dependency graph</title>
        <desc id={descId}>
          zuit-cli at the top depends on all middle-row crates. Language crates and
          zuit-analyzers both depend on zuit-core at the bottom. There are no arrows
          between language crates and zuit-analyzers — they are independent siblings.
        </desc>

        <defs>
          <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="var(--cl-text-muted)" />
          </marker>
        </defs>

        {/* CLI box */}
        <rect
          x={CLI_X} y={CLI_Y}
          width={BOX_W} height={BOX_H}
          rx={BOX_RX}
          fill="var(--cl-surface-card)"
          stroke="var(--cl-border-default)"
          strokeWidth={1.5}
        />
        <text
          x={boxCenterX(CLI_X)} y={CLI_Y + BOX_H / 2 + 5}
          textAnchor="middle"
          fontFamily="inherit" fontSize={12} fontWeight={600}
          fill="var(--cl-text-primary)"
        >
          zuit-cli
        </text>

        {/* Core box — highlighted */}
        <rect
          x={CORE_X} y={CORE_Y}
          width={BOX_W} height={BOX_H}
          rx={BOX_RX}
          fill="var(--cl-accent-primary)"
          stroke="var(--cl-accent-primary)"
          strokeWidth={2}
        />
        <text
          x={boxCenterX(CORE_X)} y={CORE_Y + BOX_H / 2 + 5}
          textAnchor="middle"
          fontFamily="inherit" fontSize={12} fontWeight={600}
          fill="var(--cl-text-inverse)"
        >
          zuit-core
        </text>

        {/* Lang crates */}
        {LANG_BOXES.map((box, i) => {
          const bx = LEFT_CENTER - BOX_W / 2;
          const by = LANG_Y_START + i * LANG_Y_STEP;
          return (
            <g key={box.id}>
              <rect
                x={bx} y={by}
                width={BOX_W} height={BOX_H}
                rx={BOX_RX}
                fill="var(--cl-surface-card)"
                stroke="var(--cl-border-default)"
                strokeWidth={1.5}
              />
              <text
                x={boxCenterX(bx)} y={by + BOX_H / 2 + 5}
                textAnchor="middle"
                fontFamily="inherit" fontSize={11} fontWeight={500}
                fill="var(--cl-text-primary)"
              >
                {box.label}
              </text>

              {/* Arrow: CLI → lang crate */}
              <Arrow
                x1={boxCenterX(CLI_X)}
                y1={boxBottom(CLI_Y)}
                x2={boxCenterX(bx)}
                y2={by}
                markerId="arr"
              />

              {/* Arrow: lang crate → core */}
              <Arrow
                x1={boxCenterX(bx)}
                y1={boxBottom(by)}
                x2={boxCenterX(CORE_X)}
                y2={CORE_Y}
                markerId="arr"
              />
            </g>
          );
        })}

        {/* Analyzers box */}
        <rect
          x={AN_X} y={AN_Y}
          width={BOX_W} height={BOX_H}
          rx={BOX_RX}
          fill="var(--cl-surface-card)"
          stroke="var(--cl-border-default)"
          strokeWidth={1.5}
        />
        <text
          x={boxCenterX(AN_X)} y={AN_Y + BOX_H / 2 + 5}
          textAnchor="middle"
          fontFamily="inherit" fontSize={11} fontWeight={500}
          fill="var(--cl-text-primary)"
        >
          zuit-analyzers
        </text>

        {/* Arrow: CLI → analyzers */}
        <Arrow
          x1={boxCenterX(CLI_X)}
          y1={boxBottom(CLI_Y)}
          x2={boxCenterX(AN_X)}
          y2={AN_Y}
          markerId="arr"
        />

        {/* Arrow: analyzers → core */}
        <Arrow
          x1={boxCenterX(AN_X)}
          y1={boxBottom(AN_Y)}
          x2={boxCenterX(CORE_X)}
          y2={CORE_Y}
          markerId="arr"
        />

        {/* Vertical divider between lang group and analyzers */}
        <line
          x1={420} y1={MID_Y - 80}
          x2={420} y2={MID_Y + 80}
          stroke="var(--cl-border-default)"
          strokeWidth={1}
          strokeDasharray="4 4"
        />
        <text
          x={420} y={MID_Y - 88}
          textAnchor="middle"
          fontFamily="inherit" fontSize={10}
          fill="var(--cl-text-muted)"
          fontStyle="italic"
        >
          neither group imports the other
        </text>

        {/* Group labels */}
        <text
          x={LEFT_CENTER} y={LANG_Y_START - 12}
          textAnchor="middle"
          fontFamily="inherit" fontSize={10} fontWeight={600}
          fill="var(--cl-text-muted)"
        >
          LANGUAGE FRONTENDS
        </text>
        <text
          x={boxCenterX(AN_X)} y={AN_Y - 12}
          textAnchor="middle"
          fontFamily="inherit" fontSize={10} fontWeight={600}
          fill="var(--cl-text-muted)"
        >
          cross-language
        </text>

        {/* Legend chip */}
        <rect
          x={VB_W - 160} y={VB_H - 40}
          width={150} height={28}
          rx={6}
          fill="var(--cl-surface-card)"
          stroke="var(--cl-border-default)"
          strokeWidth={1}
        />
        <line
          x1={VB_W - 148} y1={VB_H - 26}
          x2={VB_W - 126} y2={VB_H - 26}
          stroke="var(--cl-text-muted)"
          strokeWidth={1.5}
          markerEnd="url(#arr)"
        />
        <text
          x={VB_W - 118} y={VB_H - 21}
          fontFamily="inherit" fontSize={10}
          fill="var(--cl-text-muted)"
        >
          depends on
        </text>
      </svg>
    </div>
  );
}
