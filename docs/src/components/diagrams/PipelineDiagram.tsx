import React, {useEffect, useState} from 'react';
import styles from './Diagram.module.css';

const STAGES = [
  { id: 'source', label: 'Source files', icon: 'S', sub: 'walk_files' },
  { id: 'parse',  label: 'Parse',        icon: 'P', sub: 'rayon ‖' },
  { id: 'analyze',label: 'Analyze',      icon: 'A', sub: 'rayon ‖' },
  { id: 'score',  label: 'Score',        icon: '∑', sub: 'per-dimension' },
  { id: 'output', label: 'Output',       icon: 'O', sub: 'term · JSON · SARIF · MD' },
] as const;

// viewBox: 0 0 960 240
// 5 cards, each 140px wide, gaps of (960 - 5*140) / 6 = 26.67 → use 20 gap + padding
const CARD_W = 140;
const CARD_H = 100;
const CARD_RX = 10;
const STAGE_Y = 60;
// x positions: evenly spaced with padding
const TOTAL_W = 960;
const PAD = (TOTAL_W - 5 * CARD_W) / 6; // ~26.7
const stageX = (i: number) => PAD + i * (CARD_W + PAD);

// Arrow: from right edge of card i to left edge of card i+1
const arrowY = STAGE_Y + CARD_H / 2;

// Packet travels along the 4 arrows sequentially
// We'll animate 3 packets staggered on the full path
const PATH_SEGS = STAGES.length - 1; // 4 arrow segments

function buildPacketPath(): string {
  const points = STAGES.slice(0, -1).map((_, i) => ({
    x1: stageX(i) + CARD_W + 4,
    x2: stageX(i + 1) - 4,
    y: arrowY,
  }));
  return points
    .map((p, i) => (i === 0 ? `M ${p.x1} ${p.y} L ${p.x2} ${p.y}` : `L ${p.x2} ${p.y}`))
    .join(' ');
}

function Packet({begin}: {begin: string}) {
  return (
    <circle r={5} fill="var(--cl-accent-primary)" opacity={0.85}>
      <animateMotion dur="3s" begin={begin} repeatCount="indefinite" path={buildPacketPath()} />
    </circle>
  );
}

function useMotionAllowed(): boolean {
  const [allowed, setAllowed] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setAllowed(!mq.matches);
    update();
    mq.addEventListener('change', update);
    return () => mq.removeEventListener('change', update);
  }, []);
  return allowed;
}

export default function PipelineDiagram(): React.ReactElement {
  const titleId = 'pipeline-title';
  const descId = 'pipeline-desc';
  const motionAllowed = useMotionAllowed();

  return (
    <div className={styles.pipelineWrapper}>
      <svg
        viewBox="0 0 960 240"
        width="100%"
        role="img"
        aria-labelledby={`${titleId} ${descId}`}
        className={styles.svg}
      >
        <title id={titleId}>zuit analysis pipeline</title>
        <desc id={descId}>
          Five-stage horizontal pipeline: Source files, Parse (parallelized with rayon), Analyze
          (parallelized with rayon), Score (per dimension), Output (terminal, JSON, SARIF, Markdown).
          Data-packet dots animate along the arrows between stages.
        </desc>

        <defs>
          <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="var(--cl-border-default)" />
          </marker>
        </defs>

        {/* Arrow connectors */}
        {STAGES.slice(0, -1).map((_, i) => {
          const x1 = stageX(i) + CARD_W;
          const x2 = stageX(i + 1);
          return (
            <line
              key={i}
              x1={x1}
              y1={arrowY}
              x2={x2}
              y2={arrowY}
              stroke="var(--cl-border-default)"
              strokeWidth={2}
              markerEnd="url(#arrow)"
            />
          );
        })}

        {/* Stage cards */}
        {STAGES.map((stage, i) => {
          const x = stageX(i);
          const isParallel = stage.sub === 'rayon ‖';
          return (
            <g key={stage.id}>
              <rect
                x={x}
                y={STAGE_Y}
                width={CARD_W}
                height={CARD_H}
                rx={CARD_RX}
                fill="var(--cl-surface-card)"
                stroke={isParallel ? 'var(--cl-accent-primary)' : 'var(--cl-border-default)'}
                strokeWidth={isParallel ? 2 : 1.5}
              />
              {/* Icon glyph circle */}
              <circle
                cx={x + CARD_W / 2}
                cy={STAGE_Y + 28}
                r={16}
                fill="var(--cl-accent-primary)"
                opacity={0.15}
              />
              <text
                x={x + CARD_W / 2}
                y={STAGE_Y + 34}
                textAnchor="middle"
                fontFamily="inherit"
                fontSize={16}
                fontWeight={700}
                fill="var(--cl-accent-primary)"
              >
                {stage.icon}
              </text>
              {/* Stage label */}
              <text
                x={x + CARD_W / 2}
                y={STAGE_Y + 62}
                textAnchor="middle"
                fontFamily="inherit"
                fontSize={13}
                fontWeight={600}
                fill="var(--cl-text-primary)"
              >
                {stage.label}
              </text>
              {/* Sub-label */}
              <text
                x={x + CARD_W / 2}
                y={STAGE_Y + 80}
                textAnchor="middle"
                fontFamily="inherit"
                fontSize={10}
                fill={isParallel ? 'var(--cl-accent-secondary)' : 'var(--cl-text-muted)'}
                fontWeight={isParallel ? 600 : 400}
              >
                {stage.sub}
              </text>
            </g>
          );
        })}

        {/* Caption strip */}
        <text
          x={960 / 2}
          y={200}
          textAnchor="middle"
          fontFamily="inherit"
          fontSize={11}
          fill="var(--cl-text-muted)"
        >
          Stages highlighted in blue border are parallelized via rayon
        </text>

        {motionAllowed && (
          <g aria-hidden="true">
            <Packet begin="0s" />
            <Packet begin="1s" />
            <Packet begin="2s" />
          </g>
        )}
      </svg>
    </div>
  );
}
