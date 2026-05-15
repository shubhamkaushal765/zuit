import type {ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import styles from './index.module.css';

// Dimension stripe colors — one per dimension for taxonomic clarity.
// `stripe` is a CSS var reference so the homepage cards pick up theme changes
// and dark-mode lifts from the same --cl-dimension-* tokens used elsewhere.
const dimensions = [
  {
    name: 'Maintainability',
    desc: 'Length, nesting, branching — how easy the code is to change.',
    stripe: 'var(--cl-dimension-maintainability)',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <rect x="2" y="4" width="16" height="2" rx="1" fill="currentColor"/>
        <rect x="2" y="9" width="11" height="2" rx="1" fill="currentColor"/>
        <rect x="2" y="14" width="13" height="2" rx="1" fill="currentColor"/>
      </svg>
    ),
  },
  {
    name: 'Security',
    desc: 'Hardcoded secrets, eval sinks, unsafe blocks.',
    stripe: 'var(--cl-dimension-security)',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <path d="M10 2L4 5v5c0 3.3 2.5 6.4 6 7 3.5-.6 6-3.7 6-7V5l-6-3z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
        <line x1="10" y1="8" x2="10" y2="11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <circle cx="10" cy="13" r="1" fill="currentColor"/>
      </svg>
    ),
  },
  {
    name: 'Complexity',
    desc: 'Project-level fan-out and dependency cycles.',
    stripe: 'var(--cl-dimension-complexity)',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <circle cx="10" cy="10" r="3" stroke="currentColor" strokeWidth="1.5"/>
        <circle cx="4"  cy="4"  r="2" stroke="currentColor" strokeWidth="1.5"/>
        <circle cx="16" cy="4"  r="2" stroke="currentColor" strokeWidth="1.5"/>
        <circle cx="4"  cy="16" r="2" stroke="currentColor" strokeWidth="1.5"/>
        <circle cx="16" cy="16" r="2" stroke="currentColor" strokeWidth="1.5"/>
        <line x1="7"  y1="7"  x2="5.5"  y2="5.5"  stroke="currentColor" strokeWidth="1"/>
        <line x1="13" y1="7"  x2="14.5" y2="5.5"  stroke="currentColor" strokeWidth="1"/>
        <line x1="7"  y1="13" x2="5.5"  y2="14.5" stroke="currentColor" strokeWidth="1"/>
        <line x1="13" y1="13" x2="14.5" y2="14.5" stroke="currentColor" strokeWidth="1"/>
      </svg>
    ),
  },
  {
    name: 'Documentation',
    desc: 'Public-API doc coverage and TODO/FIXME inventory.',
    stripe: 'var(--cl-dimension-documentation)',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <rect x="3" y="2" width="14" height="16" rx="2" stroke="currentColor" strokeWidth="1.5"/>
        <line x1="6" y1="7"  x2="14" y2="7"  stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <line x1="6" y1="10" x2="14" y2="10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <line x1="6" y1="13" x2="10" y2="13" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    name: 'Test smell',
    desc: 'Test ratio, missing assertions, skipped tests.',
    stripe: 'var(--cl-dimension-test)',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <path d="M7 10l2 2 4-4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
        <circle cx="10" cy="10" r="7.5" stroke="currentColor" strokeWidth="1.5"/>
      </svg>
    ),
  },
];

// Inline pipeline SVG for the hero — simplified version of zuit-flow.svg
function PipelineDiagram(): ReactNode {
  return (
    <svg
      viewBox="0 0 560 280"
      width="100%"
      aria-label="zuit analysis pipeline: source files, parse, analyzers, findings, report"
      className={styles.heroDiagram}
    >
      {/* Source */}
      <rect x="10"  y="80" width="90" height="70" rx="6" fill="var(--zuit-blue-800)"/>
      <rect x="25"  y="93" width="38" height="44" rx="2" fill="var(--zuit-blue-600)"/>
      <line x1="30" y1="103" x2="57" y2="103" stroke="var(--zuit-blue-200)" strokeWidth="1.5" strokeLinecap="round"/>
      <line x1="30" y1="111" x2="57" y2="111" stroke="var(--zuit-blue-200)" strokeWidth="1.5" strokeLinecap="round"/>
      <line x1="30" y1="119" x2="48" y2="119" stroke="var(--zuit-blue-200)" strokeWidth="1.5" strokeLinecap="round"/>
      <line x1="30" y1="127" x2="53" y2="127" stroke="var(--zuit-blue-200)" strokeWidth="1.5" strokeLinecap="round"/>
      <text x="55"  y="172" fontFamily="system-ui,sans-serif" fontSize="11" fill="var(--zuit-blue-200)" textAnchor="middle">Source</text>

      {/* Arrow */}
      <line x1="102" y1="115" x2="128" y2="115" stroke="var(--zuit-blue-300)" strokeWidth="2"/>
      <polygon points="128,110 140,115 128,120" fill="var(--zuit-blue-300)"/>

      {/* Parse */}
      <rect x="140" y="80" width="90" height="70" rx="6" fill="var(--zuit-blue-800)"/>
      <text x="162"  y="126" fontFamily="monospace,system-ui" fontSize="26" fill="var(--zuit-blue-200)">{"{"}</text>
      <text x="197"  y="126" fontFamily="monospace,system-ui" fontSize="26" fill="var(--zuit-blue-200)">{"}"}</text>
      <text x="185"  y="172" fontFamily="system-ui,sans-serif" fontSize="11" fill="var(--zuit-blue-200)" textAnchor="middle">Parse</text>

      {/* Arrow */}
      <line x1="232" y1="115" x2="258" y2="115" stroke="var(--zuit-blue-300)" strokeWidth="2"/>
      <polygon points="258,110 270,115 258,120" fill="var(--zuit-blue-300)"/>

      {/* Analyzers */}
      <rect x="270" y="65" width="100" height="100" rx="6" fill="var(--zuit-blue-800)"/>
      <circle cx="306" cy="105" r="5" fill="var(--zuit-amber-400)"/>
      <circle cx="320" cy="118" r="5" fill="var(--zuit-amber-400)"/>
      <circle cx="334" cy="105" r="5" fill="var(--zuit-amber-400)"/>
      <circle cx="306" cy="131" r="5" fill="var(--zuit-blue-300)"/>
      <circle cx="334" cy="131" r="5" fill="var(--zuit-blue-300)"/>
      <text x="320"  y="180" fontFamily="system-ui,sans-serif" fontSize="11" fill="var(--zuit-blue-200)" textAnchor="middle">Analyzers</text>

      {/* Arrow */}
      <line x1="372" y1="115" x2="398" y2="115" stroke="var(--zuit-blue-300)" strokeWidth="2"/>
      <polygon points="398,110 410,115 398,120" fill="var(--zuit-blue-300)"/>

      {/* Findings stacked — fills track --cl-dimension-* so light/dark stay
          consistent with the homepage dimension cards and rule-page bands. */}
      <rect x="410" y="72"  width="96" height="18" rx="3" fill="var(--cl-dimension-security)" opacity="0.9"/>
      <text x="458" y="85"  fontFamily="system-ui,sans-serif" fontSize="10" fill="var(--cl-text-inverse)" textAnchor="middle">Security</text>
      <rect x="410" y="94"  width="96" height="18" rx="3" fill="var(--cl-dimension-maintainability)" opacity="0.9"/>
      <text x="458" y="107" fontFamily="system-ui,sans-serif" fontSize="10" fill="var(--cl-text-inverse)" textAnchor="middle">Maintainability</text>
      <rect x="410" y="116" width="96" height="18" rx="3" fill="var(--cl-dimension-complexity)" opacity="0.9"/>
      <text x="458" y="129" fontFamily="system-ui,sans-serif" fontSize="10" fill="var(--cl-text-inverse)" textAnchor="middle">Complexity</text>
      <rect x="410" y="138" width="96" height="18" rx="3" fill="var(--cl-dimension-documentation)" opacity="0.9"/>
      <text x="458" y="151" fontFamily="system-ui,sans-serif" fontSize="10" fill="var(--cl-text-inverse)" textAnchor="middle">Documentation</text>
      <rect x="410" y="160" width="96" height="18" rx="3" fill="var(--cl-dimension-test)" opacity="0.9"/>
      <text x="458" y="173" fontFamily="system-ui,sans-serif" fontSize="10" fill="var(--cl-text-inverse)" textAnchor="middle">Test Smell</text>
      <text x="458" y="197" fontFamily="system-ui,sans-serif" fontSize="11" fill="var(--zuit-blue-200)" textAnchor="middle">Findings</text>

      {/* Arrow */}
      <line x1="508" y1="115" x2="526" y2="115" stroke="var(--zuit-blue-300)" strokeWidth="2"/>
      <polygon points="526,110 538,115 526,120" fill="var(--zuit-blue-300)"/>

      {/* Report */}
      <rect x="538" y="80" width="18" height="70" rx="4" fill="var(--zuit-blue-800)"/>
      <rect x="541" y="85"  width="12" height="5" rx="1" fill="var(--zuit-amber-400)"/>
      <rect x="541" y="94"  width="9"  height="5" rx="1" fill="var(--zuit-blue-300)"/>
      <rect x="541" y="103" width="11" height="5" rx="1" fill="var(--zuit-blue-300)"/>
      <rect x="541" y="112" width="7"  height="5" rx="1" fill="var(--zuit-blue-300)"/>
      <rect x="541" y="121" width="10" height="5" rx="1" fill="var(--zuit-blue-300)"/>
      <text x="547" y="172" fontFamily="system-ui,sans-serif" fontSize="11" fill="var(--zuit-blue-200)" textAnchor="middle">Report</text>
    </svg>
  );
}

function HomepageHero(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={styles.hero}>
      <div className={clsx('container', styles.heroInner)}>
        <div className={styles.heroCopy}>
          <Heading as="h1" className={styles.heroTitle}>{siteConfig.title}</Heading>
          <p className={styles.heroTagline}>{siteConfig.tagline}</p>
          <div className={styles.heroButtons}>
            <Link className={clsx('button button--lg', styles.btnPrimary)} to="/quickstart">
              Scan a repo in 60 seconds
            </Link>
            <Link className={clsx('button button--lg', styles.btnOutline)} to="/workflows/gate-ci">
              See it in CI
            </Link>
          </div>
        </div>
        <div className={styles.heroVisual}>
          <PipelineDiagram />
        </div>
      </div>
    </header>
  );
}

function DimensionsSection(): ReactNode {
  return (
    <section className={styles.section}>
      <div className="container">
        <Heading as="h2" className={styles.sectionHeading}>Five dimensions</Heading>
        <p className={styles.sectionLead}>
          zuit groups every finding under one of five named dimensions and emits an independent
          0–100 score for each.
        </p>
        <div className={styles.cardGrid}>
          {dimensions.map((d) => (
            <Link key={d.name} className={styles.card} to="/concepts/dimensions">
              <span className={styles.cardStripe} style={{background: d.stripe}} aria-hidden="true"/>
              <span className={styles.cardIcon} style={{color: d.stripe}}>{d.icon}</span>
              <Heading as="h3" className={styles.cardTitle}>{d.name}</Heading>
              <p className={styles.cardDesc}>{d.desc}</p>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

const workflows = [
  {
    title: 'Local dev loop',
    desc: 'Watch mode and LSP underline findings as you type — no CI round-trip.',
    stripe: 'var(--cl-dimension-maintainability)',
    to: '/workflows/daily-dev-loop',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <rect x="2" y="3" width="16" height="12" rx="2" stroke="currentColor" strokeWidth="1.5"/>
        <line x1="7" y1="17" x2="13" y2="17" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <rect x="5" y="7" width="2" height="4" rx="1" fill="currentColor"/>
      </svg>
    ),
  },
  {
    title: 'CI quality gate',
    desc: 'Fail builds when findings cross a severity threshold. Upload SARIF to GitHub code scanning.',
    stripe: 'var(--cl-dimension-security)',
    to: '/workflows/gate-ci',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <path d="M10 2L4 5v5c0 3.3 2.5 6.4 6 7 3.5-.6 6-3.7 6-7V5l-6-3z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
        <path d="M7.5 10l2 2 3-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    title: 'Legacy adoption',
    desc: 'Baseline existing findings so CI only fails on what\'s new.',
    stripe: 'var(--cl-dimension-complexity)',
    to: '/workflows/adopt-legacy',
    icon: (
      <svg viewBox="0 0 20 20" width="18" height="18" fill="none" aria-hidden="true">
        <rect x="3" y="7" width="14" height="10" rx="2" stroke="currentColor" strokeWidth="1.5"/>
        <path d="M7 7V5a3 3 0 016 0v2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
        <line x1="6" y1="12" x2="14" y2="12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
  },
];

function HowTeamsUseSection(): ReactNode {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <Heading as="h2" className={styles.sectionHeading}>How teams use zuit</Heading>
        <p className={styles.sectionLead}>
          Three common flows. Pick the one that matches today's problem.
        </p>
        <div className={styles.cardGrid}>
          {workflows.map((w) => (
            <Link key={w.title} className={styles.card} to={w.to}>
              <span className={styles.cardStripe} style={{background: w.stripe}} aria-hidden="true"/>
              <span className={styles.cardIcon} style={{color: w.stripe}}>{w.icon}</span>
              <Heading as="h3" className={styles.cardTitle}>{w.title}</Heading>
              <p className={styles.cardDesc}>{w.desc}</p>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

// Inline pipeline nodes — five labelled boxes connected by arrows
function PipelineAtAGlance(): ReactNode {
  const nodes = ['Source', 'Parse', 'Analyzers', 'Findings', 'Report'];
  const W = 96;
  const H = 40;
  const gap = 36;
  const total = nodes.length * W + (nodes.length - 1) * gap;
  const svgH = H + 40;

  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <Heading as="h2" className={styles.sectionHeading}>Pipeline at a glance</Heading>
        <p className={styles.sectionLead}>
          Every <code>zuit analyze</code> run follows five deterministic stages. Output is sorted
          by <code>(file, span, rule_id)</code> — two runs against unchanged source produce
          byte-identical output.
        </p>
        <div className={styles.pipelineWrap}>
          <svg
            viewBox={`0 0 ${total} ${svgH}`}
            className={styles.pipelineSvg}
            aria-label="Pipeline: Source → Parse → Analyzers → Findings → Report"
          >
            {nodes.map((label, i) => {
              const x = i * (W + gap);
              const midY = svgH / 2 - 6;
              return (
                <g key={label}>
                  <rect x={x} y={midY - H / 2} width={W} height={H} rx="5"
                    fill="var(--ifm-color-primary)" opacity="0.12"
                    stroke="var(--ifm-color-primary)" strokeWidth="1.5"/>
                  <text x={x + W / 2} y={midY + 5}
                    fontFamily="system-ui,sans-serif" fontSize="13" fontWeight="600"
                    fill="var(--ifm-color-primary)" textAnchor="middle">
                    {label}
                  </text>
                  {i < nodes.length - 1 && (
                    <>
                      <line
                        x1={x + W + 2} y1={midY}
                        x2={x + W + gap - 8} y2={midY}
                        stroke="var(--ifm-color-primary)" strokeWidth="1.5"/>
                      <polygon
                        points={`${x + W + gap - 8},${midY - 5} ${x + W + gap},${midY} ${x + W + gap - 8},${midY + 5}`}
                        fill="var(--ifm-color-primary)"/>
                    </>
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      </div>
    </section>
  );
}

function QuickStartSection(): ReactNode {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <Heading as="h2" className={styles.sectionHeading}>Quick start</Heading>
        <div className={styles.quickStartCard}>
          <pre className={styles.code}>
            <code>{`cargo install --locked zuit
zuit analyze .`}</code>
          </pre>
          <p className={styles.quickStartNote}>
            See <Link to="/quickstart">Quickstart</Link> for build-from-source and CI usage.
          </p>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  return (
    <Layout
      title="zuit"
      description="Static code analysis for Rust, Python, and JavaScript/TypeScript with structured, multi-dimensional findings."
    >
      <HomepageHero />
      <main>
        <DimensionsSection />
        <HowTeamsUseSection />
        <PipelineAtAGlance />
        <QuickStartSection />
      </main>
    </Layout>
  );
}
