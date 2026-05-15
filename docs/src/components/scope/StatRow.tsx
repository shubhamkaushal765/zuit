import React from 'react';
import styles from './Scope.module.css';

export type StatAccent = 'info' | 'success' | 'warning' | 'neutral' | 'primary';

export interface Stat {
  value: string | number;
  label: string;
  accent?: StatAccent;
  hint?: string;
}

export interface StatRowProps {
  stats: Stat[];
  ariaLabel?: string;
}

export default function StatRow({ stats, ariaLabel }: StatRowProps): React.ReactElement {
  return (
    <ul role="list" aria-label={ariaLabel ?? 'Summary statistics'} className={styles.statRow}>
      {stats.map((stat, i) => {
        const liProps: React.LiHTMLAttributes<HTMLLIElement> & { 'data-accent': string } = {
          className: styles.statCard,
          'data-accent': stat.accent ?? 'neutral',
        };
        if (stat.hint !== undefined) {
          liProps.title = stat.hint;
        }
        return (
          <li key={i} {...liProps}>
            <span className={styles.statValue}>{stat.value}</span>
            <span className={styles.statLabel}>{stat.label}</span>
          </li>
        );
      })}
    </ul>
  );
}
