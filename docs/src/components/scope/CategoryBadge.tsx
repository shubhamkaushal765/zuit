import React from 'react';
import clsx from 'clsx';
import styles from './Scope.module.css';

export type BadgeTone =
  | 'info' | 'success' | 'warning' | 'danger' | 'neutral' | 'primary';

export interface CategoryBadgeProps {
  label: string;
  tone?: BadgeTone;       // default 'neutral'
  size?: 'sm' | 'md';     // default 'sm'
  monospace?: boolean;    // default false
  className?: string;     // forwarded as extra class on the span
}

export default function CategoryBadge({
  label,
  tone = 'neutral',
  size = 'sm',
  monospace = false,
  className,
}: CategoryBadgeProps): React.ReactElement {
  return (
    <span
      className={clsx(
        styles.badge,
        styles[`tone-${tone}`],
        styles[`size-${size}`],
        monospace && styles.monospace,
        className,
      )}
      data-tone={tone}
      data-size={size}
      data-monospace={String(monospace)}
    >
      {label}
    </span>
  );
}
