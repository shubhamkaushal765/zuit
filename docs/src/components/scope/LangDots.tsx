import React from 'react';
import clsx from 'clsx';
import styles from './Scope.module.css';

export interface LangFlags {
  rs?: boolean;
  py?: boolean;
  js?: boolean;
}

export interface LangDotsProps {
  langs: LangFlags;
  size?: 'sm' | 'md';
}

interface DotDef {
  key: keyof LangFlags;
  label: string;
  title: string;
  humanName: string;
}

const DOTS: DotDef[] = [
  { key: 'rs', label: 'Rs', title: 'Rust',                     humanName: 'Rust' },
  { key: 'py', label: 'Py', title: 'Python',                   humanName: 'Python' },
  { key: 'js', label: 'JS', title: 'JavaScript/TypeScript',    humanName: 'JavaScript/TypeScript' },
];

export default function LangDots({ langs, size = 'sm' }: LangDotsProps): React.ReactElement {
  return (
    <div role="group" aria-label="Language coverage" className={styles.langDots}>
      {DOTS.map(({ key, label, title, humanName }) => {
        const supported = Boolean(langs[key]);
        return (
          <span
            key={key}
            data-lang={key}
            data-dim={String(!supported)}
            data-size={size}
            title={title}
            aria-label={`${humanName} ${supported ? 'supported' : 'not supported'}`}
            className={clsx(styles.dot, styles[`dot-${key}`])}
          >
            {label}
          </span>
        );
      })}
    </div>
  );
}
