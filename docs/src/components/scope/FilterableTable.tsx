import React, { useState, useMemo, useRef, useEffect, KeyboardEvent } from 'react';
import clsx from 'clsx';
import styles from './Scope.module.css';

export type BadgeTone =
  | 'info' | 'success' | 'warning' | 'danger' | 'neutral' | 'primary';

export interface FilterableTableColumn<R> {
  key: keyof R | string;
  header: string;
  width?: string;
  render?: (row: R) => React.ReactNode;
  searchable?: boolean;
}

export interface FilterOption<R = unknown> {
  value: string;
  label: string;
  predicate?: (row: R) => boolean;
  tone?: BadgeTone;
}

export interface FilterableTableProps<R> {
  columns: FilterableTableColumn<R>[];
  rows: R[];
  filterField: keyof R;
  filterOptions: FilterOption<R>[];
  searchPlaceholder?: string;
  emptyMessage?: string;
  caption?: string;
  initialFilter?: string;
}

export default function FilterableTable<R extends object>(
  props: FilterableTableProps<R>
): React.ReactElement {
  const {
    columns,
    rows,
    filterField,
    filterOptions,
    searchPlaceholder,
    emptyMessage,
    caption,
    initialFilter,
  } = props;

  const defaultFilter = initialFilter ?? filterOptions[0]?.value ?? 'all';
  const [activeFilter, setActiveFilter] = useState<string>(defaultFilter);
  const [searchTerm, setSearchTerm] = useState<string>('');

  const pillRefs = useRef<HTMLButtonElement[]>([]);

  const searchableColKey = useMemo(
    () => columns.find(c => c.searchable)?.key,
    [columns]
  );

  const hasSearch = searchableColKey !== undefined;

  const filteredRows = useMemo(() => {
    const firstValue = filterOptions[0]?.value;
    const isAllFilter = activeFilter === firstValue;
    const activeOption = filterOptions.find(o => o.value === activeFilter);

    return rows.filter(row => {
      // Pill filter
      if (!isAllFilter) {
        if (activeOption?.predicate) {
          if (!activeOption.predicate(row)) return false;
        } else {
          if (row[filterField] !== activeFilter) return false;
        }
      }

      // Search filter
      if (hasSearch && searchTerm.trim() !== '') {
        const cellValue = String(row[searchableColKey as keyof R] ?? '');
        if (!cellValue.toLowerCase().includes(searchTerm.toLowerCase())) {
          return false;
        }
      }

      return true;
    });
  }, [rows, activeFilter, searchTerm, filterOptions, filterField, hasSearch, searchableColKey]);

  function activatePill(index: number) {
    const opt = filterOptions[index];
    if (opt) {
      setActiveFilter(opt.value);
      pillRefs.current[index]?.focus();
    }
  }

  function handlePillKeyDown(e: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = filterOptions.length - 1;
    if (e.key === 'ArrowRight') {
      e.preventDefault();
      activatePill((index + 1) % filterOptions.length);
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      activatePill((index - 1 + filterOptions.length) % filterOptions.length);
    } else if (e.key === 'Home') {
      e.preventDefault();
      activatePill(0);
    } else if (e.key === 'End') {
      e.preventDefault();
      activatePill(last);
    }
  }

  return (
    <div className={styles.tableWrap}>
      <div className={styles.controls} role="radiogroup" aria-label="Filter rows">
        {filterOptions.map((opt, i) => {
          const isActive = opt.value === activeFilter;
          return (
            <button
              key={opt.value}
              role="radio"
              aria-checked={isActive}
              data-active={String(isActive)}
              data-filter-value={opt.value}
              tabIndex={isActive ? 0 : -1}
              className={styles.pill}
              ref={el => { if (el) pillRefs.current[i] = el; }}
              onClick={() => setActiveFilter(opt.value)}
              onKeyDown={e => handlePillKeyDown(e, i)}
            >
              {opt.label}
            </button>
          );
        })}
        {hasSearch && (
          <input
            type="search"
            role="searchbox"
            aria-label="Search"
            placeholder={searchPlaceholder ?? 'Search...'}
            className={styles.searchInput}
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
          />
        )}
      </div>
      <table className={styles.scopeTable} role="table">
        {caption && <caption>{caption}</caption>}
        <thead>
          <tr>
            {columns.map(col => (
              <th key={String(col.key)} style={col.width ? { width: col.width } : undefined}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filteredRows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                role="status"
                data-empty="true"
                className={styles.emptyCell}
              >
                {emptyMessage ?? 'No matches'}
              </td>
            </tr>
          ) : (
            filteredRows.map((row, ri) => (
              <tr key={ri}>
                {columns.map(col => (
                  <td key={String(col.key)}>
                    {col.render
                      ? col.render(row)
                      : String(row[col.key as keyof R] ?? '')}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
