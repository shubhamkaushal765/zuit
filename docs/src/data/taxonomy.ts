export type RuleFamily =
  | 'MAINT' | 'SEC' | 'CPLX' | 'DOC' | 'TEST' | 'PKG' | 'SOUND' | 'OTHER';

export interface TaxonomyRow {
  id: string;
  name: string;
  family: RuleFamily;
  cwe: string[];
  owasp: string[];
  langs: { rs: boolean; py: boolean; js: boolean };
}

export const TAXONOMY: TaxonomyRow[] = [
  // MAINT rules
  {
    id: 'MAINT001-cyclomatic',
    name: 'Cyclomatic complexity',
    family: 'MAINT',
    cwe: ['CWE-1121'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'MAINT002-cognitive',
    name: 'Cognitive complexity',
    family: 'MAINT',
    cwe: ['CWE-1121'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'MAINT003-fn-length',
    name: 'Function length',
    family: 'MAINT',
    cwe: ['CWE-1121'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'MAINT004-file-length',
    name: 'File length',
    family: 'MAINT',
    cwe: ['CWE-1080'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'MAINT005-deep-nesting',
    name: 'Deeply nested control flow',
    family: 'MAINT',
    cwe: ['CWE-1124'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'MAINT006-too-many-params',
    name: 'Too many parameters',
    family: 'MAINT',
    cwe: ['CWE-1121'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  // DOC rules
  {
    id: 'DOC001-public-api-undoc',
    name: 'Undocumented public API',
    family: 'DOC',
    cwe: ['CWE-1059'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'DOC002-todo-fixme',
    name: 'TODO/FIXME comment',
    family: 'DOC',
    cwe: ['CWE-546'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'DOC004-stale-doc',
    name: 'Stale doc comment',
    family: 'DOC',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  // SEC rules
  {
    id: 'SEC001-hardcoded-secret',
    name: 'Hardcoded secret',
    family: 'SEC',
    cwe: ['CWE-798'],
    owasp: ['A07:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC002-eval-sink',
    name: 'Dynamic eval sink',
    family: 'SEC',
    cwe: ['CWE-95', 'CWE-79'],
    owasp: ['A03:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC003-shell-injection',
    name: 'Shell injection',
    family: 'SEC',
    cwe: ['CWE-78'],
    owasp: ['A03:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC004-weak-crypto',
    name: 'Weak crypto primitive',
    family: 'SEC',
    cwe: ['CWE-327'],
    owasp: ['A02:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC005-insecure-deser',
    name: 'Insecure deserialization',
    family: 'SEC',
    cwe: ['CWE-502'],
    owasp: ['A08:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC006-sql-injection',
    name: 'SQL injection',
    family: 'SEC',
    cwe: ['CWE-89'],
    owasp: ['A03:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC007-path-traversal',
    name: 'Path traversal',
    family: 'SEC',
    cwe: ['CWE-22'],
    owasp: ['A01:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC008-csrf-missing',
    name: 'Missing CSRF protection',
    family: 'SEC',
    cwe: ['CWE-352'],
    owasp: ['A01:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC009-open-redirect',
    name: 'Open redirect',
    family: 'SEC',
    cwe: ['CWE-601'],
    owasp: ['A01:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC010-ssrf',
    name: 'Server-side request forgery',
    family: 'SEC',
    cwe: ['CWE-918'],
    owasp: ['A10:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC011-cors-permissive',
    name: 'Permissive CORS',
    family: 'SEC',
    cwe: ['CWE-942'],
    owasp: ['A05:2021'],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'SEC101-rust-unsafe',
    name: 'Use of `unsafe` (Rust)',
    family: 'SEC',
    cwe: ['CWE-758'],
    owasp: [],
    langs: { rs: true, py: false, js: false },
  },
  // CPLX rules
  {
    id: 'CPLX001-fan-out',
    name: 'High fan-out',
    family: 'CPLX',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'CPLX002-cyclic-deps',
    name: 'Cyclic module dependencies',
    family: 'CPLX',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  // PKG rules
  {
    id: 'PKG001-install-script-present',
    name: 'Install script present',
    family: 'PKG',
    cwe: ['CWE-506'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  // SOUND rules
  {
    id: 'SOUND003-transmute-usage',
    name: '`transmute` usage',
    family: 'SOUND',
    cwe: ['CWE-704'],
    owasp: [],
    langs: { rs: true, py: false, js: false },
  },
  // TEST rules
  {
    id: 'TEST001-test-ratio',
    name: 'Low test-to-code ratio',
    family: 'TEST',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'TEST002-no-asserts',
    name: 'Test without assertions',
    family: 'TEST',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'TEST003-skipped',
    name: 'Skipped test',
    family: 'TEST',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'TEST004-flaky-time',
    name: 'Time-based flakiness',
    family: 'TEST',
    cwe: ['CWE-362'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'TEST005-assert-count',
    name: 'Excessive assertions in test',
    family: 'TEST',
    cwe: [],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
  {
    id: 'TEST006-shared-mutable-state',
    name: 'Shared mutable test state',
    family: 'TEST',
    cwe: ['CWE-820'],
    owasp: [],
    langs: { rs: true, py: true, js: true },
  },
];

export interface TaxonomyStats {
  total: number;
  withCwe: number;
  withOwasp: number;
  languages: number;
}

export const TAXONOMY_STATS: TaxonomyStats = {
  total: TAXONOMY.length,
  withCwe: TAXONOMY.filter(r => r.cwe.length > 0).length,
  withOwasp: TAXONOMY.filter(r => r.owasp.length > 0).length,
  languages: 3,
};
