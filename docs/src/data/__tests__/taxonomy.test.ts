import { describe, it, expect } from 'vitest';
import { TAXONOMY, TAXONOMY_STATS, type RuleFamily } from '../taxonomy';

const KNOWN_FAMILIES: RuleFamily[] = ['MAINT','SEC','CPLX','DOC','TEST','PKG','SOUND','OTHER'];
const ID_RE = /^[A-Z]+\d+-[a-z0-9-]+$/;

describe('taxonomy data', () => {
  it('has 31 rows', () => {
    expect(TAXONOMY).toHaveLength(31);
  });

  it('every id is unique', () => {
    const ids = TAXONOMY.map(r => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every id matches the canonical FAMILY+NUMBER-slug pattern', () => {
    TAXONOMY.forEach(r => expect(r.id).toMatch(ID_RE));
  });

  it('every family is one of the known enum values', () => {
    TAXONOMY.forEach(r => expect(KNOWN_FAMILIES).toContain(r.family));
  });

  it('family literal matches the id prefix', () => {
    TAXONOMY.forEach(r => {
      const prefix = r.id.match(/^[A-Z]+/)![0];
      if (KNOWN_FAMILIES.includes(prefix as RuleFamily)) {
        expect(r.family).toBe(prefix);
      } else {
        expect(r.family).toBe('OTHER');
      }
    });
  });

  it('SEC101 and SOUND003 are Rust-only', () => {
    const rustOnlyIds = ['SEC101-rust-unsafe', 'SOUND003-transmute-usage'];
    rustOnlyIds.forEach(id => {
      const row = TAXONOMY.find(r => r.id === id);
      expect(row).toBeDefined();
      expect(row!.langs).toEqual({ rs: true, py: false, js: false });
    });
  });

  it('every other rule is tri-language', () => {
    const rustOnly = new Set(['SEC101-rust-unsafe', 'SOUND003-transmute-usage']);
    TAXONOMY.filter(r => !rustOnly.has(r.id)).forEach(r => {
      expect(r.langs).toEqual({ rs: true, py: true, js: true });
    });
  });

  it('SEC002 carries two CWEs', () => {
    const sec002 = TAXONOMY.find(r => r.id === 'SEC002-eval-sink');
    expect(sec002?.cwe).toEqual(['CWE-95', 'CWE-79']);
  });

  it('stats derive correctly', () => {
    expect(TAXONOMY_STATS.total).toBe(TAXONOMY.length);
    expect(TAXONOMY_STATS.withCwe).toBe(
      TAXONOMY.filter(r => r.cwe.length > 0).length
    );
    expect(TAXONOMY_STATS.withOwasp).toBe(
      TAXONOMY.filter(r => r.owasp.length > 0).length
    );
    expect(TAXONOMY_STATS.languages).toBe(3);
  });

  it('the expected with-CWE and with-OWASP counts are as documented', () => {
    expect(TAXONOMY_STATS.withCwe).toBe(24);
    expect(TAXONOMY_STATS.withOwasp).toBe(11);
  });
});
