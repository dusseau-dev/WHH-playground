import { describe, expect, it } from 'vitest';
import {
  assessmentScopeCatalog,
  availableTestScopes,
  availableTestSurfaces,
  deriveTestCategories,
  expandTestCategories,
  getOwaspCategorySelection,
  normalizeTestScopeSelection,
  setOwaspCategorySelected,
} from '../src/security-scopes.js';

describe('CLI security scope catalog', () => {
  it('exposes all OWASP Top 10:2025 parents in order', () => {
    expect(assessmentScopeCatalog.map(({ id }) => id)).toEqual([
      'A01:2025',
      'A02:2025',
      'A03:2025',
      'A04:2025',
      'A05:2025',
      'A06:2025',
      'A07:2025',
      'A08:2025',
      'A09:2025',
      'A10:2025',
    ]);
    expect(
      assessmentScopeCatalog.filter(({ availability }) => availability === 'coming-soon').map(({ id }) => id),
    ).toEqual(['A03:2025', 'A09:2025']);
  });

  it('defaults to available checks and surfaces only', () => {
    expect(availableTestScopes).toContain('csrf');
    expect(availableTestScopes).not.toContain('dependency-risk');
    expect(availableTestSurfaces).toEqual(['browser', 'api-graphql']);
  });

  it('round-trips legacy category expansion through execution-lane derivation', () => {
    const scopes = expandTestCategories(['injection', 'authz']);
    expect(deriveTestCategories(scopes)).toEqual(['injection', 'authz']);
    expect(scopes).toContain('xxe');
    expect(scopes).toContain('csrf');
  });

  it('derives checked, unchecked, and indeterminate OWASP parent states', () => {
    expect(getOwaspCategorySelection([], 'A01:2025')).toEqual({
      checked: false,
      indeterminate: false,
      selectedCount: 0,
      totalCount: 5,
    });
    expect(getOwaspCategorySelection(['csrf'], 'A01:2025')).toEqual({
      checked: false,
      indeterminate: true,
      selectedCount: 1,
      totalCount: 5,
    });
    expect(
      getOwaspCategorySelection(
        ['csrf', 'ssrf', 'object-access', 'tenant-isolation', 'privilege-boundaries'],
        'A01:2025',
      ),
    ).toEqual({
      checked: true,
      indeterminate: false,
      selectedCount: 5,
      totalCount: 5,
    });
  });

  it('selects and clears all available children for an OWASP parent in registry order', () => {
    const selected = setOwaspCategorySelected(['verbose-errors'], 'A01:2025', true);
    expect(selected).toEqual([
      'object-access',
      'privilege-boundaries',
      'tenant-isolation',
      'csrf',
      'ssrf',
      'verbose-errors',
    ]);
    expect(setOwaspCategorySelected(selected, 'A01:2025', false)).toEqual(['verbose-errors']);
    expect(setOwaspCategorySelected(selected, 'A03:2025', true)).toEqual(selected);
  });

  it('rejects unknown granular and legacy identifiers from untyped callers', () => {
    expect(() => normalizeTestScopeSelection({ testScopes: ['unknown-scope' as never] })).toThrow(/unknown/i);
    expect(() => normalizeTestScopeSelection({ testCategories: ['unknown-lane' as never] })).toThrow(/unknown/i);
  });
});
