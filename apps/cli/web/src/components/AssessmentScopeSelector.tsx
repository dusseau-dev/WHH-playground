import { Braces, Check, ChevronDown, ChevronRight, Minus, Monitor, RadioTower } from 'lucide-react';
import { useState } from 'react';
import {
  assessmentScopeCatalog,
  assessmentScopeDefinitions,
  availableTestScopes,
  getOwaspCategorySelection,
  setOwaspCategorySelected,
  selectableTestScopes,
  testSurfaceDefinitions,
  type AssessmentTestScope,
  type AssessmentTestSurface,
  type OwaspCategory,
} from '../types/api';
import { FieldError, IconButton } from './Primitives';

interface AssessmentScopeSelectorProps {
  selectedScopes: AssessmentTestScope[];
  selectedSurfaces: AssessmentTestSurface[];
  onScopesChange: (scopes: AssessmentTestScope[]) => void;
  onSurfacesChange: (surfaces: AssessmentTestSurface[]) => void;
  scopeError?: string | undefined;
  surfaceError?: string | undefined;
}

const availabilityLabels = {
  available: 'Available',
  partial: 'Partial',
  'coming-soon': 'Coming soon',
} as const;

const surfaceIcons = {
  browser: Monitor,
  'api-graphql': Braces,
  websockets: RadioTower,
} as const;

/** Render synchronized OWASP parent controls and granular assessment checks. */
export function AssessmentScopeSelector({
  selectedScopes,
  selectedSurfaces,
  onScopesChange,
  onSurfacesChange,
  scopeError,
  surfaceError,
}: AssessmentScopeSelectorProps) {
  const [expandedCategories, setExpandedCategories] = useState<Set<OwaspCategory>>(new Set(['A01:2025']));

  const toggleCategoryExpansion = (category: OwaspCategory) => {
    setExpandedCategories((current) => {
      const next = new Set(current);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  };

  const toggleScope = (scope: AssessmentTestScope, selected: boolean) => {
    const next = new Set(selectedScopes);
    if (selected) next.add(scope);
    else next.delete(scope);
    onScopesChange(assessmentScopeDefinitions.filter(({ id }) => next.has(id)).map(({ id }) => id));
  };

  const toggleSurface = (surface: AssessmentTestSurface, selected: boolean) => {
    const next = new Set(selectedSurfaces);
    if (selected) next.add(surface);
    else next.delete(surface);
    onSurfacesChange(testSurfaceDefinitions.filter(({ id }) => next.has(id)).map(({ id }) => id));
  };

  return (
    <>
      <fieldset className="field field--wide scope-fieldset">
        <legend className="field-label">OWASP Top 10:2025 checks</legend>
        <div className="scope-toolbar">
          <span aria-live="polite">
            {selectedScopes.length} of {selectableTestScopes.length} selected
          </span>
          <div className="scope-toolbar-actions">
            <button type="button" className="scope-action" onClick={() => onScopesChange([...availableTestScopes])}>
              Select all standard checks
            </button>
            <button type="button" className="scope-action" onClick={() => onScopesChange([])}>
              Clear all checks
            </button>
          </div>
        </div>
        <div className="owasp-scope-list">
          {assessmentScopeCatalog.map((category) => {
            const categoryId = category.id as OwaspCategory;
            const children = assessmentScopeDefinitions.filter(({ owaspId }) => owaspId === category.id);
            const selection = getOwaspCategorySelection(selectedScopes, categoryId);
            const expanded = expandedCategories.has(categoryId);
            const unavailable = category.availability === 'coming-soon';
            const label = `${category.id} ${category.title}`;
            const panelId = `owasp-${category.id.slice(1, 3)}-checks`;
            return (
              <div className={`owasp-scope-row owasp-scope-row--${category.availability}`} key={category.id}>
                <div className="owasp-parent-row">
                  <label className={`owasp-parent-check${selection.indeterminate ? ' is-indeterminate' : ''}`}>
                    <input
                      type="checkbox"
                      aria-label={label}
                      checked={selection.checked}
                      disabled={unavailable}
                      ref={(element) => {
                        if (element) element.indeterminate = selection.indeterminate;
                      }}
                      onChange={(event) =>
                        onScopesChange(setOwaspCategorySelected(selectedScopes, categoryId, event.target.checked))
                      }
                    />
                    <span className="scope-checkbox" aria-hidden="true">
                      {selection.indeterminate ? <Minus size={14} /> : selection.checked ? <Check size={14} /> : null}
                    </span>
                    <span className="owasp-parent-copy">
                      <span className="owasp-code">{category.id}</span>
                      <strong>{category.title}</strong>
                    </span>
                  </label>
                  <span className={`scope-availability scope-availability--${category.availability}`}>
                    {availabilityLabels[category.availability]}
                  </span>
                  <span className="scope-count">
                    {unavailable ? `${children.length} planned` : `${selection.selectedCount}/${selection.totalCount}`}
                  </span>
                  <IconButton
                    type="button"
                    className="owasp-expand"
                    label={`${expanded ? 'Collapse' : 'Expand'} ${label}`}
                    icon={expanded ? ChevronDown : ChevronRight}
                    aria-expanded={expanded}
                    aria-controls={panelId}
                    onClick={() => toggleCategoryExpansion(categoryId)}
                  />
                </div>
                {expanded ? (
                  <div className="granular-scope-grid" id={panelId}>
                    {children.map((scope) => {
                      const scopeUnavailable = scope.availability === 'coming-soon';
                      const checked = selectedScopes.includes(scope.id);
                      return (
                        <label className="granular-scope-check" key={scope.id}>
                          <input
                            type="checkbox"
                            checked={checked}
                            disabled={scopeUnavailable}
                            onChange={(event) => toggleScope(scope.id, event.target.checked)}
                          />
                          <span className="scope-checkbox" aria-hidden="true">
                            {checked ? <Check size={13} /> : null}
                          </span>
                          <span>{scope.label}</span>
                          {scopeUnavailable ? (
                            <small>Coming soon</small>
                          ) : scope.bulkSelectable === false ? (
                            <small>Explicit opt-in</small>
                          ) : null}
                        </label>
                      );
                    })}
                  </div>
                ) : null}
              </div>
            );
          })}
        </div>
        <FieldError message={scopeError} />
      </fieldset>

      <fieldset className="field field--wide surface-fieldset">
        <legend className="field-label">Assessment surfaces</legend>
        <div className="surface-selector">
          {testSurfaceDefinitions.map((surface) => {
            const Icon = surfaceIcons[surface.id];
            const unavailable = surface.availability === 'coming-soon';
            const checked = selectedSurfaces.includes(surface.id);
            return (
              <label className="surface-option" key={surface.id}>
                <input
                  type="checkbox"
                  checked={checked}
                  disabled={unavailable}
                  onChange={(event) => toggleSurface(surface.id, event.target.checked)}
                />
                <Icon size={18} aria-hidden="true" />
                <span>{surface.label}</span>
                {unavailable ? <small>Coming soon</small> : <span className="scope-checkbox" aria-hidden="true">{checked ? <Check size={13} /> : null}</span>}
              </label>
            );
          })}
        </div>
        <FieldError message={surfaceError} />
      </fieldset>
    </>
  );
}
