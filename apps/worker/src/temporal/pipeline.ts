/**
 * Pipeline entry point — re-exports the extracted pipeline function and shared types.
 *
 * Consumers import from this module to call the pipeline as a library function
 * within their own workflow context.
 */

export type { HttpLoadSettings } from '../types/http-load.js';
export type {
  AssessmentScope,
  AssessmentSurface,
  OwaspCategory,
  OwaspCategoryId,
} from '../types/scopes.js';
export type { ActivityInput } from './activities.js';
export { type ProtectedPipelineInput, protectPipelineInput } from './pipeline-secrets.js';
export type {
  AgentMetrics,
  NormalizedPipelineInput,
  PipelineInput,
  PipelineProgress,
  PipelineState,
  PipelineSummary,
  ResumeState,
  SourceMode,
  VulnExploitPipelineResult,
} from './shared.js';
export {
  computeExpectedAgents,
  DEFAULT_URL_ONLY_WORKING_DIRECTORY,
  normalizeCliPipelineInput,
  normalizeSourceContext,
  resolveSafeDemonstrationInput,
} from './shared.js';
export { pentestPipeline } from './workflows.js';
