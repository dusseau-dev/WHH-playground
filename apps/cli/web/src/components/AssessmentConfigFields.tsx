import { AlertTriangle, ChevronDown, Eye, EyeOff, KeyRound, Minus, Plus, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
import { AssessmentScopeSelector } from "./AssessmentScopeSelector";
import { FieldError, IconButton, InlineNotice } from "./Primitives";
import {
  assessmentScopeDefinitions,
  assessmentModuleDefinitions,
  assessmentModuleIds,
  assessmentTestScopeIds,
  assessmentTestSurfaceIds,
  availableTestScopes,
  availableTestSurfaces,
  defaultAssessmentModules,
  HTTP_LOAD_DEFAULTS,
  HTTP_LOAD_ELEVATED_THRESHOLDS,
  HTTP_LOAD_EMERGENCY_LIMITS,
  selectableTestScopes,
  type AssessmentModule,
  type ConfiguredModelDescription,
  type ModelCatalogItem,
  severities,
  testSurfaceDefinitions,
  type AssessmentTestScope,
  type AssessmentTestSurface,
  type SecretState,
} from "../types/api";

const isHttpUrl = (value: string) => {
  if (!URL.canParse(value)) return false;
  return ["http:", "https:"].includes(new URL(value).protocol);
};
const optionalUrl = z.string().trim().refine((value) => !value || isHttpUrl(value), "Enter an HTTP(S) URL");
const modelSources = ["environment", "openrouter", "anthropic", "openai", "xai", "custom"] as const;
const visibleAssessmentModuleDefinitions = assessmentModuleDefinitions;

export const assessmentFormSchema = z
  .object({
    name: z.string().trim(),
    targetUrl: z.string().trim().refine(isHttpUrl, "Enter an HTTP(S) target URL"),
    sourceMode: z.enum(["source-assisted", "url-only"]),
    repoPath: z.string().trim(),
    modelSource: z.enum(modelSources),
    modelId: z.string().trim(),
    providerApiKey: z.string(),
    customProviderId: z.string().trim(),
    customBaseUrl: optionalUrl,
    customOpenAIFormat: z.enum(["chat-completions", "responses"]),
    testScopes: z.record(z.enum(assessmentTestScopeIds), z.boolean()),
    testSurfaces: z.record(z.enum(assessmentTestSurfaceIds), z.boolean()),
    assessmentModules: z.record(z.enum(assessmentModuleIds), z.boolean()),
    targetEnvironment: z.enum(["production", "staging"]),
    allowActiveDast: z.boolean(),
    acknowledgeLoadRisk: z.boolean(),
    moduleMaxRequestsPerSecond: z.number().int().min(1).max(10),
    moduleMaxConcurrency: z.number().int().min(1).max(25),
    loadStageDurationSeconds: z.number().int().min(10).max(600),
    loadErrorRateThreshold: z.number().min(0.001).max(0.5),
    loadP95LatencyMsThreshold: z.number().int().min(100).max(60000),
    httpLoadConcurrency: z.number().int().min(1).max(HTTP_LOAD_EMERGENCY_LIMITS.concurrency),
    httpLoadRequestsPerSecond: z.number().int().min(1).max(HTTP_LOAD_EMERGENCY_LIMITS.requestsPerSecond),
    httpLoadDurationSeconds: z.number().int().min(1).max(HTTP_LOAD_EMERGENCY_LIMITS.durationSeconds),
    elevatedLoadConfirmed: z.boolean(),
    safeDemonstration: z.boolean(),
    concurrency: z.number().int().min(1).max(5),
    authenticationEnabled: z.boolean(),
    loginType: z.enum(["form", "sso", "api", "basic"]),
    loginUrl: optionalUrl,
    username: z.string().trim(),
    email: z.string().trim().refine((value) => !value || z.string().email().safeParse(value).success, "Enter a valid email"),
    password: z.string(),
    totpSecret: z.string(),
    loginFlow: z.string(),
    successConditionType: z.enum(["url_contains", "element_present", "url_equals_exactly", "text_contains"]),
    successConditionValue: z.string().trim(),
    clearPassword: z.boolean(),
    clearTotp: z.boolean(),
    focusRules: z.string(),
    avoidRules: z.string(),
    rulesOfEngagement: z.string(),
    minSeverity: z.union([z.enum(severities), z.literal("")]),
    minConfidence: z.union([z.enum(["low", "medium", "high"]), z.literal("")]),
    reportGuidance: z.string(),
    sarif: z.boolean(),
    saveProfile: z.boolean(),
    profileName: z.string().trim(),
    authorizedTesting: z.boolean(),
  })
  .superRefine((value, context) => {
    if (value.sourceMode === "source-assisted" && !value.repoPath) {
      context.addIssue({ code: "custom", path: ["repoPath"], message: "Repository path is required" });
    }
    if (value.modelSource !== "environment") {
      if (!value.modelId) context.addIssue({ code: "custom", path: ["modelId"], message: "Model ID is required" });
      if (!value.providerApiKey) {
        context.addIssue({ code: "custom", path: ["providerApiKey"], message: "Provider API key is required" });
      }
    }
    if (value.modelSource === "custom") {
      if (!value.customProviderId) {
        context.addIssue({ code: "custom", path: ["customProviderId"], message: "Provider ID is required" });
      }
      if (!value.customBaseUrl) {
        context.addIssue({ code: "custom", path: ["customBaseUrl"], message: "Base URL is required" });
      }
    }
    if (!selectableTestScopes.some((scope) => value.testScopes[scope])) {
      context.addIssue({ code: "custom", path: ["testScopes"], message: "Select at least one available check" });
    }
    if (!availableTestSurfaces.some((surface) => value.testSurfaces[surface])) {
      context.addIssue({ code: "custom", path: ["testSurfaces"], message: "Select at least one available surface" });
    }
    if (value.assessmentModules["supply-chain"] && value.sourceMode !== "source-assisted") {
      context.addIssue({ code: "custom", path: ["assessmentModules"], message: "Supply-chain review requires source-assisted mode" });
    }
    if (value.allowActiveDast && value.targetEnvironment !== "staging") {
      context.addIssue({ code: "custom", path: ["allowActiveDast"], message: "Active DAST is staging-only" });
    }
    if (value.assessmentModules["http-load-capacity"]) {
      if (value.testScopes["http-load-capacity"]) {
        context.addIssue({
          code: "custom",
          path: ["assessmentModules"],
          message: "Choose either the HTTP load scope or the controlled-load module, not both",
        });
      }
      if (value.targetEnvironment !== "staging") {
        context.addIssue({ code: "custom", path: ["targetEnvironment"], message: "Controlled load testing is staging-only" });
      }
      if (!value.acknowledgeLoadRisk) {
        context.addIssue({
          code: "custom",
          path: ["acknowledgeLoadRisk"],
          message: "Acknowledge the staging load-test risk before continuing",
        });
      }
    }
    if (
      value.testScopes["http-load-capacity"] &&
      (value.httpLoadConcurrency > HTTP_LOAD_ELEVATED_THRESHOLDS.concurrency ||
        value.httpLoadRequestsPerSecond > HTTP_LOAD_ELEVATED_THRESHOLDS.requestsPerSecond ||
        value.httpLoadDurationSeconds > HTTP_LOAD_ELEVATED_THRESHOLDS.durationSeconds) &&
      !value.elevatedLoadConfirmed
    ) {
      context.addIssue({
        code: "custom",
        path: ["elevatedLoadConfirmed"],
        message: "Confirm the elevated load envelope before continuing",
      });
    }
    if (value.authenticationEnabled) {
      if (!value.loginUrl) context.addIssue({ code: "custom", path: ["loginUrl"], message: "Login URL is required" });
      if (!value.username) context.addIssue({ code: "custom", path: ["username"], message: "Username is required" });
      if (!value.successConditionValue) {
        context.addIssue({ code: "custom", path: ["successConditionValue"], message: "Success condition is required" });
      }
    }
    if (value.saveProfile && !value.profileName) {
      context.addIssue({ code: "custom", path: ["profileName"], message: "Profile name is required" });
    }
  });

export type AssessmentFormValues = z.infer<typeof assessmentFormSchema>;

function selectionRecord<T extends string>(all: readonly T[], selected: readonly T[]): Record<T, boolean> {
  const selectedSet = new Set(selected);
  return Object.fromEntries(all.map((value) => [value, selectedSet.has(value)])) as Record<T, boolean>;
}

export const assessmentDefaults: AssessmentFormValues = {
  name: "",
  targetUrl: "",
  sourceMode: "url-only",
  repoPath: "",
  modelSource: "environment",
  modelId: "",
  providerApiKey: "",
  customProviderId: "",
  customBaseUrl: "",
  customOpenAIFormat: "chat-completions",
  testScopes: selectionRecord(
    assessmentScopeDefinitions.map(({ id }) => id),
    availableTestScopes,
  ),
  testSurfaces: selectionRecord(
    testSurfaceDefinitions.map(({ id }) => id),
    availableTestSurfaces,
  ),
  assessmentModules: selectionRecord(
    assessmentModuleDefinitions.map(({ id }) => id),
    defaultAssessmentModules,
  ),
  targetEnvironment: "production",
  allowActiveDast: false,
  acknowledgeLoadRisk: false,
  moduleMaxRequestsPerSecond: 2,
  moduleMaxConcurrency: 2,
  loadStageDurationSeconds: 60,
  loadErrorRateThreshold: 0.05,
  loadP95LatencyMsThreshold: 2000,
  httpLoadConcurrency: HTTP_LOAD_DEFAULTS.concurrency,
  httpLoadRequestsPerSecond: HTTP_LOAD_DEFAULTS.requestsPerSecond,
  httpLoadDurationSeconds: HTTP_LOAD_DEFAULTS.durationSeconds,
  elevatedLoadConfirmed: false,
  safeDemonstration: true,
  concurrency: 3,
  authenticationEnabled: false,
  loginType: "form",
  loginUrl: "",
  username: "",
  email: "",
  password: "",
  totpSecret: "",
  loginFlow: "",
  successConditionType: "url_contains",
  successConditionValue: "",
  clearPassword: false,
  clearTotp: false,
  focusRules: "",
  avoidRules: "",
  rulesOfEngagement: "",
  minSeverity: "low",
  minConfidence: "medium",
  reportGuidance: "",
  sarif: false,
  saveProfile: false,
  profileName: "",
  authorizedTesting: false,
};

interface Props {
  form: UseFormReturn<AssessmentFormValues>;
  showProfileName?: boolean;
  showSaveProfile?: boolean;
  showAuthorization?: boolean;
  showModelConfig?: boolean;
  modelConfiguration?: ConfiguredModelDescription | undefined;
  modelOptions?: readonly ModelCatalogItem[] | undefined;
  modelCatalogLoading?: boolean;
  modelCatalogUnavailable?: boolean;
  passwordState?: SecretState | undefined;
  totpState?: SecretState | undefined;
}

export function AssessmentConfigFields({
  form,
  showProfileName = false,
  showSaveProfile = false,
  showAuthorization = false,
  showModelConfig = false,
  modelConfiguration,
  modelOptions = [],
  modelCatalogLoading = false,
  modelCatalogUnavailable = false,
  passwordState,
  totpState,
}: Props) {
  const [showPassword, setShowPassword] = useState(false);
  const [showTotp, setShowTotp] = useState(false);
  const [showProviderApiKey, setShowProviderApiKey] = useState(false);
  const { register, watch, setValue, getValues, formState } = form;
  const mode = watch("sourceMode");
  const modelSource = watch("modelSource");
  const authEnabled = watch("authenticationEnabled");
  const saveProfile = watch("saveProfile");
  const concurrency = watch("concurrency");
  const scopeValues = watch("testScopes");
  const surfaceValues = watch("testSurfaces");
  const moduleValues = watch("assessmentModules");
  const targetEnvironment = watch("targetEnvironment");
  const activeDast = watch("allowActiveDast");
  const httpLoadConcurrency = watch("httpLoadConcurrency");
  const httpLoadRequestsPerSecond = watch("httpLoadRequestsPerSecond");
  const httpLoadDurationSeconds = watch("httpLoadDurationSeconds");
  const selectedScopes: AssessmentTestScope[] = [];
  for (const { id } of assessmentScopeDefinitions) {
    if (scopeValues[id]) selectedScopes.push(id);
  }
  const httpLoadSelected = selectedScopes.includes("http-load-capacity");
  const elevatedHttpLoad =
    httpLoadConcurrency > HTTP_LOAD_ELEVATED_THRESHOLDS.concurrency ||
    httpLoadRequestsPerSecond > HTTP_LOAD_ELEVATED_THRESHOLDS.requestsPerSecond ||
    httpLoadDurationSeconds > HTTP_LOAD_ELEVATED_THRESHOLDS.durationSeconds;
  const selectedSurfaces: AssessmentTestSurface[] = [];
  for (const { id } of testSurfaceDefinitions) {
    if (surfaceValues[id]) selectedSurfaces.push(id);
  }
  const selectedModules: AssessmentModule[] = [];
  for (const { id } of assessmentModuleDefinitions) {
    if (moduleValues[id]) selectedModules.push(id);
  }
  const indexOffset = showProfileName ? 1 : 0;
  const sectionIndex = (index: number) => String(index + indexOffset).padStart(2, "0");
  const scopeSectionIndex = sectionIndex(showModelConfig ? 3 : 2);
  const accessSectionIndex = sectionIndex(showModelConfig ? 4 : 3);

  const stepConcurrency = (direction: number) => {
    const next = Math.min(5, Math.max(1, getValues("concurrency") + direction));
    setValue("concurrency", next, { shouldDirty: true, shouldValidate: true });
  };

  return (
    <div className="config-stack">
      {showProfileName ? (
        <section className="form-section" aria-labelledby="profile-identity-heading">
          <div className="section-heading">
            <span className="section-index">01</span>
            <h2 id="profile-identity-heading">Profile identity</h2>
          </div>
          <label className="field field--wide">
            <span className="field-label">Profile name</span>
            <input autoComplete="off" {...register("name")} aria-invalid={Boolean(formState.errors.name)} />
            <FieldError message={formState.errors.name?.message} />
          </label>
        </section>
      ) : null}

      <section className="form-section" aria-labelledby="target-heading">
        <div className="section-heading">
          <span className="section-index">{showProfileName ? "02" : "01"}</span>
          <h2 id="target-heading">Target</h2>
        </div>
        <div className="form-grid form-grid--target">
          <label className="field field--wide">
            <span className="field-label">Target URL</span>
            <input
              type="url"
              inputMode="url"
              placeholder="https://app.example.com"
              autoComplete="url"
              {...register("targetUrl")}
              aria-invalid={Boolean(formState.errors.targetUrl)}
            />
            <FieldError message={formState.errors.targetUrl?.message} />
          </label>
          <fieldset className="field field--wide">
            <legend className="field-label">Source mode</legend>
            <div className="segmented-control">
              <label>
                <input type="radio" value="url-only" {...register("sourceMode")} />
                <span>URL only</span>
              </label>
              <label>
                <input type="radio" value="source-assisted" {...register("sourceMode")} />
                <span>Source assisted</span>
              </label>
            </div>
          </fieldset>
          {mode === "source-assisted" ? (
            <label className="field field--wide field-reveal">
              <span className="field-label">Repository path</span>
              <input
                placeholder="/Users/name/projects/application"
                autoComplete="off"
                {...register("repoPath")}
                aria-invalid={Boolean(formState.errors.repoPath)}
              />
              <FieldError message={formState.errors.repoPath?.message} />
            </label>
          ) : (
            <InlineNotice tone="warning">
              URL-only mode uses browser and API observations; code-level coverage and source-location attribution will
              be unavailable.
            </InlineNotice>
          )}
        </div>
      </section>

      {showModelConfig ? (
        <section className="form-section" aria-labelledby="model-heading">
          <div className="section-heading">
            <span className="section-index">{sectionIndex(2)}</span>
            <h2 id="model-heading">Model</h2>
          </div>
          <div className="form-grid">
            <label className="field">
              <span className="field-label">Model source</span>
              <select {...register("modelSource")}>
                <option value="environment">
                  {modelConfiguration ? `${modelConfiguration.providerLabel} (configured)` : "Environment default"}
                </option>
                <optgroup label="Per-run override">
                  <option value="openrouter">OpenRouter</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="openai">OpenAI</option>
                  <option value="xai">xAI</option>
                  <option value="custom">Custom gateway</option>
                </optgroup>
              </select>
            </label>
            {modelSource === "environment" ? (
              <>
                <label className="field">
                  <span className="field-label">Model</span>
                  <span className="model-combobox">
                    <input
                      list={modelOptions.length > 0 ? "configured-model-options" : undefined}
                      placeholder={
                        modelCatalogLoading ? "Loading model catalog..." : (modelConfiguration?.modelId ?? "Runner default")
                      }
                      autoComplete="off"
                      {...register("modelId")}
                    />
                    {modelOptions.length > 0 ? <ChevronDown size={18} aria-hidden="true" /> : null}
                  </span>
                  {modelOptions.length > 0 ? (
                    <datalist id="configured-model-options">
                      {modelOptions.map((model) => (
                        <option value={model.id} key={model.id}>
                          {model.name}
                        </option>
                      ))}
                    </datalist>
                  ) : null}
                </label>
                <div className="field--wide">
                  <InlineNotice
                    tone={modelConfiguration?.credentialConfigured ? "success" : "warning"}
                    icon={<KeyRound size={17} aria-hidden="true" />}
                  >
                    {!modelConfiguration?.credentialConfigured
                      ? `${modelConfiguration?.providerLabel ?? "Provider"} credential is not configured on this runner.`
                      : modelCatalogUnavailable
                        ? `${modelConfiguration.providerLabel} credential is configured; its model catalog is unavailable.`
                        : `${modelConfiguration.providerLabel} credential is configured on this runner.`}
                  </InlineNotice>
                </div>
              </>
            ) : (
              <>
                <label className="field">
                  <span className="field-label">Model ID</span>
                  <input
                    placeholder={modelSource === "openrouter" ? "~anthropic/claude-sonnet-latest" : "provider-model-id"}
                    autoComplete="off"
                    {...register("modelId")}
                    aria-invalid={Boolean(formState.errors.modelId)}
                  />
                  <FieldError message={formState.errors.modelId?.message} />
                </label>
                <div className="field">
                  <label className="field-label" htmlFor="provider-api-key">
                    Provider API key
                  </label>
                  <span className="secret-input">
                    <input
                      id="provider-api-key"
                      type={showProviderApiKey ? "text" : "password"}
                      autoComplete="off"
                      placeholder={modelSource === "openrouter" ? "sk-or-..." : "API key"}
                      {...register("providerApiKey")}
                      aria-invalid={Boolean(formState.errors.providerApiKey)}
                    />
                    <IconButton
                      type="button"
                      label={showProviderApiKey ? "Hide provider key" : "Show provider key"}
                      icon={showProviderApiKey ? EyeOff : Eye}
                      onClick={() => setShowProviderApiKey((value) => !value)}
                    />
                  </span>
                  <FieldError message={formState.errors.providerApiKey?.message} />
                </div>
                {modelSource === "custom" ? (
                  <>
                    <label className="field">
                      <span className="field-label">Provider ID</span>
                      <input
                        placeholder="gateway"
                        autoComplete="off"
                        {...register("customProviderId")}
                        aria-invalid={Boolean(formState.errors.customProviderId)}
                      />
                      <FieldError message={formState.errors.customProviderId?.message} />
                    </label>
                    <label className="field">
                      <span className="field-label">Base URL</span>
                      <input
                        type="url"
                        placeholder="https://gateway.example.com/v1"
                        {...register("customBaseUrl")}
                        aria-invalid={Boolean(formState.errors.customBaseUrl)}
                      />
                      <FieldError message={formState.errors.customBaseUrl?.message} />
                    </label>
                    <label className="field">
                      <span className="field-label">API format</span>
                      <select {...register("customOpenAIFormat")}>
                        <option value="chat-completions">OpenAI chat completions</option>
                        <option value="responses">OpenAI responses</option>
                      </select>
                    </label>
                  </>
                ) : null}
              </>
            )}
          </div>
        </section>
      ) : null}

      <section className="form-section" aria-labelledby="scope-heading">
        <div className="section-heading">
          <span className="section-index">{scopeSectionIndex}</span>
          <h2 id="scope-heading">Assessment scope</h2>
        </div>
        <AssessmentScopeSelector
          selectedScopes={selectedScopes}
          selectedSurfaces={selectedSurfaces}
          onScopesChange={(scopes) =>
            setValue(
              "testScopes",
              selectionRecord<AssessmentTestScope>(
                assessmentScopeDefinitions.map(({ id }) => id),
                scopes,
              ),
              { shouldDirty: true, shouldValidate: true },
            )
          }
          onSurfacesChange={(surfaces) =>
            setValue(
              "testSurfaces",
              selectionRecord<AssessmentTestSurface>(
                testSurfaceDefinitions.map(({ id }) => id),
                surfaces,
              ),
              { shouldDirty: true, shouldValidate: true },
            )
          }
          scopeError={formState.errors.testScopes?.root?.message}
          surfaceError={formState.errors.testSurfaces?.root?.message}
        />
        {httpLoadSelected ? (
          <fieldset className="http-load-panel field--wide">
            <legend>HTTP load and capacity</legend>
            <div className="http-load-heading">
              <AlertTriangle size={18} aria-hidden="true" />
              <span>Authorized single-host GET traffic</span>
            </div>
            <div className="http-load-fields">
              <label className="field">
                <span className="field-label">Concurrent connections</span>
                <input
                  type="number"
                  min={1}
                  max={HTTP_LOAD_EMERGENCY_LIMITS.concurrency}
                  {...register("httpLoadConcurrency", { valueAsNumber: true })}
                  aria-invalid={Boolean(formState.errors.httpLoadConcurrency)}
                />
                <FieldError message={formState.errors.httpLoadConcurrency?.message} />
              </label>
              <label className="field">
                <span className="field-label">Requests per second</span>
                <input
                  type="number"
                  min={1}
                  max={HTTP_LOAD_EMERGENCY_LIMITS.requestsPerSecond}
                  {...register("httpLoadRequestsPerSecond", { valueAsNumber: true })}
                  aria-invalid={Boolean(formState.errors.httpLoadRequestsPerSecond)}
                />
                <FieldError message={formState.errors.httpLoadRequestsPerSecond?.message} />
              </label>
              <label className="field">
                <span className="field-label">Duration (seconds)</span>
                <input
                  type="number"
                  min={1}
                  max={HTTP_LOAD_EMERGENCY_LIMITS.durationSeconds}
                  {...register("httpLoadDurationSeconds", { valueAsNumber: true })}
                  aria-invalid={Boolean(formState.errors.httpLoadDurationSeconds)}
                />
                <FieldError message={formState.errors.httpLoadDurationSeconds?.message} />
              </label>
            </div>
            <p className="http-load-envelope">
              One worker host, direct connections, no source spoofing, and no redirect following.
            </p>
            {elevatedHttpLoad ? (
              <label className="switch-row switch-row--standalone http-load-confirmation">
                <span>
                  <strong>Allow elevated load</strong>
                  <small>These values can disrupt or exhaust the authorized target.</small>
                </span>
                <span className="switch">
                  <input type="checkbox" role="switch" {...register("elevatedLoadConfirmed")} />
                  <span aria-hidden="true" />
                </span>
                <FieldError message={formState.errors.elevatedLoadConfirmed?.message} />
              </label>
            ) : null}
          </fieldset>
        ) : null}
        <fieldset className="module-selector">
          <legend className="field-label">Assessment methods</legend>
          <p className="field-hint">Methods run independently and report their own evidence-backed status.</p>
          <div className="module-grid">
            {visibleAssessmentModuleDefinitions.map((module) => {
              const sourceUnavailable = !module.sourceModes.some((sourceMode) => sourceMode === mode);
              return (
                <label className={`module-option${moduleValues[module.id] ? " module-option--selected" : ""}`} key={module.id}>
                  <input
                    type="checkbox"
                    disabled={sourceUnavailable}
                    {...register(`assessmentModules.${module.id}`)}
                  />
                  <span>
                    <strong>{module.title}</strong>
                    <small>{module.description}</small>
                    <em>{module.tools.join(" · ")}{module.stagingOnly ? " · staging only" : ""}</em>
                  </span>
                </label>
              );
            })}
          </div>
          <FieldError message={formState.errors.assessmentModules?.root?.message} />
        </fieldset>
        <div className="module-safety-panel">
          <label className="field">
            <span className="field-label">Target environment</span>
            <select {...register("targetEnvironment")}>
              <option value="production">Production</option>
              <option value="staging">Staging clone</option>
            </select>
            <FieldError message={formState.errors.targetEnvironment?.message} />
          </label>
          <label className="field">
            <span className="field-label">Module request limit</span>
            <input type="number" min={1} max={10} {...register("moduleMaxRequestsPerSecond", { valueAsNumber: true })} />
            <small className="field-hint">Requests per second; hard-capped at 10</small>
          </label>
          <label className="field">
            <span className="field-label">Module concurrency</span>
            <input type="number" min={1} max={25} {...register("moduleMaxConcurrency", { valueAsNumber: true })} />
          </label>
          {selectedModules.includes("automated-dast") ? (
            <label className="switch-row switch-row--standalone field--wide">
              <span>
                <strong>Bounded active DAST</strong>
                <small>Runs after passive ZAP; available only for staging targets</small>
              </span>
              <span className="switch">
                <input
                  type="checkbox"
                  role="switch"
                  disabled={targetEnvironment !== "staging"}
                  {...register("allowActiveDast")}
                />
                <span aria-hidden="true" />
              </span>
              <FieldError message={formState.errors.allowActiveDast?.message} />
            </label>
          ) : null}
          {selectedModules.includes("http-load-capacity") ? (
            <>
              <label className="field">
                <span className="field-label">Seconds per load stage</span>
                <input type="number" min={10} max={600} {...register("loadStageDurationSeconds", { valueAsNumber: true })} />
              </label>
              <label className="field">
                <span className="field-label">Abort error rate</span>
                <input type="number" min={0.001} max={0.5} step={0.001} {...register("loadErrorRateThreshold", { valueAsNumber: true })} />
              </label>
              <label className="field">
                <span className="field-label">Abort p95 latency (ms)</span>
                <input type="number" min={100} max={60000} {...register("loadP95LatencyMsThreshold", { valueAsNumber: true })} />
              </label>
              <label className="switch-row switch-row--standalone field--wide">
                <span>
                  <strong>I acknowledge this staging load test</strong>
                  <small>Ramp: 1 → 5 → 10 → 25 virtual users, capped by the authorized concurrency, with automatic abort thresholds</small>
                </span>
                <span className="switch">
                  <input type="checkbox" role="switch" {...register("acknowledgeLoadRisk")} />
                  <span aria-hidden="true" />
                </span>
                <FieldError message={formState.errors.acknowledgeLoadRisk?.message} />
              </label>
            </>
          ) : null}
          {activeDast && targetEnvironment === "staging" ? (
            <InlineNotice tone="warning">Active scanning is rate-limited and constrained to the authorized staging host.</InlineNotice>
          ) : null}
        </div>
        <div className="control-row">
          <label className="switch-row">
            <span>
              <strong>Safe demonstration</strong>
              <small>Gather minimal proof for viable findings</small>
            </span>
            <span className="switch">
              <input type="checkbox" role="switch" {...register("safeDemonstration")} />
              <span aria-hidden="true" />
            </span>
          </label>
          <div className="stepper-field">
            <span>
              <strong>Concurrency</strong>
              <small>Parallel pipelines</small>
            </span>
            <div className="stepper">
              <IconButton
                type="button"
                label="Decrease concurrency"
                icon={Minus}
                onClick={() => stepConcurrency(-1)}
                disabled={concurrency <= 1}
              />
              <output aria-live="polite">{concurrency}</output>
              <IconButton
                type="button"
                label="Increase concurrency"
                icon={Plus}
                onClick={() => stepConcurrency(1)}
                disabled={concurrency >= 5}
              />
            </div>
          </div>
        </div>
      </section>

      <section className="form-section" aria-labelledby="access-heading">
        <div className="section-heading">
          <span className="section-index">{accessSectionIndex}</span>
          <h2 id="access-heading">Access</h2>
        </div>
        <label className="switch-row switch-row--standalone">
          <span>
            <strong>Authenticated assessment</strong>
            <small>Use target account credentials</small>
          </span>
          <span className="switch">
            <input type="checkbox" role="switch" {...register("authenticationEnabled")} />
            <span aria-hidden="true" />
          </span>
        </label>
        {authEnabled ? (
          <div className="form-grid field-reveal">
            <label className="field">
              <span className="field-label">Login type</span>
              <select {...register("loginType")}>
                <option value="form">Form</option>
                <option value="sso">Single sign-on</option>
                <option value="api">API</option>
                <option value="basic">HTTP Basic</option>
              </select>
            </label>
            <label className="field field--wide">
              <span className="field-label">Login URL</span>
              <input type="url" placeholder="https://app.example.com/login" {...register("loginUrl")} />
              <FieldError message={formState.errors.loginUrl?.message} />
            </label>
            <label className="field">
              <span className="field-label">Username</span>
              <input autoComplete="username" {...register("username")} aria-invalid={Boolean(formState.errors.username)} />
              <FieldError message={formState.errors.username?.message} />
            </label>
            <label className="field">
              <span className="field-label">Email</span>
              <input type="email" autoComplete="email" {...register("email")} />
              <FieldError message={formState.errors.email?.message} />
            </label>
            <label className="field">
              <span className="field-label field-label--status">
                Password
                {passwordState?.present ? (
                  <span className="secret-presence">
                    <KeyRound size={13} aria-hidden="true" /> Stored · {passwordState.persistence}
                  </span>
                ) : null}
              </span>
              <span className="secret-input">
                <input
                  type={showPassword ? "text" : "password"}
                  autoComplete="new-password"
                  placeholder={passwordState?.present ? "Stored — enter to replace" : "Optional"}
                  {...register("password")}
                />
                <IconButton
                  type="button"
                  label={showPassword ? "Hide password" : "Show password"}
                  icon={showPassword ? EyeOff : Eye}
                  onClick={() => setShowPassword((value) => !value)}
                />
              </span>
              {passwordState?.present ? (
                <label className="compact-check">
                  <input type="checkbox" {...register("clearPassword")} /> Remove stored password
                </label>
              ) : null}
            </label>
            <label className="field">
              <span className="field-label field-label--status">
                TOTP secret
                {totpState?.present ? (
                  <span className="secret-presence">
                    <KeyRound size={13} aria-hidden="true" /> Stored · {totpState.persistence}
                  </span>
                ) : null}
              </span>
              <span className="secret-input">
                <input
                  type={showTotp ? "text" : "password"}
                  autoComplete="off"
                  placeholder={totpState?.present ? "Stored — enter to replace" : "Optional"}
                  {...register("totpSecret")}
                />
                <IconButton
                  type="button"
                  label={showTotp ? "Hide TOTP secret" : "Show TOTP secret"}
                  icon={showTotp ? EyeOff : Eye}
                  onClick={() => setShowTotp((value) => !value)}
                />
              </span>
              {totpState?.present ? (
                <label className="compact-check">
                  <input type="checkbox" {...register("clearTotp")} /> Remove stored TOTP
                </label>
              ) : null}
            </label>
            <label className="field field--wide">
              <span className="field-label">Login flow</span>
              <textarea rows={3} placeholder="One operator step per line" {...register("loginFlow")} />
            </label>
            <label className="field">
              <span className="field-label">Success check</span>
              <select {...register("successConditionType")}>
                <option value="url_contains">URL contains</option>
                <option value="url_equals_exactly">URL equals</option>
                <option value="element_present">Element present</option>
                <option value="text_contains">Text contains</option>
              </select>
            </label>
            <label className="field">
              <span className="field-label">Expected value</span>
              <input {...register("successConditionValue")} aria-invalid={Boolean(formState.errors.successConditionValue)} />
              <FieldError message={formState.errors.successConditionValue?.message} />
            </label>
          </div>
        ) : null}
      </section>

      <details className="advanced-section">
        <summary>
          <span>Rules and reporting</span>
          <span className="summary-state">Advanced</span>
        </summary>
        <div className="advanced-content">
          <div className="form-grid">
            <label className="field">
              <span className="field-label">Focus rules</span>
              <textarea rows={5} placeholder="One rule per line" {...register("focusRules")} />
            </label>
            <label className="field">
              <span className="field-label">Avoid rules</span>
              <textarea rows={5} placeholder="One rule per line" {...register("avoidRules")} />
            </label>
            <label className="field field--wide">
              <span className="field-label">Rules of engagement</span>
              <textarea rows={4} {...register("rulesOfEngagement")} />
            </label>
          </div>
          <div className="form-grid">
            <label className="field">
              <span className="field-label">Minimum severity</span>
              <select {...register("minSeverity")}>
                <option value="">No minimum</option>
                {severities.map((severity) => (
                  <option value={severity} key={severity}>{severity[0]?.toUpperCase()}{severity.slice(1)}</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span className="field-label">Minimum confidence</span>
              <select {...register("minConfidence")}>
                <option value="">No minimum</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </label>
            <label className="field field--wide">
              <span className="field-label">Report guidance</span>
              <textarea rows={3} {...register("reportGuidance")} />
            </label>
            <label className="switch-row switch-row--standalone field field--wide">
              <span>
                <strong>SARIF report</strong>
                <small>Generate machine-readable findings when safe demonstration and triage permit it</small>
              </span>
              <span className="switch">
                <input type="checkbox" role="switch" {...register("sarif")} />
                <span aria-hidden="true" />
              </span>
            </label>
          </div>
        </div>
      </details>

      {showSaveProfile ? (
        <section className="form-section form-section--compact" aria-labelledby="reuse-heading">
          <div className="section-heading">
            <ShieldCheck size={18} aria-hidden="true" />
            <h2 id="reuse-heading">Reuse</h2>
          </div>
          <label className="switch-row switch-row--standalone">
            <span>
              <strong>Save as profile</strong>
              <small>Keep this non-secret configuration</small>
            </span>
            <span className="switch">
              <input type="checkbox" role="switch" {...register("saveProfile")} />
              <span aria-hidden="true" />
            </span>
          </label>
          {saveProfile ? (
            <label className="field field--wide field-reveal">
              <span className="field-label">Profile name</span>
              <input autoComplete="off" {...register("profileName")} />
              <FieldError message={formState.errors.profileName?.message} />
            </label>
          ) : null}
        </section>
      ) : null}

      {showAuthorization ? (
        <label className="authorization-check">
          <input type="checkbox" {...register("authorizedTesting")} />
          <span className="authorization-mark" aria-hidden="true" />
          <span>I confirm I am authorized to test this target.</span>
        </label>
      ) : null}
    </div>
  );
}
