import { Eye, EyeOff, KeyRound, Minus, Plus, ShieldCheck } from "lucide-react";
import { useState } from "react";
import type { UseFormReturn } from "react-hook-form";
import { z } from "zod";
import { FieldError, IconButton, InlineNotice } from "./Primitives";
import { securityTestCategories, severities, type SecretState } from "../types/api";

const isHttpUrl = (value: string) => {
  if (!URL.canParse(value)) return false;
  return ["http:", "https:"].includes(new URL(value).protocol);
};
const optionalUrl = z.string().trim().refine((value) => !value || isHttpUrl(value), "Enter an HTTP(S) URL");

export const assessmentFormSchema = z
  .object({
    name: z.string().trim(),
    targetUrl: z.string().trim().refine(isHttpUrl, "Enter an HTTP(S) target URL"),
    sourceMode: z.enum(["source-assisted", "url-only"]),
    repoPath: z.string().trim(),
    testCategories: z.object({
      injection: z.boolean(),
      xss: z.boolean(),
      auth: z.boolean(),
      authz: z.boolean(),
      ssrf: z.boolean(),
    }),
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
    if (!Object.values(value.testCategories).some(Boolean)) {
      context.addIssue({ code: "custom", path: ["testCategories"], message: "Select at least one category" });
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

export const assessmentDefaults: AssessmentFormValues = {
  name: "",
  targetUrl: "",
  sourceMode: "url-only",
  repoPath: "",
  testCategories: { injection: true, xss: true, auth: true, authz: true, ssrf: true },
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

const categoryLabels = {
  injection: "Injection",
  xss: "Cross-site scripting",
  auth: "Authentication",
  authz: "Authorization",
  ssrf: "Server-side request forgery",
} as const;

interface Props {
  form: UseFormReturn<AssessmentFormValues>;
  showProfileName?: boolean;
  showSaveProfile?: boolean;
  showAuthorization?: boolean;
  passwordState?: SecretState | undefined;
  totpState?: SecretState | undefined;
}

export function AssessmentConfigFields({
  form,
  showProfileName = false,
  showSaveProfile = false,
  showAuthorization = false,
  passwordState,
  totpState,
}: Props) {
  const [showPassword, setShowPassword] = useState(false);
  const [showTotp, setShowTotp] = useState(false);
  const { register, watch, setValue, getValues, formState } = form;
  const mode = watch("sourceMode");
  const authEnabled = watch("authenticationEnabled");
  const saveProfile = watch("saveProfile");
  const concurrency = watch("concurrency");

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

      <section className="form-section" aria-labelledby="scope-heading">
        <div className="section-heading">
          <span className="section-index">{showProfileName ? "03" : "02"}</span>
          <h2 id="scope-heading">Assessment scope</h2>
        </div>
        <fieldset className="field field--wide">
          <legend className="field-label">Security test categories</legend>
          <div className="toggle-grid">
            {securityTestCategories.map((category) => (
              <label className="check-tile" key={category}>
                <input type="checkbox" {...register(`testCategories.${category}`)} />
                <span className="check-mark" aria-hidden="true" />
                <span>{categoryLabels[category]}</span>
              </label>
            ))}
          </div>
          <FieldError message={formState.errors.testCategories?.root?.message} />
        </fieldset>
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
          <span className="section-index">{showProfileName ? "04" : "03"}</span>
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
