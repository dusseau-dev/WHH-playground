import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, FolderInput, Play } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { useNavigate } from "react-router-dom";
import {
  AssessmentConfigFields,
  assessmentDefaults,
  assessmentFormSchema,
  type AssessmentFormValues,
} from "../components/AssessmentConfigFields";
import { Button, ErrorState, PageHeader } from "../components/Primitives";
import { api } from "../lib/api";
import type { CreateRunRequest, Profile, SecurityTestCategory } from "../types/api";

function lines(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function selected<T extends string>(values: Record<T, boolean>): T[] {
  return (Object.entries(values) as Array<[T, boolean]>).filter(([, enabled]) => enabled).map(([key]) => key);
}

function toRequest(values: AssessmentFormValues, profileId?: string): CreateRunRequest {
  const authentication = values.authenticationEnabled
    ? {
        enabled: true,
        loginType: values.loginType,
        loginUrl: values.loginUrl,
        username: values.username,
        ...(values.email ? { email: values.email } : {}),
        ...(lines(values.loginFlow).length ? { loginFlow: lines(values.loginFlow) } : {}),
        successCondition: { type: values.successConditionType, value: values.successConditionValue },
        ...(values.password ? { password: values.password } : {}),
        ...(values.totpSecret ? { totpSecret: values.totpSecret } : {}),
      }
    : undefined;

  return {
    ...(profileId && { profileId }),
    targetUrl: values.targetUrl,
    sourceMode: values.sourceMode,
    ...(values.sourceMode === "source-assisted" ? { repoPath: values.repoPath } : {}),
    scope: {
      testCategories: selected<SecurityTestCategory>(values.testCategories),
      safeDemonstration: values.safeDemonstration,
      concurrency: values.concurrency,
    },
    ...(authentication ? { authentication } : {}),
    rules: {
      focus: lines(values.focusRules),
      avoid: lines(values.avoidRules),
      ...(values.rulesOfEngagement.trim() && { rulesOfEngagement: values.rulesOfEngagement.trim() }),
    },
    report: {
      ...(values.minSeverity && { minSeverity: values.minSeverity }),
      ...(values.minConfidence && { minConfidence: values.minConfidence }),
      ...(values.reportGuidance.trim() && { guidance: values.reportGuidance.trim() }),
      sarif: values.sarif,
    },
    ...(values.saveProfile ? { saveProfile: { name: values.profileName } } : {}),
    authorizationConfirmed: true,
  };
}

function profileToForm(profile: Profile): AssessmentFormValues {
  const defaults = structuredClone(assessmentDefaults);
  return {
    ...defaults,
    targetUrl: profile.targetUrl,
    sourceMode: profile.sourceMode,
    repoPath: profile.repoPath ?? "",
    testCategories: Object.fromEntries(
      Object.keys(defaults.testCategories).map((key) => [
        key,
        profile.scope.testCategories.includes(key as SecurityTestCategory),
      ]),
    ) as AssessmentFormValues["testCategories"],
    safeDemonstration: profile.scope.safeDemonstration,
    concurrency: profile.scope.concurrency,
    authenticationEnabled: profile.authentication?.enabled ?? false,
    loginType: profile.authentication?.loginType ?? "form",
    loginUrl: profile.authentication?.loginUrl ?? "",
    username: profile.authentication?.username ?? "",
    email: profile.authentication?.email ?? "",
    loginFlow: profile.authentication?.loginFlow?.join("\n") ?? "",
    successConditionType: profile.authentication?.successCondition.type ?? "url_contains",
    successConditionValue: profile.authentication?.successCondition.value ?? "",
    focusRules: profile.rules.focus.join("\n"),
    avoidRules: profile.rules.avoid.join("\n"),
    rulesOfEngagement: profile.rules.rulesOfEngagement ?? "",
    minSeverity: profile.report.minSeverity ?? "",
    minConfidence: profile.report.minConfidence ?? "",
    reportGuidance: profile.report.guidance ?? "",
    sarif: profile.report.sarif ?? false,
  };
}

export function NewAssessmentPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [profileLoading, setProfileLoading] = useState(false);
  const [loadedProfileId, setLoadedProfileId] = useState<string>();
  const form = useForm<AssessmentFormValues>({
    resolver: zodResolver(assessmentFormSchema),
    defaultValues: assessmentDefaults,
    mode: "onBlur",
  });
  const profilesQuery = useQuery({ queryKey: ["profiles"], queryFn: api.listProfiles });
  const launchMutation = useMutation({
    mutationFn: api.createRun,
    onSuccess: (run) => {
      void queryClient.invalidateQueries({ queryKey: ["runs"] });
      navigate(`/runs/${encodeURIComponent(run.id)}`);
    },
  });

  const loadProfile = async (profileId: string) => {
    if (!profileId) {
      setLoadedProfileId(undefined);
      form.reset(assessmentDefaults);
      return;
    }
    setProfileLoading(true);
    try {
      const profile = await queryClient.fetchQuery({
        queryKey: ["profiles", profileId],
        queryFn: () => api.getProfile(profileId),
      });
      setLoadedProfileId(profile.id);
      form.reset(profileToForm(profile));
    } finally {
      setProfileLoading(false);
    }
  };

  const submit = form.handleSubmit(async (values) => {
    if (!values.authorizedTesting) {
      form.setError("authorizedTesting", { message: "Authorization confirmation is required" });
      document.querySelector<HTMLInputElement>('input[name="authorizedTesting"]')?.focus();
      return;
    }
    await launchMutation.mutateAsync(toRequest(values, loadedProfileId));
  });

  return (
    <div className="page page--assessment">
      <PageHeader
        eyebrow="Run configuration"
        title="New assessment"
        actions={
          profilesQuery.data?.items.length ? (
            <label className="profile-loader">
              <FolderInput size={16} aria-hidden="true" />
              <span className="sr-only">Load profile</span>
              <select
                defaultValue=""
                disabled={profileLoading}
                onChange={(event) => void loadProfile(event.target.value)}
              >
                <option value="">Load profile…</option>
                {profilesQuery.data.items.map((profile) => (
                  <option value={profile.id} key={profile.id}>
                    {profile.name}
                  </option>
                ))}
              </select>
            </label>
          ) : null
        }
      />

      <form className="assessment-form" onSubmit={(event) => void submit(event)} noValidate>
        <AssessmentConfigFields form={form} showSaveProfile showAuthorization />
        {form.formState.errors.authorizedTesting ? (
          <div className="form-submit-error" role="alert">
            {form.formState.errors.authorizedTesting.message}
          </div>
        ) : null}
        {launchMutation.isError ? (
          <ErrorState
            message={
              launchMutation.error instanceof Error ? launchMutation.error.message : "Assessment could not be started"
            }
          />
        ) : null}
        <footer className="form-footer">
          <div className="launch-summary" aria-live="polite">
            <Play size={16} aria-hidden="true" />
            {selected(form.watch("testCategories")).length} categories · concurrency {form.watch("concurrency")}
          </div>
          <Button
            type="submit"
            variant="primary"
            icon={<ArrowRight size={17} aria-hidden="true" />}
            busy={launchMutation.isPending}
          >
            Start assessment
          </Button>
        </footer>
      </form>
    </div>
  );
}
