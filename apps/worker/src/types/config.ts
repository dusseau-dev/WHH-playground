// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Configuration type definitions
 */

export type RuleType = 'url_path' | 'subdomain' | 'domain' | 'method' | 'header' | 'parameter' | 'code_path';

export interface Rule {
  description: string;
  type: RuleType;
  value: string;
}

export interface Rules {
  avoid?: Rule[];
  focus?: Rule[];
}

export type VulnClass = 'injection' | 'xss' | 'auth' | 'authz' | 'ssrf';

/** Whether a run can inspect source code or is limited to the live target. */
export type SourceMode = 'source-assisted' | 'url-only';

export const ALL_VULN_CLASSES: readonly VulnClass[] = ['injection', 'xss', 'auth', 'authz', 'ssrf'];

export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type Confidence = 'low' | 'medium' | 'high';

export interface ReportConfig {
  min_severity?: Severity;
  min_confidence?: Confidence;
  guidance?: string;
  /** Emit a SARIF 2.1.0 artifact when the run satisfies the safety and triage gates. */
  sarif?: boolean | 'true' | 'false';
}

export type DistributedReportConfig = Omit<ReportConfig, 'sarif'> & { sarif: boolean };

export type LoginType = 'form' | 'sso' | 'api' | 'basic';

export interface SuccessCondition {
  type: 'url_contains' | 'element_present' | 'url_equals_exactly' | 'text_contains';
  value: string;
}

export interface EmailLogin {
  address: string;
  password: string;
  totp_secret?: string;
}

export interface Credentials {
  username: string;
  password?: string;
  totp_secret?: string;
  email_login?: EmailLogin;
}

export interface Authentication {
  login_type: LoginType;
  login_url: string;
  credentials: Credentials;
  login_flow?: string[];
  success_condition: SuccessCondition;
}

export interface Config {
  rules?: Rules;
  authentication?: Authentication;
  pipeline?: PipelineConfig;
  description?: string;
  vuln_classes?: VulnClass[];
  /** Whether to run safe, authorized demonstrations of confirmed findings. */
  safe_demonstration?: boolean | 'true' | 'false';
  /** @deprecated Use safe_demonstration. */
  exploit?: boolean | 'true' | 'false';
  report?: ReportConfig;
  rules_of_engagement?: string;
}

export type RetryPreset = 'default' | 'subscription';

export interface PipelineConfig {
  retry_preset?: RetryPreset;
  max_concurrent_pipelines?: number;
}

export interface DistributedConfig {
  avoid: Rule[];
  focus: Rule[];
  authentication: Authentication | null;
  description: string;
  vuln_classes: VulnClass[];
  /** Whether to run safe, authorized demonstrations of confirmed findings. */
  safeDemonstration: boolean;
  report: DistributedReportConfig;
  rules_of_engagement: string;
}

/**
 * LLM provider configuration for multi-provider support.
 *
 * Maps to SDK environment variables at execution time. When providerType
 * is omitted or 'anthropic_api', falls back to apiKey + ANTHROPIC_API_KEY.
 */
export interface ProviderConfig {
  readonly providerType?: string;
  /** Provider id when providerType is "generic" (for example, "google"). */
  readonly providerId?: string;
  /** One model id for the whole run. modelOverrides remains the tier-compatible fallback. */
  readonly model?: string;
  readonly apiKey?: string;
  readonly awsRegion?: string;
  readonly awsAccessKeyId?: string;
  readonly awsSecretAccessKey?: string;
  /** Optional temporary-session token accompanying the AWS access-key pair. */
  readonly awsSessionToken?: string;
  readonly gcpRegion?: string;
  readonly gcpProjectId?: string;
  readonly gcpCredentialsPath?: string;
  readonly baseUrl?: string;
  readonly authToken?: string;
  readonly modelOverrides?: Record<string, string>;
  /** OpenAI-compatible gateway wire format. */
  readonly openAIFormat?: 'chat-completions' | 'responses';
  readonly supportsStructuredOutput?: boolean;
}

/**
 * Runtime configuration for the DI container.
 *
 * Abstracts path conventions and credential threading so consumers
 * can override OSS defaults without modifying source files.
 */
export interface ContainerConfig {
  /** Subdirectory for deliverables relative to the working directory. Default: '.shannon/deliverables' */
  readonly deliverablesSubdir: string;
  /** Directory for audit logs. Default: './workspaces' */
  readonly auditDir: string;
  /** API key override — when set, executor reads from config instead of process.env */
  readonly apiKey?: string;
  /** Prompt directory override — when set, prompt manager loads from this path */
  readonly promptDir?: string;
  /** LLM provider configuration — when set, executor maps to SDK env vars directly */
  readonly providerConfig?: ProviderConfig;
}
