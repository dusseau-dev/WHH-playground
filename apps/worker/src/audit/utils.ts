// Copyright (C) 2025 Keygraph, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.

/**
 * Audit System Utilities
 *
 * Core utility functions for path generation, atomic writes, and formatting.
 * All functions are pure and crash-safe.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { INTERNAL_DIR, WORKSPACES_DIR } from '../paths.js';
import { ensureDirectory } from '../utils/file-io.js';

export type { SessionMetadata } from '../types/audit.js';

import type { SessionMetadata } from '../types/audit.js';

/**
 * Extract and sanitize hostname from URL for use in identifiers
 */
export function sanitizeHostname(url: string): string {
  return new URL(url).hostname.replace(/[^a-zA-Z0-9-]/g, '-');
}

/**
 * Generate standardized session identifier from workflow ID
 * Workflow IDs already contain hostname, so we use them directly
 */
export function generateSessionIdentifier(sessionMetadata: SessionMetadata): string {
  return sessionMetadata.id;
}

/**
 * Generate path to audit log directory for a session
 * Uses custom outputPath if provided, otherwise defaults to WORKSPACES_DIR
 */
export function generateAuditPath(sessionMetadata: SessionMetadata): string {
  const sessionIdentifier = generateSessionIdentifier(sessionMetadata);
  const baseDir = sessionMetadata.outputPath || WORKSPACES_DIR;
  return path.join(baseDir, sessionIdentifier);
}

/** Generate the hidden state directory within an assessment workspace. */
export function generateInternalPath(sessionMetadata: SessionMetadata): string {
  return path.join(generateAuditPath(sessionMetadata), INTERNAL_DIR);
}

/**
 * Generate path to agent log file
 */
export function generateLogPath(
  sessionMetadata: SessionMetadata,
  agentName: string,
  timestamp: number,
  attemptNumber: number,
): string {
  const auditPath = generateInternalPath(sessionMetadata);
  const filename = `${timestamp}_${agentName}_attempt-${attemptNumber}.log`;
  return path.join(auditPath, 'agents', filename);
}

/**
 * Generate path to prompt snapshot file
 */
export function generatePromptPath(sessionMetadata: SessionMetadata, agentName: string): string {
  const auditPath = generateInternalPath(sessionMetadata);
  return path.join(auditPath, 'prompts', `${agentName}.md`);
}

/**
 * Generate path to session.json file
 */
export function generateSessionJsonPath(sessionMetadata: SessionMetadata): string {
  const auditPath = generateInternalPath(sessionMetadata);
  return path.join(auditPath, 'session.json');
}

/**
 * Promote legacy workspace-root session state before a current-path file can be
 * initialized. Linking first makes the complete legacy file visible atomically;
 * removing the old name afterwards completes the migration.
 */
async function migrateLegacySessionJson(sessionMetadata: SessionMetadata): Promise<void> {
  const legacyPath = path.join(generateAuditPath(sessionMetadata), 'session.json');
  const currentPath = generateSessionJsonPath(sessionMetadata);

  try {
    await fs.link(legacyPath, currentPath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'EEXIST') return;
    throw error;
  }

  try {
    await fs.unlink(legacyPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

/**
 * Path to the shared authenticated browser session saved by the preflight
 * validator and consumed by downstream agents via `_shared-session.txt`.
 */
export function authStateFile(sessionMetadata: SessionMetadata): string {
  return path.join(generateInternalPath(sessionMetadata), 'auth-state.json');
}

/**
 * Generate path to workflow.log file
 */
export function generateWorkflowLogPath(sessionMetadata: SessionMetadata): string {
  const auditPath = generateInternalPath(sessionMetadata);
  return path.join(auditPath, 'workflow.log');
}

/**
 * Initialize audit directory structure for a session
 * Creates: workspaces/{sessionId}/.shannon/{agents,prompts}/
 */
export async function initializeAuditStructure(sessionMetadata: SessionMetadata): Promise<void> {
  const auditPath = generateInternalPath(sessionMetadata);
  const agentsPath = path.join(auditPath, 'agents');
  const promptsPath = path.join(auditPath, 'prompts');

  await ensureDirectory(auditPath);
  await migrateLegacySessionJson(sessionMetadata);
  await ensureDirectory(agentsPath);
  await ensureDirectory(promptsPath);
}
