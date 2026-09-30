import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { MetricsTracker } from '../src/audit/metrics-tracker.js';
import { toAgentMetrics } from '../src/temporal/activities.js';
import type { PipelineState } from '../src/temporal/shared.js';
import { toWorkflowSummary } from '../src/temporal/summary-mapper.js';
import type { AgentEndResult } from '../src/types/audit.js';

const tempRoots: string[] = [];

afterEach(async () => {
  await Promise.all(tempRoots.splice(0).map((root) => fs.rm(root, { recursive: true, force: true })));
});

function endResult(overrides: Partial<AgentEndResult> = {}): AgentEndResult {
  return {
    attemptNumber: 1,
    duration_ms: 100,
    cost_usd: 3.75,
    input_tokens: 11,
    output_tokens: 22,
    cache_read_tokens: 33,
    cache_write_tokens: 44,
    num_turns: 5,
    success: true,
    ...overrides,
  };
}

describe('usage accounting', () => {
  it('maps the already-aggregated agent result to activity metrics exactly once', () => {
    expect(toAgentMetrics(endResult(), 125)).toEqual({
      durationMs: 125,
      inputTokens: 11,
      outputTokens: 22,
      cacheReadTokens: 33,
      cacheWriteTokens: 44,
      costUsd: 3.75,
      numTurns: 5,
    });
  });

  it('persists per-attempt usage and includes terminal failure spend in session totals', async () => {
    const outputPath = await fs.mkdtemp(path.join(os.tmpdir(), 'shannon-usage-'));
    tempRoots.push(outputPath);
    await fs.mkdir(path.join(outputPath, 'usage-session', '.shannon'), { recursive: true });
    const tracker = new MetricsTracker({ id: 'usage-session', webUrl: 'https://target.test', outputPath });
    await tracker.initialize('workflow-id');

    await tracker.endAgent('recon', endResult({ success: false }));
    await tracker.endAgent(
      'recon',
      endResult({
        attemptNumber: 2,
        duration_ms: 80,
        cost_usd: 1.25,
        input_tokens: 7,
        output_tokens: 8,
        cache_read_tokens: 9,
        cache_write_tokens: 10,
        num_turns: 2,
      }),
    );
    await tracker.endAgent(
      'auth-vuln',
      endResult({
        cost_usd: 0.5,
        input_tokens: 1,
        output_tokens: 2,
        cache_read_tokens: 3,
        cache_write_tokens: 4,
        num_turns: 1,
        success: false,
        isFinalAttempt: true,
      }),
    );

    const data = tracker.getMetrics();
    expect(data.metrics.agents.recon?.attempts).toMatchObject([
      {
        cost_usd: 3.75,
        input_tokens: 11,
        output_tokens: 22,
        cache_read_tokens: 33,
        cache_write_tokens: 44,
        num_turns: 5,
        success: false,
      },
      {
        cost_usd: 1.25,
        input_tokens: 7,
        output_tokens: 8,
        cache_read_tokens: 9,
        cache_write_tokens: 10,
        num_turns: 2,
        success: true,
      },
    ]);
    expect(data.metrics.agents.recon).toMatchObject({
      total_cost_usd: 5,
      total_input_tokens: 18,
      total_output_tokens: 30,
      total_cache_read_tokens: 42,
      total_cache_write_tokens: 54,
      total_turns: 7,
    });
    expect(data.metrics).toMatchObject({
      total_cost_usd: 5.5,
      total_input_tokens: 19,
      total_output_tokens: 32,
      total_cache_read_tokens: 45,
      total_cache_write_tokens: 58,
      total_turns: 8,
    });
  });

  it('carries activity usage into the workflow summary', () => {
    const state = {
      status: 'completed',
      currentPhase: null,
      currentAgent: null,
      activeAgents: [],
      activeTestCategories: [],
      expectedAgents: ['recon'],
      completedAgents: ['recon'],
      failedAgent: null,
      error: null,
      startTime: 0,
      agentMetrics: {
        recon: {
          durationMs: 125,
          inputTokens: 11,
          outputTokens: 22,
          cacheReadTokens: 33,
          cacheWriteTokens: 44,
          costUsd: 3.75,
          numTurns: 5,
        },
      },
      triageRan: true,
      summary: {
        totalCostUsd: 3.75,
        totalDurationMs: 125,
        totalTurns: 5,
        totalInputTokens: 11,
        totalOutputTokens: 22,
        totalCacheReadTokens: 33,
        totalCacheWriteTokens: 44,
        agentCount: 1,
      },
    } as PipelineState;

    expect(toWorkflowSummary(state, 'completed')).toMatchObject({
      totalCostUsd: 3.75,
      totalTurns: 5,
      totalInputTokens: 11,
      totalOutputTokens: 22,
      totalCacheReadTokens: 33,
      totalCacheWriteTokens: 44,
      agentMetrics: {
        recon: {
          costUsd: 3.75,
          inputTokens: 11,
          outputTokens: 22,
          cacheReadTokens: 33,
          cacheWriteTokens: 44,
          numTurns: 5,
        },
      },
    });
  });
});
