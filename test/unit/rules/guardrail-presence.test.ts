import { describe, it, expect } from 'vitest';
import { guardrailPresenceRule } from '../../../src/rules/guardrail-presence';
import { makeParsedFile, emptyContext, emptyPlanOverlay } from './helpers';
import { PlanResource } from '../../../src/types';

function planResource(address: string, type: string, name: string): PlanResource {
  return {
    address,
    type,
    name,
    values: {},
    unknownPaths: new Set(),
    sensitivePaths: new Set(),
  };
}

describe('S-9.x.2 Guardrail Presence', () => {
  it('SKIPs when no Bedrock signal is present', () => {
    const files = [
      makeParsedFile({
        aws_s3_bucket: { logs: [{ bucket: 'unrelated' }] },
      }),
    ];
    const findings = guardrailPresenceRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('SKIPs when only a guardrail resource is declared (no workload)', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_guardrail: { gr: [{ name: 'standalone' }] },
      }),
    ];
    const findings = guardrailPresenceRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('WARNs when a Bedrock Agent exists but no guardrail is declared', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: { support_bot: [{ name: 'support-bot' }] },
      }),
    ];
    const findings = guardrailPresenceRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('direct Bedrock resource');
    expect(findings[0].remediation).toContain('aws_bedrock_guardrail');
  });

  it('WARNs when only an IAM grant for bedrock:InvokeModel is present', () => {
    const files = [
      makeParsedFile({
        aws_iam_role_policy: {
          allow_bedrock: [
            {
              policy: JSON.stringify({
                Statement: [{ Effect: 'Allow', Action: 'bedrock:InvokeModel', Resource: '*' }],
              }),
            },
          ],
        },
      }),
    ];
    const findings = guardrailPresenceRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('IAM grant');
  });

  it('PASSes when the only guardrail lives inside a module (plan overlay)', () => {
    // Regression: an IAM grant in raw HCL plus a guardrail buried in a module
    // (visible only via the plan overlay). Before the overlay was threaded into
    // findResources, this reported a false "no guardrail declared" WARN while
    // S-9.x.3 inspected the very same guardrail's body.
    const files = [
      makeParsedFile({
        aws_iam_role_policy: {
          allow_bedrock: [
            {
              policy: JSON.stringify({
                Statement: [{ Effect: 'Allow', Action: 'bedrock:InvokeModel', Resource: '*' }],
              }),
            },
          ],
        },
      }),
    ];
    const overlay = emptyPlanOverlay();
    overlay.resources.set(
      'module.bedrock_governance.aws_bedrock_guardrail.recruiter',
      planResource(
        'module.bedrock_governance.aws_bedrock_guardrail.recruiter',
        'aws_bedrock_guardrail',
        'recruiter',
      ),
    );
    const findings = guardrailPresenceRule.run(files, emptyContext({ planOverlay: overlay }));

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('recruiter');
  });

  it('PASSes when Bedrock is used and a guardrail is declared', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: { support_bot: [{ name: 'support-bot' }] },
        aws_bedrock_guardrail: {
          content_filter: [{ name: 'content-filter' }],
        },
      }),
    ];
    const findings = guardrailPresenceRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('content_filter');
    expect(findings[0].description).toContain('SDK-driven');
  });
});
