import { describe, it, expect } from 'vitest';
import { hardRailsRule } from '../../../src/rules/hard-rails';
import { runScan } from '../../../src/runner';
import { emptyContext, emptyPlanOverlay } from './helpers';
import { ParsedFile, HCL2JSONOutput } from '../../../src/types';

// --- builders for the hcl2json guardrail body shape ------------------------

function paFilter(input = 'HIGH', output = 'NONE'): Record<string, unknown> {
  return { type: 'PROMPT_ATTACK', input_strength: input, output_strength: output };
}

function harmfulFilter(type = 'HATE', input = 'HIGH', output = 'HIGH'): Record<string, unknown> {
  return { type, input_strength: input, output_strength: output };
}

function contentPolicy(...filters: Record<string, unknown>[]): Record<string, unknown> {
  return { content_policy_config: [{ filters_config: filters }] };
}

function piiPolicy(...entries: Record<string, unknown>[]): Record<string, unknown> {
  return { sensitive_information_policy_config: [{ pii_entities_config: entries }] };
}

function groundingPolicy(...filters: Record<string, unknown>[]): Record<string, unknown> {
  return { contextual_grounding_policy_config: [{ filters_config: filters }] };
}

function denyTopic(name = 'investment_advice'): Record<string, unknown> {
  return { topic_policy_config: [{ topics_config: [{ name, type: 'DENY', definition: 'x' }] }] };
}

function merge(...parts: Record<string, unknown>[]): Record<string, unknown> {
  return Object.assign({ name: 'gr' }, ...parts);
}

// A guardrail body with both mandatory surfaces blocking - the PASS baseline.
function bothMandatoryBlocking(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return merge(contentPolicy(paFilter('HIGH'), harmfulFilter('HATE', 'HIGH', 'HIGH')), extra);
}

function grFile(
  body: Record<string, unknown>,
  extra?: { locals?: Record<string, unknown>[]; variable?: Record<string, Record<string, unknown>[]> },
  name = 'gr',
): ParsedFile {
  const json: HCL2JSONOutput = { resource: { aws_bedrock_guardrail: { [name]: [body] } } };
  if (extra?.locals) json.locals = extra.locals;
  if (extra?.variable) json.variable = extra.variable;
  return { filePath: 'test.tf', json, rawHcl: '' };
}

function run(files: ParsedFile[], ctx = emptyContext()) {
  return hardRailsRule.run(files, ctx);
}

describe('S-9.x.3 hard-rails enforcement', () => {
  it('SKIPs when no aws_bedrock_guardrail is declared', () => {
    const file: ParsedFile = {
      filePath: 'test.tf',
      rawHcl: '',
      json: { resource: { aws_s3_bucket: { b: [{ bucket: 'x' }] } } },
    };
    const findings = run([file]);
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
    expect(findings[0].description).toContain('S-9.x.2');
  });

  it('WARNs (empty) when a guardrail declares no policy body', () => {
    const findings = run([grFile({ name: 'empty-gr' })]);
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('declares no policy body');
  });

  it('PASSes when both mandatory surfaces block', () => {
    const findings = run([grFile(bothMandatoryBlocking())]);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('enforces both mandatory surfaces');
    expect(findings[0].description).toContain('adversarial-input resilience');
  });

  it('WARNs (mandatory gap) when PROMPT_ATTACK is present but no harmful-content filter', () => {
    const findings = run([grFile(merge(contentPolicy(paFilter('HIGH'))))]);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('no harmful-content filter declared');
  });

  it('WARNs (mandatory gap) when a harmful-content filter blocks but no PROMPT_ATTACK filter', () => {
    const findings = run([grFile(merge(contentPolicy(harmfulFilter('HATE', 'HIGH', 'HIGH'))))]);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('prompt injection uncontrolled');
  });

  it('WARNs when every filter (incl. PROMPT_ATTACK) is set to NONE', () => {
    const findings = run([
      grFile(merge(contentPolicy(paFilter('NONE'), harmfulFilter('HATE', 'NONE', 'NONE')))),
    ]);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('input_strength = NONE');
    expect(findings[0].description).toContain('all content filters set below MEDIUM');
  });

  it('does not consult output_strength for PROMPT_ATTACK (input NONE -> WARN)', () => {
    const findings = run([
      grFile(merge(contentPolicy(paFilter('NONE', 'HIGH'), harmfulFilter('HATE', 'HIGH', 'HIGH')))),
    ]);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('PROMPT_ATTACK filter present but not enforcing');
  });

  it('PASSes with PII ANONYMIZE, noting ANONYMIZE counts as enforcing', () => {
    const findings = run([
      grFile(bothMandatoryBlocking(piiPolicy({ type: 'NAME', action: 'ANONYMIZE' }))),
    ]);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('Also enforcing: PII');
    expect(findings[0].description).toContain('consider BLOCK');
  });

  it('PASSes with mixed PII BLOCK + ANONYMIZE (no advisory note when a BLOCK exists)', () => {
    const findings = run([
      grFile(
        bothMandatoryBlocking(
          piiPolicy({ type: 'SSN', action: 'BLOCK' }, { type: 'PHONE', action: 'ANONYMIZE' }),
        ),
      ),
    ]);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('Also enforcing: PII');
    expect(findings[0].description).not.toContain('consider BLOCK');
  });

  it('PASSes with no PII config and notes the surface is not configured (no WARN)', () => {
    const findings = run([grFile(bothMandatoryBlocking())]);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('PII surface not configured');
  });

  it('PASSes with grounding threshold = 0 (permissive grounding does not gate)', () => {
    const findings = run([
      grFile(bothMandatoryBlocking(groundingPolicy({ type: 'GROUNDING', threshold: 0 }))),
    ]);
    expect(findings[0].status).toBe('PASS');
    // Grounding is declared-but-permissive: not reported as "enforcing" nor as "not configured".
    expect(findings[0].description).not.toContain('Also enforcing: contextual grounding');
  });

  it('PASSes with grounding threshold = 0.7 and reports grounding as enforcing', () => {
    const findings = run([
      grFile(bothMandatoryBlocking(groundingPolicy({ type: 'GROUNDING', threshold: 0.7 }))),
    ]);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('contextual grounding');
  });

  it('PASSes and reports denied topics as an informational note', () => {
    const findings = run([grFile(bothMandatoryBlocking(denyTopic()))]);
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('1 denied topic(s) declared');
  });

  it('is INCONCLUSIVE when PROMPT_ATTACK input_strength is a var with no default', () => {
    const findings = run([
      grFile(merge(contentPolicy(paFilter('${var.strength}'), harmfulFilter('HATE', 'HIGH', 'HIGH')))),
    ]);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].unresolvedReason).toBe('var-no-default');
  });

  it('resolves a local literal "HIGH" and PASSes', () => {
    const body = merge(contentPolicy(paFilter('${local.strength}'), harmfulFilter('HATE', 'HIGH', 'HIGH')));
    const findings = run([grFile(body, { locals: [{ strength: 'HIGH' }] })]);
    expect(findings[0].status).toBe('PASS');
  });

  it('is INCONCLUSIVE for a dynamic filters_config block', () => {
    const body = merge({
      content_policy_config: [{ dynamic: [{ filters_config: [{ for_each: '${var.filters}', content: [{}] }] }] }],
    });
    const findings = run([grFile(body)]);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].unresolvedReason).toBe('complex-interpolation');
  });

  it('plan overlay resolves a var with no static default -> PASS', () => {
    const overlay = { ...emptyPlanOverlay(), variables: new Map([['strength', 'HIGH']]) };
    const body = merge(contentPolicy(paFilter('${var.strength}'), harmfulFilter('HATE', '${var.strength}', '${var.strength}')));
    const findings = run([grFile(body)], emptyContext({ planOverlay: overlay }));
    expect(findings[0].status).toBe('PASS');
  });

  it('emits one finding per guardrail with mixed states', () => {
    const file: ParsedFile = {
      filePath: 'test.tf',
      rawHcl: '',
      json: {
        resource: {
          aws_bedrock_guardrail: {
            strong: [bothMandatoryBlocking()],
            empty: [{ name: 'empty' }],
            content_only: [merge(contentPolicy(harmfulFilter('HATE', 'HIGH', 'HIGH')))],
          },
        },
      },
    };
    const findings = run([file]);
    expect(findings).toHaveLength(3);
    const byName = (n: string) => findings.find((f) => f.description.includes(`aws_bedrock_guardrail.${n}`));
    expect(byName('strong')!.status).toBe('PASS');
    expect(byName('empty')!.status).toBe('WARN');
    expect(byName('content_only')!.status).toBe('WARN');
  });

  describe('Decision B/C - attaching-agent enrichment', () => {
    it('names attaching agents (blast radius) in the finding', () => {
      const file: ParsedFile = {
        filePath: 'test.tf',
        rawHcl: '',
        json: {
          resource: {
            aws_bedrock_guardrail: { filter: [merge(contentPolicy(harmfulFilter('HATE', 'HIGH', 'HIGH')))] },
            aws_bedrockagent_agent: {
              support_bot: [
                {
                  agent_name: 'support-bot',
                  guardrail_configuration: [
                    { guardrail_identifier: '${aws_bedrock_guardrail.filter.guardrail_id}', guardrail_version: '1' },
                  ],
                },
              ],
            },
          },
        },
      };
      const findings = run([file]);
      const gr = findings.find((f) => f.ruleId === 'S-9.x.3')!;
      expect(gr.description).toContain('attached to agent(s): support_bot');
    });

    it('appends the SDK-blind-spot note when no agent attaches the guardrail', () => {
      const findings = run([grFile(merge(contentPolicy(harmfulFilter('HATE', 'HIGH', 'HIGH'))))]);
      expect(findings[0].description).toContain('Not attached to any Bedrock Agent');
    });
  });

  describe('strict-mode escalation', () => {
    it('escalates a mandatory-surface INCONCLUSIVE to FAIL under --plan + --strict-account-logging', () => {
      const overlay = emptyPlanOverlay();
      const body = merge(contentPolicy(paFilter('${var.strength}'), harmfulFilter('HATE', 'HIGH', 'HIGH')));
      const findings = runScan([grFile(body)], { plan: overlay, strictAccountLogging: true });
      const gr = findings.find((f) => f.ruleId === 'S-9.x.3')!;
      expect(gr.status).toBe('FAIL');
    });
  });
});
