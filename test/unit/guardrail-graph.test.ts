import { describe, it, expect } from 'vitest';
import { buildGuardrailGraph } from '../../src/utils/guardrail-graph';
import { makeParsedFile } from './rules/helpers';

// hcl2json emits a resource reference like
//   guardrail_identifier = aws_bedrock_guardrail.filter.guardrail_id
// as the interpolation-wrapped string below.
function ref(name: string, attr = 'guardrail_id'): string {
  return `\${aws_bedrock_guardrail.${name}.${attr}}`;
}

function agent(name: string, identifier?: string): Record<string, unknown> {
  const body: Record<string, unknown> = { agent_name: name };
  if (identifier !== undefined) {
    body.guardrail_configuration = [{ guardrail_identifier: identifier, guardrail_version: '1' }];
  }
  return body;
}

describe('buildGuardrailGraph', () => {
  it('links a reference to a guardrail declared in scope', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: { support_bot: [agent('support-bot', ref('filter'))] },
        aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] },
      }),
    ];

    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('support_bot')).toEqual({ kind: 'declared', guardrail: 'filter' });
    expect(guardrailToAgents.get('filter')).toEqual(['support_bot']);
  });

  it('marks a reference to a guardrail not in scope as reference-external', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: { support_bot: [agent('support-bot', ref('platform_gr'))] },
      }),
    ];

    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('support_bot')).toEqual({
      kind: 'reference-external',
      guardrail: 'platform_gr',
    });
    // External references never populate the declared-guardrail index.
    expect(guardrailToAgents.size).toBe(0);
  });

  it('treats a literal ID / ARN as opaque (literal)', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          bot_id: [agent('bot-id', 'abcd1234')],
          bot_arn: [agent('bot-arn', 'arn:aws:bedrock:us-east-1:123456789012:guardrail/abcd1234')],
        },
      }),
    ];

    const { agentToGuardrail } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('bot_id')).toEqual({ kind: 'literal' });
    expect(agentToGuardrail.get('bot_arn')).toEqual({ kind: 'literal' });
  });

  it('marks var/local/module expressions as unresolved', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          v: [agent('v', '${var.guardrail_id}')],
          l: [agent('l', 'local.gr')],
          m: [agent('m', '${module.security.guardrail_id}')],
        },
      }),
    ];

    const { agentToGuardrail } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('v')).toEqual({ kind: 'unresolved' });
    expect(agentToGuardrail.get('l')).toEqual({ kind: 'unresolved' });
    expect(agentToGuardrail.get('m')).toEqual({ kind: 'unresolved' });
  });

  it('marks an agent with no guardrail_configuration (or empty identifier) as none', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          bare: [agent('bare')],
          empty: [agent('empty', '   ')],
        },
      }),
    ];

    const { agentToGuardrail } = buildGuardrailGraph(files);

    expect(agentToGuardrail.get('bare')).toEqual({ kind: 'none' });
    expect(agentToGuardrail.get('empty')).toEqual({ kind: 'none' });
  });

  it('collects multiple agents attaching the same declared guardrail', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          support_bot: [agent('support-bot', ref('filter'))],
          billing_bot: [agent('billing-bot', ref('filter', 'id'))],
        },
        aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] },
      }),
    ];

    const { guardrailToAgents } = buildGuardrailGraph(files);

    expect(guardrailToAgents.get('filter')).toEqual(['support_bot', 'billing_bot']);
  });

  it('returns empty maps when there are no agents', () => {
    const files = [
      makeParsedFile({ aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] } }),
    ];

    const { agentToGuardrail, guardrailToAgents } = buildGuardrailGraph(files);

    expect(agentToGuardrail.size).toBe(0);
    expect(guardrailToAgents.size).toBe(0);
  });
});
