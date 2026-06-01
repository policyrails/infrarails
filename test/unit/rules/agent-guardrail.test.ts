import { describe, it, expect } from 'vitest';
import { agentGuardrailRule } from '../../../src/rules/agent-guardrail';
import { makeParsedFile, emptyContext } from './helpers';

function agent(config?: Record<string, unknown>): Record<string, unknown> {
  const body: Record<string, unknown> = { agent_name: 'support-bot' };
  if (config) body.guardrail_configuration = [config];
  return body;
}

describe('S-9.x.1 Bedrock Agent guardrail attachment', () => {
  it('SKIPs when there are no Bedrock Agents', () => {
    const findings = agentGuardrailRule.run(
      [makeParsedFile({ aws_s3_bucket: { b: [{ bucket: 'x' }] } })],
      emptyContext(),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('FAILs when an agent has no guardrail_configuration', () => {
    const findings = agentGuardrailRule.run(
      [makeParsedFile({ aws_bedrockagent_agent: { support_bot: [agent()] } })],
      emptyContext(),
    );
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('no guardrail_configuration');
  });

  it('FAILs when guardrail_identifier is empty', () => {
    const findings = agentGuardrailRule.run(
      [
        makeParsedFile({
          aws_bedrockagent_agent: { support_bot: [agent({ guardrail_identifier: '', guardrail_version: '1' })] },
        }),
      ],
      emptyContext(),
    );
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('empty or unset');
  });

  it('PASSes a literal identifier with a numbered version, noting it is opaque', () => {
    const findings = agentGuardrailRule.run(
      [
        makeParsedFile({
          aws_bedrockagent_agent: {
            support_bot: [agent({ guardrail_identifier: 'abcd1234', guardrail_version: '2' })],
          },
        }),
      ],
      emptyContext(),
    );
    expect(findings[0].status).toBe('PASS');
    expect(findings[0].description).toContain('literal ID/ARN');
  });

  it('WARNs on a DRAFT version', () => {
    const findings = agentGuardrailRule.run(
      [
        makeParsedFile({
          aws_bedrockagent_agent: {
            support_bot: [agent({ guardrail_identifier: 'abcd1234', guardrail_version: 'DRAFT' })],
          },
        }),
      ],
      emptyContext(),
    );
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('DRAFT');
  });

  describe('Decision A - referential integrity', () => {
    it('PASSes a reference to a guardrail declared in scope (was INCONCLUSIVE before)', () => {
      const findings = agentGuardrailRule.run(
        [
          makeParsedFile({
            aws_bedrockagent_agent: {
              support_bot: [
                agent({
                  guardrail_identifier: '${aws_bedrock_guardrail.filter.guardrail_id}',
                  guardrail_version: '1',
                }),
              ],
            },
            aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] },
          }),
        ],
        emptyContext(),
      );
      expect(findings[0].status).toBe('PASS');
    });

    it('WARNs on a reference to a guardrail NOT declared in scope', () => {
      const findings = agentGuardrailRule.run(
        [
          makeParsedFile({
            aws_bedrockagent_agent: {
              support_bot: [
                agent({
                  guardrail_identifier: '${aws_bedrock_guardrail.platform_gr.guardrail_id}',
                  guardrail_version: '1',
                }),
              ],
            },
          }),
        ],
        emptyContext(),
      );
      expect(findings[0].status).toBe('WARN');
      expect(findings[0].description).toContain('not in the scanned');
      expect(findings[0].description).toContain('platform_gr');
    });

    it('keeps a reference-to-declared INCONCLUSIVE when the VERSION is expression-driven', () => {
      const findings = agentGuardrailRule.run(
        [
          makeParsedFile({
            aws_bedrockagent_agent: {
              support_bot: [
                agent({
                  guardrail_identifier: '${aws_bedrock_guardrail.filter.guardrail_id}',
                  guardrail_version: '${var.gr_version}',
                }),
              ],
            },
            aws_bedrock_guardrail: { filter: [{ name: 'content-filter' }] },
          }),
        ],
        emptyContext(),
      );
      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toContain('guardrail_version');
    });

    it('keeps a var-driven identifier INCONCLUSIVE (unchanged)', () => {
      const findings = agentGuardrailRule.run(
        [
          makeParsedFile({
            aws_bedrockagent_agent: {
              support_bot: [
                agent({ guardrail_identifier: '${var.guardrail_id}', guardrail_version: '1' }),
              ],
            },
          }),
        ],
        emptyContext(),
      );
      expect(findings[0].status).toBe('INCONCLUSIVE');
    });
  });
});
