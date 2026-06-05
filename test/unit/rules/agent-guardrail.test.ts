import { describe, it, expect } from 'vitest';
import { agentGuardrailRule } from '../../../src/rules/agent-guardrail';
import { makeParsedFile, emptyContext } from './helpers';
import { parsePlanObject } from '../../../src/plan-parser';

// A plan where the agent (module recruiter_api) attaches a guardrail (module
// bedrock_governance) whose identifier/version are known-after-apply - so the
// agent body values are empty and only the configuration reference graph proves
// attachment. `versioned` toggles whether the version output reaches an
// aws_bedrock_guardrail_version resource.
function crossModulePlanOverlay(opts?: { versioned?: boolean; indexed?: boolean }) {
  const versionOutput =
    opts?.versioned === false
      ? { expression: { constant_value: 'DRAFT' } }
      : { expression: { references: ['aws_bedrock_guardrail_version.recruiter.version'] } };
  // count/for_each expands the agent into indexed plan instances; the config
  // block stays index-free.
  const agentAddress = opts?.indexed
    ? 'module.recruiter_api.aws_bedrockagent_agent.recruiter[0]'
    : 'module.recruiter_api.aws_bedrockagent_agent.recruiter';
  return parsePlanObject({
    format_version: '1.2',
    terraform_version: '1.7.5',
    planned_values: {
      root_module: {
        child_modules: [
          {
            address: 'module.bedrock_governance',
            resources: [
              {
                address: 'module.bedrock_governance.aws_bedrock_guardrail.recruiter',
                type: 'aws_bedrock_guardrail',
                name: 'recruiter',
                values: {},
              },
            ],
          },
          {
            address: 'module.recruiter_api',
            resources: [
              {
                address: agentAddress,
                type: 'aws_bedrockagent_agent',
                name: 'recruiter',
                values: { guardrail_configuration: [{}] },
              },
            ],
          },
        ],
      },
    },
    configuration: {
      root_module: {
        module_calls: {
          recruiter_api: {
            expressions: {
              guardrail_identifier: { references: ['module.bedrock_governance.guardrail_identifier'] },
              guardrail_version: { references: ['module.bedrock_governance.guardrail_version'] },
            },
            module: {
              resources: [
                {
                  address: 'aws_bedrockagent_agent.recruiter',
                  type: 'aws_bedrockagent_agent',
                  name: 'recruiter',
                  expressions: {
                    guardrail_configuration: {
                      references: ['var.guardrail_identifier', 'var.guardrail_version'],
                    },
                  },
                },
              ],
            },
          },
          bedrock_governance: {
            expressions: {},
            module: {
              outputs: {
                guardrail_identifier: {
                  expression: { references: ['aws_bedrock_guardrail.recruiter.guardrail_arn'] },
                },
                guardrail_version: versionOutput,
              },
            },
          },
        },
      },
    },
  });
}

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

  describe('cross-module attachment via plan configuration', () => {
    it('PASSes a plan-sourced agent whose guardrail is known-after-apply (no false FAIL)', () => {
      const findings = agentGuardrailRule.run(
        [],
        emptyContext({ planOverlay: crossModulePlanOverlay() }),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('PASS');
      expect(findings[0].description).toContain('resolved across module boundary');
      expect(findings[0].description).toContain('version pinned via aws_bedrock_guardrail_version');
    });

    it('does not emit the agent twice when scanned as both HCL and plan instance', () => {
      const files = [
        makeParsedFile({
          aws_bedrockagent_agent: {
            recruiter: [
              {
                agent_name: 'recruiter',
                guardrail_configuration: [
                  {
                    guardrail_identifier: '${var.guardrail_identifier}',
                    guardrail_version: '${var.guardrail_version}',
                  },
                ],
              },
            ],
          },
        }),
      ];
      const findings = agentGuardrailRule.run(
        files,
        emptyContext({ planOverlay: crossModulePlanOverlay() }),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('PASS');
    });

    it('PASSes a count/for_each plan agent (indexed address) instead of false-FAILing', () => {
      const findings = agentGuardrailRule.run(
        [],
        emptyContext({ planOverlay: crossModulePlanOverlay({ indexed: true }) }),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('PASS');
      expect(findings[0].description).toContain('resolved across module boundary');
    });

    it('WARNs (version unset) when the chain proves attachment but not a numbered version', () => {
      const findings = agentGuardrailRule.run(
        [],
        emptyContext({ planOverlay: crossModulePlanOverlay({ versioned: false }) }),
      );
      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('WARN');
      expect(findings[0].description).toContain('DRAFT/unset');
    });
  });
});
