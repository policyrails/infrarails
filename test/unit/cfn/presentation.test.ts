import { describe, it, expect } from 'vitest';
import { applyCfnPresentation, rewriteToCfnVocabulary } from '../../../src/cfn/presentation';
import { Finding } from '../../../src/types';

function finding(overrides: Partial<Finding>): Finding {
  return {
    ruleId: 'S-9.x.1',
    status: 'PASS',
    filePath: '/infra/template.yaml',
    description: '',
    remediation: '',
    regulatoryReference: 'EU AI Act Article 9',
    nistReference: 'NIST',
    isoReference: 'ISO',
    ...overrides,
  };
}

describe('rewriteToCfnVocabulary', () => {
  it('rewrites a resource address to CFN type + quoted logical id', () => {
    expect(
      rewriteToCfnVocabulary('aws_bedrock_guardrail.RecruiterGuardrail is missing a control'),
    ).toBe('AWS::Bedrock::Guardrail "RecruiterGuardrail" is missing a control');
  });

  it('rewrites addresses in a comma-separated list, longest type first', () => {
    expect(
      rewriteToCfnVocabulary(
        '3 resource(s): aws_bedrock_guardrail.GR, aws_bedrock_guardrail_version.GRV, aws_bedrockagent_agent.Agent',
      ),
    ).toBe(
      '3 resource(s): AWS::Bedrock::Guardrail "GR", AWS::Bedrock::GuardrailVersion "GRV", AWS::Bedrock::Agent "Agent"',
    );
  });

  it('rewrites bare type mentions and curated property terms', () => {
    expect(
      rewriteToCfnVocabulary('1 aws_bedrock_guardrail resource(s) declared in scanned IaC'),
    ).toBe('1 AWS::Bedrock::Guardrail resource(s) declared in scanned IaC');
    expect(rewriteToCfnVocabulary('Increase retention_in_days to >= 180')).toBe(
      'Increase RetentionInDays to >= 180',
    );
    expect(
      rewriteToCfnVocabulary('Add a PROMPT_ATTACK filter with input_strength set to HIGH'),
    ).toBe('Add a PROMPT_ATTACK filter with InputStrength set to HIGH');
    expect(
      rewriteToCfnVocabulary('a guardrail_configuration block with guardrail_identifier and guardrail_version'),
    ).toBe('a GuardrailConfiguration block with GuardrailIdentifier and GuardrailVersion');
  });

  it('leaves raw ${...} expression chains fully intact (no half-translation)', () => {
    const expr =
      'guardrail_identifier=${aws_bedrock_guardrail.GR.guardrail_arn}, guardrail_version=${aws_bedrock_guardrail_version.GRV.version}';
    expect(rewriteToCfnVocabulary(expr)).toBe(
      'GuardrailIdentifier=${aws_bedrock_guardrail.GR.guardrail_arn}, GuardrailVersion=${aws_bedrock_guardrail_version.GRV.version}',
    );
  });

  it('never touches TF-only types that have no CFN equivalent', () => {
    const text =
      'a Terraform stack declaring aws_bedrock_model_invocation_logging_configuration';
    expect(rewriteToCfnVocabulary(text)).toBe(text);
  });

  it('displays synthesized S3 companions as the property block on the bucket', () => {
    expect(rewriteToCfnVocabulary('aws_s3_bucket_versioning.LogBucket has no status')).toBe(
      'AWS::S3::Bucket VersioningConfiguration "LogBucket" has no status',
    );
    expect(rewriteToCfnVocabulary('on aws_iam_role_policy.LambdaPolicy (bedrock:InvokeModel)')).toBe(
      'on AWS::IAM::Policy "LambdaPolicy" (bedrock:InvokeModel)',
    );
  });

  it('a trailing sentence period does not block the address rewrite', () => {
    expect(rewriteToCfnVocabulary('resolved to aws_bedrock_guardrail.GR.')).toBe(
      'resolved to AWS::Bedrock::Guardrail "GR".',
    );
  });
});

describe('applyCfnPresentation', () => {
  const cfnPath = '/infra/template.yaml';
  const tfPath = '/infra/main.tf';

  it('rewrites CFN-pathed findings and leaves TF-pathed findings untouched', () => {
    const tfDescription = '1 aws_bedrock_guardrail resource(s) declared in scanned IaC';
    const out = applyCfnPresentation(
      [
        finding({ filePath: cfnPath, description: tfDescription }),
        finding({ filePath: tfPath, description: tfDescription }),
      ],
      [cfnPath, tfPath],
    );
    expect(out[0].description).toContain('AWS::Bedrock::Guardrail');
    expect(out[1].description).toBe(tfDescription);
  });

  it('plan-sourced citations are terraform, never rewritten', () => {
    const description = 'aws_bedrock_guardrail.recruiter is missing a control';
    const out = applyCfnPresentation(
      [finding({ filePath: 'plan:module.gov.aws_bedrock_guardrail.recruiter', description })],
      [cfnPath],
    );
    expect(out[0].description).toBe(description);
  });

  it('pathless findings follow the scan: rewritten only when every file is CFN', () => {
    const description = 'No aws_bedrock_guardrail declared in scanned IaC.';
    const allCfn = applyCfnPresentation([finding({ filePath: '', description })], [cfnPath]);
    expect(allCfn[0].description).toBe('No AWS::Bedrock::Guardrail declared in scanned IaC.');

    const mixed = applyCfnPresentation([finding({ filePath: '', description })], [cfnPath, tfPath]);
    expect(mixed[0].description).toBe(description);
  });

  it('does not mutate the input findings', () => {
    const original = finding({ filePath: cfnPath, description: 'aws_bedrock_guardrail.GR x' });
    applyCfnPresentation([original], [cfnPath]);
    expect(original.description).toBe('aws_bedrock_guardrail.GR x');
  });
});
