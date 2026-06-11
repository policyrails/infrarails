import { describe, it, expect } from 'vitest';
import { parseCfnTemplate } from '../../../src/cfn/template';
import { normaliseCfnTemplate } from '../../../src/cfn/normalise';
import { runScan } from '../../../src/runner';
import { Finding, ParsedFile } from '../../../src/types';
import { makeParsedFile } from '../rules/helpers';

function cfnFile(yaml: string, filePath = '/infra/template.yaml'): ParsedFile {
  const t = parseCfnTemplate(filePath, yaml);
  if (!t) throw new Error('fixture is not a CFN template');
  return normaliseCfnTemplate(t);
}

function byRule(findings: Finding[], ruleId: string): Finding | undefined {
  return findings.find((f) => f.ruleId === ruleId);
}

// A TF-sourced logging config pointing at literal names, used to exercise the
// phase-2 rules against CFN-declared storage (the mixed-estate scenario).
function tfLoggingConfig(bucket = 'ai-logs', group = '/aws/bedrock/logs'): ParsedFile {
  return makeParsedFile(
    {
      aws_bedrock_model_invocation_logging_configuration: {
        this: [
          {
            logging_config: [
              {
                s3_config: [{ bucket_name: bucket }],
                cloudwatch_config: [{ log_group_name: group }],
              },
            ],
          },
        ],
      },
    },
    '/infra/main.tf',
  );
}

describe('S-12.1.1 CloudFormation logging gap', () => {
  const agentTemplate = [
    'AWSTemplateFormatVersion: "2010-09-09"',
    'Resources:',
    '  Agent:',
    '    Type: AWS::Bedrock::Agent',
    '    Properties:',
    '      AgentName: support',
  ].join('\n');

  it('CFN-only Bedrock usage -> INCONCLUSIVE explaining the CFN gap (permissive)', () => {
    const findings = runScan([cfnFile(agentTemplate)]);
    const f = byRule(findings, 'S-12.1.1')!;
    expect(f.status).toBe('INCONCLUSIVE');
    expect(f.description).toMatch(/CloudFormation has no resource type/);
    expect(f.remediation).toMatch(/PutModelInvocationLoggingConfiguration/);
  });

  it('CFN-only Bedrock usage stays INCONCLUSIVE even under --strict-account-logging', () => {
    const findings = runScan([cfnFile(agentTemplate)], { strictAccountLogging: true });
    const f = byRule(findings, 'S-12.1.1')!;
    expect(f.status).toBe('INCONCLUSIVE');
    expect(f.description).toMatch(/CloudFormation has no resource type/);
  });

  it('mixed TF+CFN Bedrock usage keeps the standard strict FAIL (TF could declare logging)', () => {
    const tfAgent = makeParsedFile(
      { aws_bedrockagent_agent: { tf_agent: [{ agent_name: 'tf-side' }] } },
      '/infra/main.tf',
    );
    const findings = runScan([tfAgent, cfnFile(agentTemplate)], { strictAccountLogging: true });
    const f = byRule(findings, 'S-12.1.1')!;
    expect(f.status).toBe('FAIL');
    expect(f.description).toMatch(/Strict account-logging mode/);
  });
});

describe('Condition-gated resources -> INCONCLUSIVE (cfn-condition-gated)', () => {
  it('conditional CloudTrail', () => {
    const findings = runScan([
      cfnFile(
        [
          'AWSTemplateFormatVersion: "2010-09-09"',
          'Conditions:',
          '  CreateTrail: !Equals [a, b]',
          'Resources:',
          '  Trail:',
          '    Type: AWS::CloudTrail::Trail',
          '    Condition: CreateTrail',
          '    Properties:',
          '      IsLogging: true',
          '      S3BucketName: audit',
        ].join('\n'),
      ),
    ]);
    const f = byRule(findings, 'S-12.x.4')!;
    expect(f.status).toBe('INCONCLUSIVE');
    expect(f.description).toMatch(/Condition "CreateTrail"/);
    expect(f.unresolvedReason).toBe('cfn-condition-gated');
  });

  it('conditional encryption/versioning/lifecycle controls on the log bucket', () => {
    const storage = cfnFile(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Conditions:',
        '  Hardened: !Equals [a, b]',
        'Resources:',
        '  LogBucket:',
        '    Type: AWS::S3::Bucket',
        '    Condition: Hardened',
        '    Properties:',
        '      BucketName: ai-logs',
        '      BucketEncryption:',
        '        ServerSideEncryptionConfiguration:',
        '          - ServerSideEncryptionByDefault:',
        '              SSEAlgorithm: aws:kms',
        '      VersioningConfiguration:',
        '        Status: Enabled',
        '      LifecycleConfiguration:',
        '        Rules:',
        '          - Id: retain',
        '            Status: Enabled',
        '            ExpirationInDays: 365',
      ].join('\n'),
    );
    const findings = runScan([tfLoggingConfig(), storage]);
    for (const ruleId of ['S-12.x.2a', 'S-12.x.1', 'S-12.1.2b']) {
      const f = byRule(findings, ruleId)!;
      expect(f.status, ruleId).toBe('INCONCLUSIVE');
      expect(f.unresolvedReason, ruleId).toBe('cfn-condition-gated');
    }
  });

  it('conditional log group referenced by Bedrock logging', () => {
    const storage = cfnFile(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Conditions:',
        '  KeepLogs: !Equals [a, b]',
        'Resources:',
        '  LG:',
        '    Type: AWS::Logs::LogGroup',
        '    Condition: KeepLogs',
        '    Properties:',
        '      LogGroupName: /aws/bedrock/logs',
        '      RetentionInDays: 365',
      ].join('\n'),
    );
    const findings = runScan([tfLoggingConfig(), storage]);
    const f = byRule(findings, 'S-12.1.2a')!;
    expect(f.status).toBe('INCONCLUSIVE');
    expect(f.unresolvedReason).toBe('cfn-condition-gated');
  });

  it('conditional guardrail -> S-9.x.2 and S-9.x.3 INCONCLUSIVE, agent conditional -> S-9.x.1', () => {
    const findings = runScan([
      cfnFile(
        [
          'AWSTemplateFormatVersion: "2010-09-09"',
          'Conditions:',
          '  WithRails: !Equals [a, b]',
          'Resources:',
          '  GR:',
          '    Type: AWS::Bedrock::Guardrail',
          '    Condition: WithRails',
          '    Properties:',
          '      Name: gr',
          '      ContentPolicyConfig:',
          '        FiltersConfig:',
          '          - Type: PROMPT_ATTACK',
          '            InputStrength: HIGH',
          '          - Type: HATE',
          '            InputStrength: HIGH',
          '            OutputStrength: HIGH',
          '  Agent:',
          '    Type: AWS::Bedrock::Agent',
          '    Condition: WithRails',
          '    Properties:',
          '      AgentName: support',
          '      GuardrailConfiguration:',
          '        GuardrailIdentifier: !GetAtt GR.GuardrailId',
          '        GuardrailVersion: "1"',
        ].join('\n'),
      ),
    ]);
    expect(byRule(findings, 'S-9.x.2')!.status).toBe('INCONCLUSIVE');
    expect(byRule(findings, 'S-9.x.3')!.status).toBe('INCONCLUSIVE');
    expect(byRule(findings, 'S-9.x.1')!.status).toBe('INCONCLUSIVE');
  });

  it('unconditional controls are unaffected (PASS path intact)', () => {
    const storage = cfnFile(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Resources:',
        '  LogBucket:',
        '    Type: AWS::S3::Bucket',
        '    Properties:',
        '      BucketName: ai-logs',
        '      BucketEncryption:',
        '        ServerSideEncryptionConfiguration:',
        '          - ServerSideEncryptionByDefault:',
        '              SSEAlgorithm: aws:kms',
        '      VersioningConfiguration:',
        '        Status: Enabled',
        '      LifecycleConfiguration:',
        '        Rules:',
        '          - Id: retain',
        '            Status: Enabled',
        '            ExpirationInDays: 365',
        '  LG:',
        '    Type: AWS::Logs::LogGroup',
        '    Properties:',
        '      LogGroupName: /aws/bedrock/logs',
        '      RetentionInDays: 365',
      ].join('\n'),
    );
    const findings = runScan([tfLoggingConfig(), storage]);
    expect(byRule(findings, 'S-12.1.1')!.status).toBe('PASS');
    expect(byRule(findings, 'S-12.x.2a')!.status).toBe('PASS');
    expect(byRule(findings, 'S-12.x.1')!.status).toBe('PASS');
    expect(byRule(findings, 'S-12.1.2b')!.status).toBe('PASS');
    expect(byRule(findings, 'S-12.1.2a')!.status).toBe('PASS');
  });
});

describe('S-9.x.1 CloudFormation agent guardrail attachment', () => {
  // An unconditional CDK-style stack: the agent wires its guardrail and version
  // through Fn::GetAtt to in-template resources. Both values are known-after-apply,
  // but the references name declared resources, so attachment and a numbered
  // version pin are statically verifiable - this must PASS, not INCONCLUSIVE.
  const attachedAgentTemplate = [
    'AWSTemplateFormatVersion: "2010-09-09"',
    'Resources:',
    '  GR:',
    '    Type: AWS::Bedrock::Guardrail',
    '    Properties:',
    '      Name: gr',
    '  GRVersion:',
    '    Type: AWS::Bedrock::GuardrailVersion',
    '    Properties:',
    '      GuardrailIdentifier: !GetAtt GR.GuardrailId',
    '  Agent:',
    '    Type: AWS::Bedrock::Agent',
    '    Properties:',
    '      AgentName: support',
    '      GuardrailConfiguration:',
    '        GuardrailIdentifier: !GetAtt GR.GuardrailArn',
    '        GuardrailVersion: !GetAtt GRVersion.Version',
  ].join('\n');

  it('PASSes when the agent attaches an in-template guardrail + version via Fn::GetAtt', () => {
    const findings = runScan([cfnFile(attachedAgentTemplate)]);
    const f = byRule(findings, 'S-9.x.1')!;
    expect(f.status).toBe('PASS');
    expect(f.description).toContain('versioned guardrail attached');
    expect(f.description).toContain('version pinned via aws_bedrock_guardrail_version');
  });

  it('stays INCONCLUSIVE when the GetAtt version target is not declared in the template', () => {
    // GuardrailVersion references a version resource that does not exist here:
    // the pin is unverifiable, so the conservative verdict stands (no false PASS).
    const orphanVersion = [
      'AWSTemplateFormatVersion: "2010-09-09"',
      'Resources:',
      '  GR:',
      '    Type: AWS::Bedrock::Guardrail',
      '    Properties:',
      '      Name: gr',
      '  Agent:',
      '    Type: AWS::Bedrock::Agent',
      '    Properties:',
      '      AgentName: support',
      '      GuardrailConfiguration:',
      '        GuardrailIdentifier: !GetAtt GR.GuardrailArn',
      '        GuardrailVersion: !ImportValue shared-guardrail-version',
    ].join('\n');
    const f = byRule(runScan([cfnFile(orphanVersion)]), 'S-9.x.1')!;
    expect(f.status).toBe('INCONCLUSIVE');
  });
});

describe('cross-stack and nested-stack signals', () => {
  it('Fn::ImportValue of a baseline export keeps CloudTrail INCONCLUSIVE with the hint', () => {
    const findings = runScan([
      cfnFile(
        [
          'AWSTemplateFormatVersion: "2010-09-09"',
          'Resources:',
          '  GR:',
          '    Type: AWS::Bedrock::Guardrail',
          '    Properties:',
          '      Name: gr',
          '      KmsKeyArn: !ImportValue security-baseline-kms-key',
        ].join('\n'),
      ),
    ]);
    const f = byRule(findings, 'S-12.x.4')!;
    expect(f.status).toBe('INCONCLUSIVE');
    expect(f.description).toContain('Fn::ImportValue "security-baseline-kms-key"');
  });

  it('a Bedrock-shaped nested stack triggers the remote-module wall', () => {
    const findings = runScan([
      cfnFile(
        [
          'AWSTemplateFormatVersion: "2010-09-09"',
          'Resources:',
          '  BedrockLogging:',
          '    Type: AWS::CloudFormation::Stack',
          '    Properties:',
          '      TemplateURL: https://s3.amazonaws.com/platform/bedrock-logging.yaml',
          '      Parameters:',
          '        LogBucketName: ai-logs',
        ].join('\n'),
      ),
    ]);
    const f = byRule(findings, 'S-12.x.5')!;
    expect(f.status).toBe('INCONCLUSIVE');
    expect(f.description).toContain('BedrockLogging');
    expect(f.description).toContain('https://s3.amazonaws.com/platform/bedrock-logging.yaml');
  });
});
