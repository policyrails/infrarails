import { describe, it, expect } from 'vitest';
import { parseCfnTemplate } from '../../../src/cfn/template';
import { normaliseCfnTemplate } from '../../../src/cfn/normalise';
import { CFN_CONDITION_KEY } from '../../../src/cfn/source';
import {
  findIamBedrockGrants,
  findRemoteModules,
  findResources,
  getNestedValue,
} from '../../../src/utils/resource-helpers';
import { ParsedFile } from '../../../src/types';

function normalise(yaml: string, filePath = '/infra/template.yaml'): ParsedFile {
  const t = parseCfnTemplate(filePath, yaml);
  if (!t) throw new Error('fixture is not a CFN template');
  return normaliseCfnTemplate(t);
}

describe('normaliseCfnTemplate', () => {
  it('splits an inline-configured S3 bucket into the TF companion resources', () => {
    const pf = normalise(
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
        '              KMSMasterKeyID: !Ref Key',
        '      VersioningConfiguration:',
        '        Status: Enabled',
        '      LifecycleConfiguration:',
        '        Rules:',
        '          - Id: retain',
        '            Status: Enabled',
        '            ExpirationInDays: 365',
        '      ObjectLockEnabled: true',
        '  Key:',
        '    Type: AWS::KMS::Key',
      ].join('\n'),
    );

    const bucket = findResources([pf], 'aws_s3_bucket')[0];
    expect(bucket.name).toBe('LogBucket');
    expect(bucket.body.bucket).toBe('ai-logs');

    const enc = findResources([pf], 'aws_s3_bucket_server_side_encryption_configuration')[0];
    expect(enc.body.bucket).toBe('${aws_s3_bucket.LogBucket.id}');
    expect(
      getNestedValue(enc.body, 'rule.apply_server_side_encryption_by_default.sse_algorithm'),
    ).toBe('aws:kms');
    expect(
      getNestedValue(enc.body, 'rule.apply_server_side_encryption_by_default.kms_master_key_id'),
    ).toBe('${aws_kms_key.Key.id}');

    const vers = findResources([pf], 'aws_s3_bucket_versioning')[0];
    expect(getNestedValue(vers.body, 'versioning_configuration.status')).toBe('Enabled');

    const lc = findResources([pf], 'aws_s3_bucket_lifecycle_configuration')[0];
    expect(getNestedValue(lc.body, 'rule.expiration.days')).toBe(365);

    expect(findResources([pf], 'aws_s3_bucket_object_lock_configuration')).toHaveLength(1);
  });

  it('maps LogGroup / SubscriptionFilter / CloudTrail property names', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Resources:',
        '  LG:',
        '    Type: AWS::Logs::LogGroup',
        '    Properties:',
        '      LogGroupName: /aws/bedrock/logs',
        '      RetentionInDays: 365',
        '  SF:',
        '    Type: AWS::Logs::SubscriptionFilter',
        '    Properties:',
        '      LogGroupName: !Ref LG',
        '      DestinationArn: arn:aws:lambda:us-east-1:1:function:fwd',
        '      FilterPattern: ""',
        '  Trail:',
        '    Type: AWS::CloudTrail::Trail',
        '    Properties:',
        '      TrailName: audit',
        '      IsLogging: false',
        '      S3BucketName: trail-bucket',
      ].join('\n'),
    );

    const lg = findResources([pf], 'aws_cloudwatch_log_group')[0];
    expect(lg.body.name).toBe('/aws/bedrock/logs');
    expect(lg.body.retention_in_days).toBe(365);

    const sf = findResources([pf], 'aws_cloudwatch_log_subscription_filter')[0];
    expect(sf.body.log_group_name).toBe('${aws_cloudwatch_log_group.LG.id}');

    const trail = findResources([pf], 'aws_cloudtrail')[0];
    expect(trail.body.enable_logging).toBe(false);
    expect(trail.body.name).toBe('audit');
    expect(trail.body.s3_bucket_name).toBe('trail-bucket');
  });

  it('snake_cases Bedrock guardrail/agent bodies into the TF provider shape', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Resources:',
        '  GR:',
        '    Type: AWS::Bedrock::Guardrail',
        '    Properties:',
        '      Name: gr',
        '      ContentPolicyConfig:',
        '        FiltersConfig:',
        '          - Type: PROMPT_ATTACK',
        '            InputStrength: HIGH',
        '            OutputStrength: NONE',
        '      SensitiveInformationPolicyConfig:',
        '        PiiEntitiesConfig:',
        '          - Type: EMAIL',
        '            Action: BLOCK',
        '  Agent:',
        '    Type: AWS::Bedrock::Agent',
        '    Properties:',
        '      AgentName: support',
        '      GuardrailConfiguration:',
        '        GuardrailIdentifier: !GetAtt GR.GuardrailId',
        '        GuardrailVersion: "1"',
      ].join('\n'),
    );

    const gr = findResources([pf], 'aws_bedrock_guardrail')[0];
    // getNestedValue auto-unwraps single-element arrays, matching how the
    // hard-rails blocks() helper consumes the path.
    const filter = getNestedValue(gr.body, 'content_policy_config.filters_config');
    expect(filter).toEqual({
      type: 'PROMPT_ATTACK',
      input_strength: 'HIGH',
      output_strength: 'NONE',
    });
    expect(
      getNestedValue(gr.body, 'sensitive_information_policy_config.pii_entities_config.action'),
    ).toBe('BLOCK');

    const agent = findResources([pf], 'aws_bedrockagent_agent')[0];
    expect(getNestedValue(agent.body, 'guardrail_configuration.guardrail_identifier')).toBe(
      '${aws_bedrock_guardrail.GR.guardrail_id}',
    );
    expect(getNestedValue(agent.body, 'guardrail_configuration.guardrail_version')).toBe('1');
  });

  it('stamps Condition-guarded resources (and their split-out companions)', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Conditions:',
        '  IsProd: !Equals [a, a]',
        'Resources:',
        '  B:',
        '    Type: AWS::S3::Bucket',
        '    Condition: IsProd',
        '    Properties:',
        '      VersioningConfiguration:',
        '        Status: Enabled',
      ].join('\n'),
    );
    const bucket = findResources([pf], 'aws_s3_bucket')[0];
    expect(bucket.body[CFN_CONDITION_KEY]).toBe('IsProd');
    const vers = findResources([pf], 'aws_s3_bucket_versioning')[0];
    expect(vers.body[CFN_CONDITION_KEY]).toBe('IsProd');
  });

  it('converts Parameters to variable blocks with Number coercion', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Parameters:',
        '  Retention:',
        '    Type: Number',
        '    Default: "30"',
        '  Name:',
        '    Type: String',
        '    Default: ai-logs',
        '  NoDefault:',
        '    Type: String',
        'Resources:',
        '  LG:',
        '    Type: AWS::Logs::LogGroup',
        '    Properties:',
        '      RetentionInDays: !Ref Retention',
      ].join('\n'),
    );
    expect(pf.json.variable).toEqual({
      Retention: [{ default: 30 }],
      Name: [{ default: 'ai-logs' }],
      NoDefault: [{}],
    });
    const lg = findResources([pf], 'aws_cloudwatch_log_group')[0];
    expect(lg.body.retention_in_days).toBe('${var.Retention}');
  });

  it('serialises IAM inline policies so the Bedrock IAM grant detection fires', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Resources:',
        '  AppRole:',
        '    Type: AWS::IAM::Role',
        '    Properties:',
        '      AssumeRolePolicyDocument:',
        '        Version: "2012-10-17"',
        '        Statement: []',
        '      Policies:',
        '        - PolicyName: invoke',
        '          PolicyDocument:',
        '            Version: "2012-10-17"',
        '            Statement:',
        '              - Effect: Allow',
        '                Action:',
        '                  - bedrock:InvokeModel',
        '                Resource: "*"',
      ].join('\n'),
    );
    const grants = findIamBedrockGrants([pf]);
    expect(grants).toHaveLength(1);
    expect(grants[0].actions).toEqual(['bedrock:InvokeModel']);
    expect(grants[0].resourceAddress).toBe('aws_iam_role_policy.AppRole');
  });

  it('maps nested stacks to module calls with snake_cased inputs', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Resources:',
        '  LoggingStack:',
        '    Type: AWS::CloudFormation::Stack',
        '    Properties:',
        '      TemplateURL: https://s3.amazonaws.com/templates/logging.yaml',
        '      Parameters:',
        '        LogBucketName: ai-logs',
      ].join('\n'),
    );
    const remote = findRemoteModules([pf]);
    expect(remote).toHaveLength(1);
    expect(remote[0].name).toBe('LoggingStack');
    expect(remote[0].source).toBe('https://s3.amazonaws.com/templates/logging.yaml');
    const body = (pf.json.module!.LoggingStack as Array<Record<string, unknown>>)[0];
    expect(body.log_bucket_name).toBe('ai-logs');
  });

  it('writes resource headers into the synthetic rawHcl at the template lines', () => {
    const yaml = [
      'AWSTemplateFormatVersion: "2010-09-09"',
      'Resources:',
      '  LG:',
      '    Type: AWS::Logs::LogGroup',
      '    Properties:',
      '      RetentionInDays: 30',
    ].join('\n');
    const pf = normalise(yaml);
    const lines = pf.rawHcl.split('\n');
    expect(lines[2]).toBe('resource "aws_cloudwatch_log_group" "LG" {'); // line 3
    expect(lines[0]).toBe('#'); // filler, not empty (keeps ^\s* from spanning)
    expect(lines).toHaveLength(6);
  });

  it('drops unmapped resource types without inventing bodies', () => {
    const pf = normalise(
      [
        'AWSTemplateFormatVersion: "2010-09-09"',
        'Resources:',
        '  Fn:',
        '    Type: AWS::Lambda::Function',
        '    Properties:',
        '      Runtime: nodejs20.x',
      ].join('\n'),
    );
    expect(pf.json.resource ?? {}).toEqual({});
  });
});
