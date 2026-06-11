import { describe, it, expect } from 'vitest';
import {
  looksLikeCfnTemplate,
  parseCfnTemplate,
  rawTextSniffsCfn,
} from '../../../src/cfn/template';

describe('looksLikeCfnTemplate', () => {
  it('accepts a template with AWSTemplateFormatVersion', () => {
    expect(looksLikeCfnTemplate({ AWSTemplateFormatVersion: '2010-09-09' })).toBe(true);
  });

  it('accepts a Resources map whose entries all have AWS:: types', () => {
    expect(
      looksLikeCfnTemplate({
        Resources: { B: { Type: 'AWS::S3::Bucket' }, C: { Type: 'Custom::Thing' } },
      }),
    ).toBe(true);
  });

  it('accepts a SAM template via Transform', () => {
    expect(
      looksLikeCfnTemplate({
        Transform: 'AWS::Serverless-2016-10-31',
        Resources: { F: { Type: 'AWS::Serverless::Function' } },
      }),
    ).toBe(true);
  });

  it('rejects a package.json-shaped object', () => {
    expect(looksLikeCfnTemplate({ name: 'pkg', version: '1.0.0', dependencies: {} })).toBe(false);
  });

  it('rejects a Kubernetes manifest', () => {
    expect(
      looksLikeCfnTemplate({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'x' } }),
    ).toBe(false);
  });

  it('rejects a Resources map with non-CFN entries', () => {
    expect(looksLikeCfnTemplate({ Resources: { a: { foo: 1 } } })).toBe(false);
  });
});

describe('rawTextSniffsCfn', () => {
  it('sniffs AWSTemplateFormatVersion', () => {
    expect(rawTextSniffsCfn('AWSTemplateFormatVersion: 2010-09-09\nbroken')).toBe(true);
  });
  it('sniffs Resources + AWS:: type', () => {
    expect(rawTextSniffsCfn('Resources:\n  B:\n    Type: AWS::S3::Bucket\n  bad: [')).toBe(true);
  });
  it('does not sniff a helm-ish yaml', () => {
    expect(rawTextSniffsCfn('apiVersion: v1\nkind: Service\nspec: {{ .Values.x }}')).toBe(false);
  });
});

describe('parseCfnTemplate (YAML)', () => {
  const yaml = [
    'AWSTemplateFormatVersion: "2010-09-09"',
    'Parameters:',
    '  Env:',
    '    Type: String',
    '    Default: prod',
    'Mappings:',
    '  RegionMap:',
    '    us-east-1:',
    '      ami: ami-123',
    'Conditions:',
    '  IsProd: !Equals [!Ref Env, prod]',
    'Resources:',
    '  LogBucket:',
    '    Type: AWS::S3::Bucket',
    '    Condition: IsProd',
    '    Properties:',
    '      BucketName: !Ref Env',
    '      Tags:',
    '        - Key: arn',
    '          Value: !GetAtt LogBucket.Arn',
    '      Sub1: !Sub "${Env}-suffix"',
    '      Joined: !Join ["-", [a, b]]',
    '      Imported: !ImportValue shared-name',
    '      Retention: 30',
  ].join('\n');

  it('canonicalises short tags to long form', () => {
    const t = parseCfnTemplate('t.yaml', yaml)!;
    const props = t.resources[0].properties;
    expect(props.BucketName).toEqual({ Ref: 'Env' });
    expect((props.Tags as unknown[])[0]).toEqual({
      Key: 'arn',
      Value: { 'Fn::GetAtt': ['LogBucket', 'Arn'] },
    });
    expect(props.Sub1).toEqual({ 'Fn::Sub': '${Env}-suffix' });
    expect(props.Joined).toEqual({ 'Fn::Join': ['-', ['a', 'b']] });
    expect(props.Imported).toEqual({ 'Fn::ImportValue': 'shared-name' });
  });

  it('keeps scalar types (numbers stay numbers)', () => {
    const t = parseCfnTemplate('t.yaml', yaml)!;
    expect(t.resources[0].properties.Retention).toBe(30);
  });

  it('captures the logical-id line and top-level property lines', () => {
    const t = parseCfnTemplate('t.yaml', yaml)!;
    const r = t.resources[0];
    expect(r.line).toBe(13); // "  LogBucket:"
    expect(r.propertyLines.BucketName).toBe(17);
  });

  it('captures Condition, Parameters, and Mappings', () => {
    const t = parseCfnTemplate('t.yaml', yaml)!;
    expect(t.resources[0].condition).toBe('IsProd');
    expect(t.parameters.Env).toEqual({ Type: 'String', Default: 'prod' });
    expect(t.mappings).toEqual({ RegionMap: { 'us-east-1': { ami: 'ami-123' } } });
  });

  it('returns undefined for parseable non-CFN YAML', () => {
    expect(parseCfnTemplate('t.yaml', 'apiVersion: v1\nkind: Pod')).toBeUndefined();
  });

  it('throws on YAML syntax errors', () => {
    expect(() =>
      parseCfnTemplate('t.yaml', 'Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Tags: [oops'),
    ).toThrow(/Failed to parse/);
  });
});

describe('parseCfnTemplate (JSON)', () => {
  const json = JSON.stringify(
    {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        Trail: {
          Type: 'AWS::CloudTrail::Trail',
          Properties: { IsLogging: true, S3BucketName: { Ref: 'Bucket' } },
        },
      },
    },
    null,
    2,
  );

  it('parses long-form intrinsics natively', () => {
    const t = parseCfnTemplate('t.json', json)!;
    expect(t.resources[0].cfnType).toBe('AWS::CloudTrail::Trail');
    expect(t.resources[0].properties.S3BucketName).toEqual({ Ref: 'Bucket' });
    expect(t.resources[0].properties.IsLogging).toBe(true);
  });

  it('approximates the resource line', () => {
    const t = parseCfnTemplate('t.json', json)!;
    expect(t.resources[0].line).toBeGreaterThan(1);
  });

  it('returns undefined for non-CFN JSON', () => {
    expect(parseCfnTemplate('package.json', '{"name":"x","version":"1.0.0"}')).toBeUndefined();
  });

  it('throws on malformed JSON', () => {
    expect(() => parseCfnTemplate('t.json', '{"Resources": ')).toThrow(/Failed to parse/);
  });
});
