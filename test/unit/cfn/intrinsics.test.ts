import { describe, it, expect } from 'vitest';
import {
  NO_VALUE,
  TranslationContext,
  pascalToSnake,
  translateValue,
} from '../../../src/cfn/intrinsics';
import { resolveExpression } from '../../../src/resolver';

function ctx(): TranslationContext {
  return {
    parameters: {
      Env: { Type: 'String', Default: 'prod' },
      NoDefault: { Type: 'String' },
    },
    resourceTfType: new Map<string, string | undefined>([
      ['LogBucket', 'aws_s3_bucket'],
      ['Unmapped', undefined],
    ]),
    mappings: { RegionMap: { 'us-east-1': { ami: 'ami-123' } } },
  };
}

describe('pascalToSnake', () => {
  it('handles acronyms and plain Pascal', () => {
    expect(pascalToSnake('SSEAlgorithm')).toBe('sse_algorithm');
    expect(pascalToSnake('KMSMasterKeyID')).toBe('kms_master_key_id');
    expect(pascalToSnake('RetentionInDays')).toBe('retention_in_days');
    expect(pascalToSnake('Arn')).toBe('arn');
    expect(pascalToSnake('GuardrailId')).toBe('guardrail_id');
    expect(pascalToSnake('PiiEntitiesConfig')).toBe('pii_entities_config');
  });
});

describe('translateValue', () => {
  it('Ref to a parameter becomes ${var.X}', () => {
    expect(translateValue({ Ref: 'Env' }, ctx())).toBe('${var.Env}');
  });

  it('Ref to a mapped resource becomes a TF resource reference', () => {
    expect(translateValue({ Ref: 'LogBucket' }, ctx())).toBe('${aws_s3_bucket.LogBucket.id}');
  });

  it('Ref to an unmapped resource becomes an fn-not-static sentinel', () => {
    expect(translateValue({ Ref: 'Unmapped' }, ctx())).toBe('${cfn:fn-not-static:Ref Unmapped}');
  });

  it('Ref to a pseudo parameter becomes a pseudo-parameter sentinel', () => {
    expect(translateValue({ Ref: 'AWS::Region' }, ctx())).toBe(
      '${cfn:pseudo-parameter:AWS::Region}',
    );
  });

  it('Ref AWS::NoValue drops the property from objects', () => {
    expect(translateValue({ Keep: 1, Drop: { Ref: 'AWS::NoValue' } }, ctx())).toEqual({ Keep: 1 });
  });

  it('GetAtt to a mapped resource becomes a snake_cased TF attribute reference', () => {
    expect(translateValue({ 'Fn::GetAtt': ['LogBucket', 'Arn'] }, ctx())).toBe(
      '${aws_s3_bucket.LogBucket.arn}',
    );
  });

  it('GetAtt to an unmapped resource or dotted attribute stays a sentinel', () => {
    expect(translateValue({ 'Fn::GetAtt': ['Unmapped', 'Arn'] }, ctx())).toMatch(
      /^\$\{cfn:fn-not-static:/,
    );
    expect(translateValue({ 'Fn::GetAtt': ['LogBucket', 'Outputs.Name'] }, ctx())).toMatch(
      /^\$\{cfn:fn-not-static:/,
    );
  });

  it('Sub with all-static vars collapses to a literal', () => {
    expect(translateValue({ 'Fn::Sub': ['${a}-x', { a: 'val' }] }, ctx())).toBe('val-x');
  });

  it('Sub over a parameter becomes a composite TF interpolation', () => {
    expect(translateValue({ 'Fn::Sub': '${Env}-suffix' }, ctx())).toBe('${var.Env}-suffix');
  });

  it('Sub that is exactly one pseudo parameter becomes a pseudo sentinel', () => {
    expect(translateValue({ 'Fn::Sub': '${AWS::AccountId}' }, ctx())).toBe(
      '${cfn:pseudo-parameter:AWS::AccountId}',
    );
  });

  it('Sub keeps literal ${!escapes}', () => {
    expect(translateValue({ 'Fn::Sub': 'a-${!keep}' }, ctx())).toBe('a-${keep}');
  });

  it('ImportValue becomes an import-value sentinel carrying the export name', () => {
    expect(translateValue({ 'Fn::ImportValue': 'baseline-log-bucket' }, ctx())).toBe(
      '${cfn:import-value:baseline-log-bucket}',
    );
  });

  it('Fn::If is never evaluated', () => {
    expect(translateValue({ 'Fn::If': ['IsProd', 'a', 'b'] }, ctx())).toBe(
      '${cfn:fn-not-static:If IsProd}',
    );
  });

  it('FindInMap resolves when fully static, sentinels otherwise', () => {
    expect(translateValue({ 'Fn::FindInMap': ['RegionMap', 'us-east-1', 'ami'] }, ctx())).toBe(
      'ami-123',
    );
    expect(
      translateValue({ 'Fn::FindInMap': ['RegionMap', { Ref: 'AWS::Region' }, 'ami'] }, ctx()),
    ).toMatch(/^\$\{cfn:complex:/);
  });

  it('Join of literals collapses; Join with a ref stays composite', () => {
    expect(translateValue({ 'Fn::Join': ['-', ['a', 'b']] }, ctx())).toBe('a-b');
    expect(translateValue({ 'Fn::Join': ['', ['pre-', { Ref: 'Env' }]] }, ctx())).toBe(
      'pre-${var.Env}',
    );
  });

  it('Select / Split / Base64 resolve static inputs', () => {
    expect(translateValue({ 'Fn::Select': [1, ['a', 'b']] }, ctx())).toBe('b');
    expect(translateValue({ 'Fn::Split': [',', 'a,b'] }, ctx())).toEqual(['a', 'b']);
    expect(translateValue({ 'Fn::Base64': 'hi' }, ctx())).toBe(
      Buffer.from('hi').toString('base64'),
    );
  });

  it('dynamic references in plain strings become dynamic-reference sentinels', () => {
    // Braces are stripped from the sentinel detail so the ${...} wrapper stays parseable.
    expect(translateValue('{{resolve:ssm:/my/param}}', ctx())).toBe(
      '${cfn:dynamic-reference:resolve:ssm:/my/param}',
    );
  });

  it('Ref AWS::NoValue at array level is dropped', () => {
    expect(translateValue([1, { Ref: 'AWS::NoValue' }, 2], ctx())).toEqual([1, 2]);
  });

  it('NO_VALUE is exported for callers that need the marker', () => {
    expect(translateValue({ Ref: 'AWS::NoValue' }, ctx())).toBe(NO_VALUE);
  });
});

describe('resolver integration for CFN sentinels', () => {
  it.each([
    ['${cfn:import-value:shared-bucket}', 'cfn-import-value'],
    ['${cfn:dynamic-reference:resolve:ssm:/p}', 'cfn-dynamic-reference'],
    ['${cfn:pseudo-parameter:AWS::Region}', 'cfn-pseudo-parameter'],
    ['${cfn:fn-not-static:If IsProd}', 'cfn-fn-not-static'],
    ['${cfn:complex:Join}', 'complex-interpolation'],
  ])('%s -> %s', (expr, reason) => {
    const result = resolveExpression(expr, []);
    expect(result).toEqual({
      kind: 'unresolvable',
      expression: expr,
      reason,
      sourceField: 'unknown',
    });
  });

  it('a composite containing a sentinel reports complex-interpolation', () => {
    const result = resolveExpression('pre-${cfn:pseudo-parameter:AWS::Region}-post', []);
    expect(result?.kind).toBe('unresolvable');
    if (result?.kind === 'unresolvable') {
      expect(result.reason).toBe('complex-interpolation');
    }
  });
});
