import { describe, it, expect } from 'vitest';
import { cwRetentionRule } from '../../../src/rules/cw-retention';
import { ParsedFile } from '../../../src/types';
import { makeParsedFile, emptyContext, bedrockContext } from './helpers';

describe('S-12.1.2a CloudWatch Retention', () => {
  it('should SKIP when no Bedrock logging detected', () => {
    const files = [makeParsedFile({})];
    const findings = cwRetentionRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should SKIP when Bedrock logging has no CloudWatch groups', () => {
    const ctx = bedrockContext({ groupNames: [] });
    const files = [makeParsedFile({})];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should WARN when log group not found in Terraform', () => {
    const ctx = bedrockContext();
    const files = [makeParsedFile({})];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].remediation).toContain('No CloudWatch subscription filter was found');
  });

  it('should WARN when retention < 180 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 7 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].remediation).toContain('No CloudWatch subscription filter was found');
    expect(findings[0].remediation).toContain('EU AI Act Art. 19(1)');
    expect(findings[0].remediation).toContain('at least six months');
    expect(findings[0].remediation).toContain('180-day floor');
    expect(findings[0].remediation).toContain('365 days is the typical floor for production AI');
  });

  it('should WARN with forwarder-found note when subscription filter is present', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 7 }],
        },
        aws_cloudwatch_log_subscription_filter: {
          datadog: [
            {
              log_group_name: '/aws/bedrock/invocation-logs',
              destination_arn: 'arn:aws:lambda:us-east-1:123456789012:function:datadog-forwarder',
              filter_pattern: '',
            },
          ],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].remediation).toContain('A CloudWatch subscription filter was found');
  });

  it('should WARN when retention >= 180 but < 365 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 200 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
  });

  it('should PASS when retention >= 365 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 365 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should PASS when retention is 0 (never expire)', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 0 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should PASS when retention_in_days references a numeric variable default >= 365', () => {
    const ctx = bedrockContext();
    const file: ParsedFile = {
      filePath: 'test.tf',
      rawHcl: '',
      json: {
        variable: { log_retention_days: [{ type: 'number', default: 365 }] },
        resource: {
          aws_cloudwatch_log_group: {
            bedrock_logs: [
              { name: '/aws/bedrock/invocation-logs', retention_in_days: '${var.log_retention_days}' },
            ],
          },
        },
      },
    };
    const findings = cwRetentionRule.run([file], ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should WARN when retention_in_days references a numeric variable default < 180', () => {
    const ctx = bedrockContext();
    const file: ParsedFile = {
      filePath: 'test.tf',
      rawHcl: '',
      json: {
        variable: { log_retention_days: [{ type: 'number', default: 30 }] },
        resource: {
          aws_cloudwatch_log_group: {
            bedrock_logs: [
              { name: '/aws/bedrock/invocation-logs', retention_in_days: '${var.log_retention_days}' },
            ],
          },
        },
      },
    };
    const findings = cwRetentionRule.run([file], ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toContain('30 days');
  });

  it('should PASS when retention_in_days references a local with a numeric value', () => {
    const ctx = bedrockContext();
    const file: ParsedFile = {
      filePath: 'test.tf',
      rawHcl: '',
      json: {
        locals: [{ retention: 400 }],
        resource: {
          aws_cloudwatch_log_group: {
            bedrock_logs: [
              { name: '/aws/bedrock/invocation-logs', retention_in_days: '${local.retention}' },
            ],
          },
        },
      },
    };
    const findings = cwRetentionRule.run([file], ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should remain INCONCLUSIVE when retention variable has no default', () => {
    const ctx = bedrockContext();
    const file: ParsedFile = {
      filePath: 'test.tf',
      rawHcl: '',
      json: {
        variable: { log_retention_days: [{ type: 'number' }] },
        resource: {
          aws_cloudwatch_log_group: {
            bedrock_logs: [
              { name: '/aws/bedrock/invocation-logs', retention_in_days: '${var.log_retention_days}' },
            ],
          },
        },
      },
    };
    const findings = cwRetentionRule.run([file], ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
  });

  it('should WARN when retention_in_days is not set', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs' }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
  });

  describe('--strict-account-logging escalation (forwarder-aware)', () => {
    const filterFor = (logGroupName: string) => ({
      aws_cloudwatch_log_subscription_filter: {
        datadog: [
          {
            log_group_name: logGroupName,
            destination_arn: 'arn:aws:lambda:us-east-1:0:function:fwd',
            filter_pattern: '',
          },
        ],
      },
    });

    it('FAIL when log group missing and no forwarder', () => {
      const ctx = bedrockContext({ strictAccountLogging: true });
      const findings = cwRetentionRule.run([makeParsedFile({})], ctx);
      expect(findings[0].status).toBe('FAIL');
      expect(findings[0].description).toContain('Strict account-logging mode');
    });

    it('stays WARN when log group missing but forwarder present', () => {
      const ctx = bedrockContext({ strictAccountLogging: true });
      const findings = cwRetentionRule.run(
        [makeParsedFile(filterFor('/aws/bedrock/invocation-logs'))],
        ctx,
      );
      expect(findings[0].status).toBe('WARN');
    });

    it('FAIL when retention < 180 and no forwarder', () => {
      const ctx = bedrockContext({ strictAccountLogging: true });
      const files = [
        makeParsedFile({
          aws_cloudwatch_log_group: {
            bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 7 }],
          },
        }),
      ];
      expect(cwRetentionRule.run(files, ctx)[0].status).toBe('FAIL');
    });

    it('stays WARN when retention < 180 but forwarder present', () => {
      const ctx = bedrockContext({ strictAccountLogging: true });
      const files = [
        makeParsedFile({
          aws_cloudwatch_log_group: {
            bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 7 }],
          },
          ...filterFor('/aws/bedrock/invocation-logs'),
        }),
      ];
      expect(cwRetentionRule.run(files, ctx)[0].status).toBe('WARN');
    });

    it('FAIL when retention_in_days unset and no forwarder', () => {
      const ctx = bedrockContext({ strictAccountLogging: true });
      const files = [
        makeParsedFile({
          aws_cloudwatch_log_group: {
            bedrock_logs: [{ name: '/aws/bedrock/invocation-logs' }],
          },
        }),
      ];
      expect(cwRetentionRule.run(files, ctx)[0].status).toBe('FAIL');
    });

    it('180-364 day retention stays WARN even without forwarder (retention exists)', () => {
      const ctx = bedrockContext({ strictAccountLogging: true });
      const files = [
        makeParsedFile({
          aws_cloudwatch_log_group: {
            bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 200 }],
          },
        }),
      ];
      expect(cwRetentionRule.run(files, ctx)[0].status).toBe('WARN');
    });
  });
});
