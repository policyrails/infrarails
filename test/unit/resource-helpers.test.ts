import { describe, it, expect } from 'vitest';
import {
  getNestedValue,
  findResourceLine,
  matchesBucket,
  BEDROCK_DIRECT_RESOURCE_TYPES,
  BEDROCK_DATA_SOURCE_TYPES,
  BEDROCK_IAM_ACTIONS,
  BEDROCK_VPC_ENDPOINT_SUFFIXES,
  BEDROCK_LOGGING_INPUT_KEYS,
  BEDROCK_MODULE_NAME_TOKENS,
  BASELINE_REMOTE_STATE_NAMES,
  findBedrockResources,
  findBedrockDataSources,
  findIamBedrockGrants,
  findBedrockVpcEndpoints,
  findBedrockRelatedModuleCalls,
  findBaselineRemoteState,
  findBedrockLoggingReferences,
  findResources,
} from '../../src/utils/resource-helpers';
import { ParsedFile, PlanOverlay, PlanResource } from '../../src/types';

function pf(json: ParsedFile['json'], filePath = 'main.tf'): ParsedFile {
  return { filePath, json, rawHcl: '' };
}

describe('getNestedValue', () => {
  it('should return a simple nested value', () => {
    const obj = { a: { b: { c: 'hello' } } };
    expect(getNestedValue(obj, 'a.b.c')).toBe('hello');
  });

  it('should auto-unwrap single-element arrays', () => {
    const obj = { a: [{ b: [{ c: 'hello' }] }] };
    expect(getNestedValue(obj, 'a.b.c')).toBe('hello');
  });

  it('should return undefined for missing paths', () => {
    const obj = { a: { b: 1 } };
    expect(getNestedValue(obj, 'a.c')).toBeUndefined();
  });

  it('should handle null/undefined gracefully', () => {
    expect(getNestedValue(null, 'a.b')).toBeUndefined();
    expect(getNestedValue(undefined, 'a.b')).toBeUndefined();
  });
});

describe('findResourceLine', () => {
  it('should find the line number of a resource', () => {
    const hcl = `resource "aws_s3_bucket" "other" {
  bucket = "other-bucket"
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-bucket"
}
`;
    expect(findResourceLine(hcl, 'aws_s3_bucket', 'logs')).toBe(4);
  });

  it('should return undefined when resource not found', () => {
    expect(findResourceLine('', 'aws_s3_bucket', 'logs')).toBeUndefined();
  });
});

describe('matchesBucket', () => {
  it('should match by bucket attribute', () => {
    const body = { bucket: 'my-bucket' };
    expect(matchesBucket(body, 'some-name', ['my-bucket'])).toBe(true);
  });

  it('should match by resource name', () => {
    const body = {};
    expect(matchesBucket(body, 'logs', ['logs'])).toBe(true);
  });

  it('should return false for no match', () => {
    const body = { bucket: 'other-bucket' };
    expect(matchesBucket(body, 'other-name', ['my-bucket'])).toBe(false);
  });

  it('should return false for empty targets', () => {
    expect(matchesBucket({}, 'logs', [])).toBe(false);
  });
});

describe('Bedrock finite lists', () => {
  it('BEDROCK_DIRECT_RESOURCE_TYPES has no duplicates and every entry starts with aws_bedrock', () => {
    expect(new Set(BEDROCK_DIRECT_RESOURCE_TYPES).size).toBe(BEDROCK_DIRECT_RESOURCE_TYPES.length);
    for (const t of BEDROCK_DIRECT_RESOURCE_TYPES) {
      expect(t.startsWith('aws_bedrock')).toBe(true);
    }
  });

  it('BEDROCK_DIRECT_RESOURCE_TYPES excludes the logging-config resource', () => {
    expect(BEDROCK_DIRECT_RESOURCE_TYPES).not.toContain(
      'aws_bedrock_model_invocation_logging_configuration',
    );
  });

  it('BEDROCK_IAM_ACTIONS covers Invoke, Converse, Retrieve verbs and bedrock:*', () => {
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:InvokeModel');
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:Converse');
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:RetrieveAndGenerate');
    expect(BEDROCK_IAM_ACTIONS).toContain('bedrock:*');
  });

  it('BEDROCK_VPC_ENDPOINT_SUFFIXES contains all four runtime/agent variants', () => {
    expect(BEDROCK_VPC_ENDPOINT_SUFFIXES).toEqual(
      expect.arrayContaining(['.bedrock', '.bedrock-runtime', '.bedrock-agent', '.bedrock-agent-runtime']),
    );
  });

  it('BEDROCK_LOGGING_INPUT_KEYS, BEDROCK_MODULE_NAME_TOKENS, BASELINE_REMOTE_STATE_NAMES are non-empty', () => {
    expect(BEDROCK_LOGGING_INPUT_KEYS.length).toBeGreaterThan(0);
    expect(BEDROCK_MODULE_NAME_TOKENS.length).toBeGreaterThan(0);
    expect(BASELINE_REMOTE_STATE_NAMES.length).toBeGreaterThan(0);
  });
});

describe('findBedrockResources', () => {
  it('finds direct Bedrock resources and skips the logging resource', () => {
    const files = [
      pf({
        resource: {
          aws_bedrockagent_agent: { a: [{ agent_name: 'a' }] },
          aws_bedrock_inference_profile: { p: [{ name: 'p' }] },
          aws_bedrock_model_invocation_logging_configuration: { main: [{}] },
          aws_s3_bucket: { logs: [{ bucket: 'x' }] },
        },
      }),
    ];
    const found = findBedrockResources(files);
    const types = found.map((r) => r.type);
    expect(types).toContain('aws_bedrockagent_agent');
    expect(types).toContain('aws_bedrock_inference_profile');
    expect(types).not.toContain('aws_bedrock_model_invocation_logging_configuration');
    expect(types).not.toContain('aws_s3_bucket');
  });
});

describe('findBedrockDataSources', () => {
  it('matches every entry in BEDROCK_DATA_SOURCE_TYPES', () => {
    for (const t of BEDROCK_DATA_SOURCE_TYPES) {
      const files = [pf({ data: { [t]: { x: [{}] } } })];
      const found = findBedrockDataSources(files);
      expect(found.map((r) => r.type)).toContain(t);
    }
  });

  it('ignores non-Bedrock data sources', () => {
    const files = [pf({ data: { aws_caller_identity: { current: [{}] } } })];
    expect(findBedrockDataSources(files)).toHaveLength(0);
  });
});

describe('findIamBedrockGrants', () => {
  it('matches actions array in aws_iam_policy_document data sources', () => {
    const files = [
      pf({
        data: {
          aws_iam_policy_document: {
            doc: [{ statement: [{ actions: ['bedrock:InvokeModel'], resources: ['*'] }] }],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants).toHaveLength(1);
    expect(grants[0].actions).toEqual(['bedrock:InvokeModel']);
  });

  it('matches singular action field on a statement', () => {
    const files = [
      pf({
        data: {
          aws_iam_policy_document: {
            doc: [{ statement: { action: 'bedrock:Converse', resources: ['*'] } }],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants[0].actions).toContain('bedrock:Converse');
  });

  it('matches inline JSON policy on aws_iam_role_policy', () => {
    const files = [
      pf({
        resource: {
          aws_iam_role_policy: {
            p: [
              {
                policy: JSON.stringify({
                  Statement: [{ Effect: 'Allow', Action: 'bedrock:Retrieve', Resource: '*' }],
                }),
              },
            ],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants).toHaveLength(1);
    expect(grants[0].actions).toContain('bedrock:Retrieve');
  });

  it('returns nothing for unparseable interpolated policy strings (no false signal)', () => {
    const files = [
      pf({
        resource: {
          aws_iam_role_policy: {
            p: [{ policy: '${data.template_file.policy.rendered}' }],
          },
        },
      }),
    ];
    expect(findIamBedrockGrants(files)).toHaveLength(0);
  });

  it('matches the bedrock:* wildcard literal', () => {
    const files = [
      pf({
        resource: {
          aws_iam_policy: {
            wide: [{ policy: JSON.stringify({ Statement: [{ Action: 'bedrock:*' }] }) }],
          },
        },
      }),
    ];
    const grants = findIamBedrockGrants(files);
    expect(grants[0].actions).toContain('bedrock:*');
  });
});

describe('findBedrockVpcEndpoints', () => {
  it('matches bedrock-runtime literal', () => {
    const files = [
      pf({
        resource: {
          aws_vpc_endpoint: {
            br: [{ service_name: 'com.amazonaws.us-east-1.bedrock-runtime' }],
          },
        },
      }),
    ];
    const found = findBedrockVpcEndpoints(files);
    expect(found).toHaveLength(1);
    expect(found[0].serviceName).toBe('com.amazonaws.us-east-1.bedrock-runtime');
  });

  it('matches bedrock-agent-runtime', () => {
    const files = [
      pf({
        resource: {
          aws_vpc_endpoint: {
            br: [{ service_name: 'com.amazonaws.eu-west-1.bedrock-agent-runtime' }],
          },
        },
      }),
    ];
    expect(findBedrockVpcEndpoints(files)).toHaveLength(1);
  });

  it('returns nothing for non-Bedrock services', () => {
    const files = [
      pf({
        resource: {
          aws_vpc_endpoint: { s3: [{ service_name: 'com.amazonaws.us-east-1.s3' }] },
        },
      }),
    ];
    expect(findBedrockVpcEndpoints(files)).toHaveLength(0);
  });

  it('resolves var.X indirection for service_name', () => {
    const files: ParsedFile[] = [
      {
        filePath: '/repo/main.tf',
        rawHcl: '',
        json: {
          resource: {
            aws_vpc_endpoint: { br: [{ service_name: '${var.svc}' }] },
          },
          variable: {
            svc: [{ default: 'com.amazonaws.us-east-1.bedrock-runtime' }],
          },
        },
      },
    ];
    expect(findBedrockVpcEndpoints(files)).toHaveLength(1);
  });
});

describe('findBedrockRelatedModuleCalls', () => {
  it('matches a module by name token (bedrock)', () => {
    const files = [
      pf({
        module: {
          bedrock_logging: [{ source: 'registry.terraform.io/org/x/aws' }],
        },
      }),
    ];
    const found = findBedrockRelatedModuleCalls(files);
    expect(found).toHaveLength(1);
    expect(found[0].matchedTokens).toContain('bedrock');
  });

  it('matches a module by Bedrock-logging input key (log_bucket)', () => {
    const files = [
      pf({
        module: {
          generic: [{ source: './local', log_bucket: 'audit-logs' }],
        },
      }),
    ];
    const found = findBedrockRelatedModuleCalls(files);
    expect(found).toHaveLength(1);
    expect(found[0].matchedInputKeys).toContain('log_bucket');
  });

  it('ignores unrelated modules', () => {
    const files = [
      pf({
        module: {
          vpc: [{ source: './vpc', cidr_block: '10.0.0.0/16' }],
        },
      }),
    ];
    expect(findBedrockRelatedModuleCalls(files)).toHaveLength(0);
  });

  it('marks remote vs local correctly', () => {
    const files = [
      pf({
        module: {
          bedrock_a: [{ source: './local' }],
          bedrock_b: [{ source: 'registry.terraform.io/org/x/aws' }],
        },
      }),
    ];
    const found = findBedrockRelatedModuleCalls(files);
    const a = found.find((m) => m.name === 'bedrock_a');
    const b = found.find((m) => m.name === 'bedrock_b');
    expect(a?.isRemote).toBe(false);
    expect(b?.isRemote).toBe(true);
  });
});

describe('findBaselineRemoteState', () => {
  it('matches data terraform_remote_state with baseline name', () => {
    const files = [
      pf({
        data: {
          terraform_remote_state: {
            account_baseline: [{ backend: 's3' }],
          },
        },
      }),
    ];
    const found = findBaselineRemoteState(files);
    expect(found).toHaveLength(1);
    expect(found[0].matchedToken).toBe('account_baseline');
  });

  it('matches central_logging', () => {
    const files = [
      pf({
        data: {
          terraform_remote_state: { central_logging: [{ backend: 's3' }] },
        },
      }),
    ];
    expect(findBaselineRemoteState(files)).toHaveLength(1);
  });

  it('ignores unrelated remote-state references', () => {
    const files = [
      pf({
        data: {
          terraform_remote_state: { vpc: [{ backend: 's3' }] },
        },
      }),
    ];
    expect(findBaselineRemoteState(files)).toHaveLength(0);
  });
});

function planRes(address: string, type: string, name: string, values: Record<string, unknown> = {}): PlanResource {
  return { address, type, name, values, unknownPaths: new Set(), sensitivePaths: new Set() };
}

function planOverlayWith(resources: PlanResource[]): PlanOverlay {
  const map = new Map<string, PlanResource>();
  for (const r of resources) map.set(r.address, r);
  return {
    formatVersion: '1.2',
    terraformVersion: '1.7.5',
    resources: map,
    deletions: new Map(),
    flags: { noActionableChanges: false },
    variables: new Map(),
    outputs: new Map(),
  };
}

describe('findResources plan overlay reconciliation', () => {
  it('suppresses the root-level plan duplicate of an HCL resource', () => {
    const files = [pf({ resource: { aws_s3_bucket: { logs: [{ bucket: 'root-logs' }] } } })];
    const overlay = planOverlayWith([
      planRes('aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'root-logs' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(1);
    expect(found[0].source).toBe('hcl');
  });

  it('folds a local-module HCL block with its module-buried plan instance into one entry', () => {
    // Reproduces the reported duplicate: a guardrail in a local module is
    // walked from disk (un-prefixed in HCL) AND surfaced by the plan overlay
    // (module-prefixed). It is ONE resource and must yield ONE entry.
    const files = [pf({ resource: { aws_s3_bucket: { logs: [{ bucket: 'root-logs' }] } } }, 'modules/logging/main.tf')];
    const overlay = planOverlayWith([
      planRes('module.logging.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'resolved-logs' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(1);
    // Plan instance is kept (resolved body + address) but borrows the HCL file
    // path so the finding stays attributable to source.
    expect(found[0].address).toBe('module.logging.aws_s3_bucket.logs');
    expect(found[0].body.bucket).toBe('resolved-logs');
    expect(found[0].filePath).toBe('modules/logging/main.tf');
  });

  it('collapses count/for_each instances of a module resource to one entry', () => {
    const files: ParsedFile[] = [];
    const overlay = planOverlayWith([
      planRes('module.logging.aws_s3_bucket.logs[0]', 'aws_s3_bucket', 'logs', { bucket: 'a' }),
      planRes('module.logging.aws_s3_bucket.logs[1]', 'aws_s3_bucket', 'logs', { bucket: 'b' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(1);
  });

  it('keeps distinct module calls that share a leaf name as separate entries', () => {
    const files: ParsedFile[] = [];
    const overlay = planOverlayWith([
      planRes('module.logging_us.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'us' }),
      planRes('module.logging_eu.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'eu' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(2);
    expect(found.map((r) => r.address).sort()).toEqual([
      'module.logging_eu.aws_s3_bucket.logs',
      'module.logging_us.aws_s3_bucket.logs',
    ]);
  });

  it('keeps a root HCL block when its leaf name also appears under a module', () => {
    // Rare leaf-name collision: a root resource and an unrelated module resource
    // share a name. The root HCL block must survive (not be folded away).
    const files = [pf({ resource: { aws_s3_bucket: { logs: [{ bucket: 'root-logs' }] } } })];
    const overlay = planOverlayWith([
      planRes('aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'root-logs' }),
      planRes('module.audit.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'audit-logs' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(2);
    expect(found.some((r) => r.source === 'hcl')).toBe(true);
    expect(found.some((r) => r.address === 'module.audit.aws_s3_bucket.logs')).toBe(true);
  });

  it('keeps a genuinely plan-only resource (no HCL on disk)', () => {
    const files: ParsedFile[] = [];
    const overlay = planOverlayWith([
      planRes('module.remote.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'remote-logs' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(1);
    expect(found[0].source).toBe('plan');
    expect(found[0].filePath).toBe('plan:module.remote.aws_s3_bucket.logs');
  });
});

// Regression suite for the leaf-name reconciliation bug: a plan instance must
// be paired with the on-disk HCL block of the SAME resource (by module
// directory), never merely by leaf name. Two failures the old code produced:
//   (1) a TARGETED plan dropped a root resource that shared a module leaf name;
//   (2) two local modules sharing the `this` leaf name cross-wired attribution.
// Core invariant (CLAUDE.md): supplying a plan must NEVER make the scanner less
// certain than scanning source alone - in particular, never drop a resource.
describe('findResources reconciliation - leaf-name collision robustness', () => {
  // A root module main.tf that wires a local child module, plus the child's file.
  const rootWithModule = (
    moduleBlocks: Record<string, unknown>,
    rootResources?: Record<string, unknown>,
  ): ParsedFile =>
    pf(
      { ...(rootResources ? { resource: rootResources } : {}), module: moduleBlocks },
      'main.tf',
    );

  it('(1) targeted plan does NOT drop a root resource that shares a module leaf name', () => {
    const files = [
      rootWithModule(
        { app: [{ source: './modules/app' }] },
        { aws_s3_bucket: { logs: [{ bucket: 'root-logs' }] } },
      ),
      pf({ resource: { aws_s3_bucket: { logs: [{ bucket: 'app-bucket' }] } } }, 'modules/app/main.tf'),
    ];
    // `terraform plan -target=module.app`: the root bucket is absent from the plan.
    const overlay = planOverlayWith([
      planRes('module.app.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'app-bucket' }),
    ]);

    const found = findResources(files, 'aws_s3_bucket', overlay);

    // Root bucket survives, attributed to its OWN file (not cross-wired).
    const root = found.find((r) => r.source === 'hcl');
    expect(root).toBeDefined();
    expect(root?.filePath).toBe('main.tf');
    expect(root?.body.bucket).toBe('root-logs');
    // Module bucket present, paired with its own module file.
    const appInst = found.find((r) => r.address === 'module.app.aws_s3_bucket.logs');
    expect(appInst?.filePath).toBe('modules/app/main.tf');
    expect(found).toHaveLength(2);
  });

  it('(1b) source-only and targeted-plan scans agree on which resources exist', () => {
    const files = [
      rootWithModule(
        { app: [{ source: './modules/app' }] },
        { aws_s3_bucket: { logs: [{ bucket: 'root-logs' }] } },
      ),
      pf({ resource: { aws_s3_bucket: { logs: [{ bucket: 'app-bucket' }] } } }, 'modules/app/main.tf'),
    ];
    const sourceOnly = findResources(files, 'aws_s3_bucket'); // no overlay
    const withPlan = findResources(files, 'aws_s3_bucket', planOverlayWith([
      planRes('module.app.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'app-bucket' }),
    ]));
    // The plan must not REMOVE a resource the source-only scan saw.
    expect(withPlan.length).toBeGreaterThanOrEqual(sourceOnly.length);
    // The root bucket is present in both.
    expect(sourceOnly.some((r) => r.filePath === 'main.tf')).toBe(true);
    expect(withPlan.some((r) => r.filePath === 'main.tf')).toBe(true);
  });

  it('(2) two local modules sharing leaf name "this" each fold to their OWN file', () => {
    const files = [
      rootWithModule({
        us: [{ source: './modules/us' }],
        eu: [{ source: './modules/eu' }],
      }),
      pf({ resource: { aws_s3_bucket: { this: [{ bucket: 'us-bucket' }] } } }, 'modules/us/main.tf'),
      pf({ resource: { aws_s3_bucket: { this: [{ bucket: 'eu-bucket' }] } } }, 'modules/eu/main.tf'),
    ];
    const overlay = planOverlayWith([
      planRes('module.us.aws_s3_bucket.this', 'aws_s3_bucket', 'this', { bucket: 'us-bucket' }),
      planRes('module.eu.aws_s3_bucket.this', 'aws_s3_bucket', 'this', { bucket: 'eu-bucket' }),
    ]);

    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(2);

    const us = found.find((r) => r.address === 'module.us.aws_s3_bucket.this');
    const eu = found.find((r) => r.address === 'module.eu.aws_s3_bucket.this');
    // Correct, NOT cross-wired: each borrows its own module's file and HCL body.
    expect(us?.filePath).toBe('modules/us/main.tf');
    expect(us?.hclBody?.bucket).toBe('us-bucket');
    expect(eu?.filePath).toBe('modules/eu/main.tf');
    expect(eu?.hclBody?.bucket).toBe('eu-bucket');
  });

  it('(3) degenerate: same leaf name across modules with NO wiring - no loss, no cross-wire', () => {
    // Module subtrees scanned without the root that wires them. The directory
    // index cannot disambiguate, so we conservatively do NOT fold: no resource
    // is dropped and no plan entry borrows the wrong file (safe over precise).
    const files = [
      pf({ resource: { aws_s3_bucket: { this: [{ bucket: 'us-bucket' }] } } }, 'modules/us/main.tf'),
      pf({ resource: { aws_s3_bucket: { this: [{ bucket: 'eu-bucket' }] } } }, 'modules/eu/main.tf'),
    ];
    const overlay = planOverlayWith([
      planRes('module.us.aws_s3_bucket.this', 'aws_s3_bucket', 'this', { bucket: 'us-bucket' }),
      planRes('module.eu.aws_s3_bucket.this', 'aws_s3_bucket', 'this', { bucket: 'eu-bucket' }),
    ]);

    const found = findResources(files, 'aws_s3_bucket', overlay);
    // Both HCL blocks retained with correct buckets (nothing lost).
    expect(found.filter((r) => r.source === 'hcl').map((r) => r.body.bucket).sort()).toEqual([
      'eu-bucket',
      'us-bucket',
    ]);
    // Plan entries are NOT cross-wired onto another module's file.
    for (const r of found.filter((r) => r.source === 'plan')) {
      expect(r.filePath.startsWith('plan:')).toBe(true);
      expect(r.hclBody).toBeUndefined();
    }
    // Both module addresses are present (no instance silently lost).
    expect(found.some((r) => r.address === 'module.us.aws_s3_bucket.this')).toBe(true);
    expect(found.some((r) => r.address === 'module.eu.aws_s3_bucket.this')).toBe(true);
  });

  it('(4) nested local modules resolve the full module path', () => {
    const files = [
      rootWithModule({ outer: [{ source: './modules/outer' }] }),
      pf({ module: { inner: [{ source: './inner' }] } }, 'modules/outer/main.tf'),
      pf(
        { resource: { aws_s3_bucket: { data: [{ bucket: 'inner-bucket' }] } } },
        'modules/outer/inner/main.tf',
      ),
    ];
    const overlay = planOverlayWith([
      planRes('module.outer.module.inner.aws_s3_bucket.data', 'aws_s3_bucket', 'data', {
        bucket: 'inner-bucket',
      }),
    ]);

    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(1);
    expect(found[0].address).toBe('module.outer.module.inner.aws_s3_bucket.data');
    expect(found[0].filePath).toBe('modules/outer/inner/main.tf');
    expect(found[0].body.bucket).toBe('inner-bucket');
  });

  it('(5) one module reused under two names (shared source dir) - present once each, no cross-wire', () => {
    const files = [
      rootWithModule({
        a: [{ source: './mod' }],
        b: [{ source: './mod' }],
      }),
      pf({ resource: { aws_s3_bucket: { this: [{ bucket: 'shared' }] } } }, 'mod/main.tf'),
    ];
    const overlay = planOverlayWith([
      planRes('module.a.aws_s3_bucket.this', 'aws_s3_bucket', 'this', { bucket: 'shared' }),
      planRes('module.b.aws_s3_bucket.this', 'aws_s3_bucket', 'this', { bucket: 'shared' }),
    ]);

    const found = findResources(files, 'aws_s3_bucket', overlay);
    // Exactly the two distinct module instances - no duplicate, no missing.
    expect(found.map((r) => r.address).sort()).toEqual([
      'module.a.aws_s3_bucket.this',
      'module.b.aws_s3_bucket.this',
    ]);
  });

  it('(6) remote-module-only and a same-named local resource stay distinct', () => {
    const files = [
      pf({ resource: { aws_s3_bucket: { logs: [{ bucket: 'local-logs' }] } } }, 'main.tf'),
    ];
    const overlay = planOverlayWith([
      planRes('aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'local-logs' }),
      planRes('module.remote.aws_s3_bucket.logs', 'aws_s3_bucket', 'logs', { bucket: 'remote-logs' }),
    ]);
    const found = findResources(files, 'aws_s3_bucket', overlay);
    expect(found).toHaveLength(2);
    // Root stays HCL-attributed; remote stays plan-only and is not dropped.
    expect(found.some((r) => r.source === 'hcl' && r.filePath === 'main.tf')).toBe(true);
    const remote = found.find((r) => r.address === 'module.remote.aws_s3_bucket.logs');
    expect(remote?.source).toBe('plan');
    expect(remote?.filePath).toBe('plan:module.remote.aws_s3_bucket.logs');
  });
});

describe('findBedrockLoggingReferences', () => {
  it('detects data.terraform_remote_state.X.outputs.<bedrock-logging-key> in resource bodies', () => {
    const files = [
      pf({
        resource: {
          aws_s3_bucket_policy: {
            p: [
              {
                bucket: '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
                policy: '{}',
              },
            ],
          },
        },
      }),
    ];
    const found = findBedrockLoggingReferences(files);
    expect(found).toHaveLength(1);
    expect(found[0].remoteStateName).toBe('account_baseline');
    expect(found[0].outputKey).toBe('log_bucket');
  });

  it('does not match unrelated remote-state output keys', () => {
    const files = [
      pf({
        resource: {
          aws_s3_bucket_policy: {
            p: [{ bucket: '${data.terraform_remote_state.vpc.outputs.cidr_block}' }],
          },
        },
      }),
    ];
    expect(findBedrockLoggingReferences(files)).toHaveLength(0);
  });
});
