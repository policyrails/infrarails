import { HCL2JSONOutput, ParsedFile } from '../types';
import { CfnParsedResource, CfnTemplate } from './template';
import {
  NO_VALUE,
  TranslationContext,
  pascalToSnake,
  translateValue,
} from './intrinsics';
import { CFN_CONDITION_KEY } from './source';

// ---------------------------------------------------------------------------
// CFN -> ParsedFile normalisation.
//
// The scanner's internal representation IS the Terraform-JSON shape
// (HCL2JSONOutput): every rule, the resolver, and the plan overlay already
// speak it. This module maps each CloudFormation resource into that shape -
// AWS::S3::Bucket becomes aws_s3_bucket (plus the aws_s3_bucket_* companion
// resources Terraform splits out), AWS::Bedrock::Guardrail becomes
// aws_bedrock_guardrail with PascalCase keys snake_cased, and nested stacks
// become module calls - so each rule is written once and runs against either
// dialect unchanged.
//
// Honesty contract: where CFN cannot express something the rules check
// (intrinsics resolved only at deploy time, Condition-guarded resources,
// resource types CFN lacks), the normaliser produces sentinel expressions /
// condition stamps that surface as INCONCLUSIVE - never a fabricated PASS.
// ---------------------------------------------------------------------------

/**
 * CFN type -> Terraform type, used to translate !Ref / !GetAtt into TF-style
 * resource references. A superset of the types the normaliser emits bodies
 * for: IAM principals are referenceable (RoleArn: !GetAtt Role.Arn) even
 * though no rule consumes their body.
 *
 * Update by appending - same convention as the Bedrock lists in
 * src/utils/resource-helpers.ts.
 */
export const CFN_REF_TYPE_MAP: Record<string, string> = {
  'AWS::S3::Bucket': 'aws_s3_bucket',
  'AWS::Logs::LogGroup': 'aws_cloudwatch_log_group',
  'AWS::Logs::SubscriptionFilter': 'aws_cloudwatch_log_subscription_filter',
  'AWS::CloudTrail::Trail': 'aws_cloudtrail',
  'AWS::EC2::VPCEndpoint': 'aws_vpc_endpoint',
  'AWS::KMS::Key': 'aws_kms_key',
  'AWS::IAM::Role': 'aws_iam_role',
  'AWS::IAM::User': 'aws_iam_user',
  'AWS::IAM::Group': 'aws_iam_group',
  'AWS::IAM::ManagedPolicy': 'aws_iam_policy',
  'AWS::Bedrock::Guardrail': 'aws_bedrock_guardrail',
  'AWS::Bedrock::GuardrailVersion': 'aws_bedrock_guardrail_version',
  'AWS::Bedrock::Agent': 'aws_bedrockagent_agent',
  'AWS::Bedrock::AgentAlias': 'aws_bedrockagent_agent_alias',
  'AWS::Bedrock::KnowledgeBase': 'aws_bedrockagent_knowledge_base',
  'AWS::Bedrock::DataSource': 'aws_bedrockagent_data_source',
  'AWS::Bedrock::Flow': 'aws_bedrockagent_flow',
  'AWS::Bedrock::Prompt': 'aws_bedrockagent_prompt',
  'AWS::Bedrock::PromptVersion': 'aws_bedrockagent_prompt_version',
  'AWS::Bedrock::ApplicationInferenceProfile': 'aws_bedrock_inference_profile',
};

/**
 * Bedrock CFN types whose bodies map to the TF provider shape by plain
 * key-snake-casing (the provider mirrors the API surface CFN also mirrors).
 */
const SNAKE_CASE_BODY_TYPES: Record<string, string> = {
  'AWS::Bedrock::Guardrail': 'aws_bedrock_guardrail',
  'AWS::Bedrock::GuardrailVersion': 'aws_bedrock_guardrail_version',
  'AWS::Bedrock::Agent': 'aws_bedrockagent_agent',
  'AWS::Bedrock::AgentAlias': 'aws_bedrockagent_agent_alias',
  'AWS::Bedrock::KnowledgeBase': 'aws_bedrockagent_knowledge_base',
  'AWS::Bedrock::DataSource': 'aws_bedrockagent_data_source',
  'AWS::Bedrock::Flow': 'aws_bedrockagent_flow',
  'AWS::Bedrock::Prompt': 'aws_bedrockagent_prompt',
  'AWS::Bedrock::PromptVersion': 'aws_bedrockagent_prompt_version',
  'AWS::Bedrock::ApplicationInferenceProfile': 'aws_bedrock_inference_profile',
};

/**
 * Normalise one parsed CFN template into the ParsedFile shape the rest of the
 * pipeline consumes. The synthetic rawHcl carries one
 * `resource "<tf_type>" "<LogicalId>"` header per synthesized resource, placed
 * on the template line the resource (or the relevant property block) was
 * declared on, so findResourceLine() attributes findings to real YAML lines.
 */
export function normaliseCfnTemplate(t: CfnTemplate): ParsedFile {
  const ctx: TranslationContext = {
    parameters: t.parameters,
    resourceTfType: new Map(
      t.resources.map((r) => [r.logicalId, CFN_REF_TYPE_MAP[r.cfnType]]),
    ),
    mappings: t.mappings,
  };

  const resource: Record<string, Record<string, Record<string, unknown>[]>> = {};
  const moduleBlocks: Record<string, Array<Record<string, unknown>>> = {};
  // Filler lines are '#' (not ''): findResourceLine's `^\s*resource` pattern
  // would otherwise let \s* swallow a run of empty lines and report the line
  // where the blank run starts instead of the line carrying the header.
  const FILLER = '#';
  const rawLines: string[] = new Array(t.lineCount).fill(FILLER);

  const add = (
    tfType: string,
    name: string,
    body: Record<string, unknown>,
    condition: string | undefined,
    line: number | undefined,
  ): void => {
    if (condition) body[CFN_CONDITION_KEY] = condition;
    (resource[tfType] ??= {})[name] = [body];
    if (line !== undefined && line >= 1 && line <= rawLines.length && rawLines[line - 1] === FILLER) {
      rawLines[line - 1] = `resource "${tfType}" "${name}" {`;
    }
  };

  for (const res of t.resources) {
    normaliseResource(res, ctx, add, moduleBlocks);
  }

  const variable = parametersToVariables(t.parameters);

  const json: HCL2JSONOutput = {};
  if (Object.keys(resource).length > 0) json.resource = resource;
  if (Object.keys(variable).length > 0) json.variable = variable;
  if (Object.keys(moduleBlocks).length > 0) json.module = moduleBlocks;

  return { filePath: t.filePath, json, rawHcl: rawLines.join('\n') };
}

type AddFn = (
  tfType: string,
  name: string,
  body: Record<string, unknown>,
  condition: string | undefined,
  line: number | undefined,
) => void;

function normaliseResource(
  res: CfnParsedResource,
  ctx: TranslationContext,
  add: AddFn,
  moduleBlocks: Record<string, Array<Record<string, unknown>>>,
): void {
  const translated = translateValue(res.properties, ctx);
  const props = (translated === NO_VALUE ? {} : translated) as Record<string, unknown>;
  const id = res.logicalId;
  const cond = res.condition;

  switch (res.cfnType) {
    case 'AWS::S3::Bucket':
      normaliseS3Bucket(res, props, add);
      return;

    case 'AWS::Logs::LogGroup': {
      const body = snakeKeysDeep(props) as Record<string, unknown>;
      renameKey(body, 'log_group_name', 'name');
      add('aws_cloudwatch_log_group', id, body, cond, res.line);
      return;
    }

    case 'AWS::Logs::SubscriptionFilter':
      add('aws_cloudwatch_log_subscription_filter', id, snakeKeysDeep(props) as Record<string, unknown>, cond, res.line);
      return;

    case 'AWS::CloudTrail::Trail': {
      const body = snakeKeysDeep(props) as Record<string, unknown>;
      renameKey(body, 'is_logging', 'enable_logging');
      renameKey(body, 'trail_name', 'name');
      add('aws_cloudtrail', id, body, cond, res.line);
      return;
    }

    case 'AWS::EC2::VPCEndpoint':
      add('aws_vpc_endpoint', id, snakeKeysDeep(props) as Record<string, unknown>, cond, res.line);
      return;

    case 'AWS::IAM::ManagedPolicy': {
      const policy = stringifyPolicy(props.PolicyDocument);
      const body: Record<string, unknown> = {};
      if (typeof props.ManagedPolicyName === 'string') body.name = props.ManagedPolicyName;
      if (policy !== undefined) body.policy = policy;
      add('aws_iam_policy', id, body, cond, res.line);
      return;
    }

    case 'AWS::IAM::Policy': {
      const policy = stringifyPolicy(props.PolicyDocument);
      const body: Record<string, unknown> = {};
      if (typeof props.PolicyName === 'string') body.name = props.PolicyName;
      if (policy !== undefined) body.policy = policy;
      add('aws_iam_role_policy', id, body, cond, res.line);
      return;
    }

    case 'AWS::IAM::Role':
      normaliseInlinePolicies(res, props, 'aws_iam_role_policy', add);
      return;
    case 'AWS::IAM::User':
      normaliseInlinePolicies(res, props, 'aws_iam_user_policy', add);
      return;
    case 'AWS::IAM::Group':
      normaliseInlinePolicies(res, props, 'aws_iam_group_policy', add);
      return;

    case 'AWS::CloudFormation::Stack': {
      // A nested stack is CFN's module call: TemplateURL plays `source` (an
      // https:// URL is "remote" exactly like a registry/git module source),
      // and Parameters play the module inputs - snake_cased so the
      // Bedrock-logging input-key detection matches.
      const body: Record<string, unknown> = {};
      if (typeof props.TemplateURL === 'string') body.source = props.TemplateURL;
      const params = props.Parameters;
      if (params !== null && typeof params === 'object' && !Array.isArray(params)) {
        for (const [k, v] of Object.entries(params as Record<string, unknown>)) {
          body[pascalToSnake(k)] = v;
        }
      }
      moduleBlocks[res.logicalId] = [body];
      return;
    }

    default: {
      const tfType = SNAKE_CASE_BODY_TYPES[res.cfnType];
      if (tfType) {
        add(tfType, id, snakeKeysDeep(props) as Record<string, unknown>, cond, res.line);
      }
      // Unmapped types (Lambda functions, queues, ...) are outside every
      // rule's scope - they are simply not represented.
      return;
    }
  }

  // helper closure used above
  function normaliseS3Bucket(
    r: CfnParsedResource,
    translatedProps: Record<string, unknown>,
    addFn: AddFn,
  ): void {
    const p = snakeKeysDeep(translatedProps) as Record<string, unknown>;
    const bucketBody: Record<string, unknown> = { ...p };
    if (bucketBody.bucket_name !== undefined) {
      bucketBody.bucket = bucketBody.bucket_name;
      delete bucketBody.bucket_name;
    }
    addFn('aws_s3_bucket', r.logicalId, bucketBody, r.condition, r.line);

    // Terraform splits encryption / versioning / lifecycle / object-lock into
    // companion resources; the rules look for those. Synthesize them from the
    // inline CFN blocks, wired back to the bucket by reference so the existing
    // bucket-matching (literal name or resource address) works unchanged.
    const bucketRef = `\${aws_s3_bucket.${r.logicalId}.id}`;

    const sse = pickArray(p, 'bucket_encryption', 'server_side_encryption_configuration');
    if (sse.length > 0) {
      const rules = sse.map((entry) => {
        const e = (entry ?? {}) as Record<string, unknown>;
        const out: Record<string, unknown> = {
          apply_server_side_encryption_by_default: e.server_side_encryption_by_default ?? {},
        };
        if (e.bucket_key_enabled !== undefined) out.bucket_key_enabled = e.bucket_key_enabled;
        return out;
      });
      addFn(
        'aws_s3_bucket_server_side_encryption_configuration',
        r.logicalId,
        { bucket: bucketRef, rule: rules },
        r.condition,
        propLineOf(r, 'BucketEncryption'),
      );
    }

    const versioning = p.versioning_configuration;
    if (versioning !== null && typeof versioning === 'object') {
      addFn(
        'aws_s3_bucket_versioning',
        r.logicalId,
        { bucket: bucketRef, versioning_configuration: versioning },
        r.condition,
        propLineOf(r, 'VersioningConfiguration'),
      );
    }

    const lifecycleRules = pickArray(p, 'lifecycle_configuration', 'rules');
    if (lifecycleRules.length > 0) {
      const rules = lifecycleRules.map((entry) => {
        const e = { ...((entry ?? {}) as Record<string, unknown>) };
        if (e.expiration_in_days !== undefined) {
          e.expiration = [{ days: e.expiration_in_days }];
          delete e.expiration_in_days;
        } else if (e.expiration_date !== undefined) {
          e.expiration = [{ date: e.expiration_date }];
          delete e.expiration_date;
        }
        return e;
      });
      addFn(
        'aws_s3_bucket_lifecycle_configuration',
        r.logicalId,
        { bucket: bucketRef, rule: rules },
        r.condition,
        propLineOf(r, 'LifecycleConfiguration'),
      );
    }

    if (p.object_lock_enabled === true || (p.object_lock_configuration !== null && typeof p.object_lock_configuration === 'object')) {
      addFn(
        'aws_s3_bucket_object_lock_configuration',
        r.logicalId,
        { bucket: bucketRef },
        r.condition,
        propLineOf(r, 'ObjectLockConfiguration') ?? propLineOf(r, 'ObjectLockEnabled'),
      );
    }
  }

  function normaliseInlinePolicies(
    r: CfnParsedResource,
    translatedProps: Record<string, unknown>,
    tfType: string,
    addFn: AddFn,
  ): void {
    const policies = translatedProps.Policies;
    if (!Array.isArray(policies)) return;
    policies.forEach((entry, i) => {
      if (entry === null || typeof entry !== 'object') return;
      const e = entry as Record<string, unknown>;
      const policy = stringifyPolicy(e.PolicyDocument);
      if (policy === undefined) return;
      const suffix =
        typeof e.PolicyName === 'string' && !e.PolicyName.includes('${')
          ? e.PolicyName
          : String(i);
      const name = policies.length === 1 ? r.logicalId : `${r.logicalId}_${suffix}`;
      addFn(tfType, name, { policy }, r.condition, r.line);
    });
  }

  function propLineOf(r: CfnParsedResource, key: string): number | undefined {
    return r.propertyLines[key] ?? r.line;
  }
}

/**
 * Serialise an IAM policy document to the JSON string Terraform's inline
 * `policy` attribute carries. Keys inside the document are IAM keys
 * (Statement / Action / Effect) and are deliberately NOT snake_cased.
 */
function stringifyPolicy(doc: unknown): string | undefined {
  if (doc === null || typeof doc !== 'object') return undefined;
  return JSON.stringify(doc);
}

function parametersToVariables(
  parameters: Record<string, Record<string, unknown>>,
): Record<string, Record<string, unknown>[]> {
  const out: Record<string, Record<string, unknown>[]> = {};
  for (const [name, decl] of Object.entries(parameters)) {
    const body: Record<string, unknown> = {};
    if (decl.Default !== undefined) {
      body.default =
        decl.Type === 'Number' && Number.isFinite(Number(decl.Default))
          ? Number(decl.Default)
          : decl.Default;
    }
    out[name] = [body];
  }
  return out;
}

/** Recursively snake_case object keys. Values (strings) are never touched. */
function snakeKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map((v) => snakeKeysDeep(v));
  if (value === null || typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[pascalToSnake(k)] = snakeKeysDeep(v);
  }
  return out;
}

function renameKey(obj: Record<string, unknown>, from: string, to: string): void {
  if (obj[from] !== undefined) {
    obj[to] = obj[from];
    delete obj[from];
  }
}

/** Read obj[a][b] tolerating object-or-array shapes; always returns an array. */
function pickArray(obj: Record<string, unknown>, a: string, b: string): unknown[] {
  const outer = obj[a];
  if (outer === null || typeof outer !== 'object') return [];
  const inner = Array.isArray(outer)
    ? (outer[0] as Record<string, unknown> | undefined)?.[b]
    : (outer as Record<string, unknown>)[b];
  if (inner === undefined || inner === null) return [];
  return Array.isArray(inner) ? inner : [inner];
}
