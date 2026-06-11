import * as path from 'path';
import { ParsedFile, PlanOverlay, PlanResource, ResolutionResult, UnresolvableReason } from './types';
import { getNestedValue } from './utils/resource-helpers';

const INTERP = /^\$\{([^}]+)\}$/;
// Accept optional `[...]` indexing on resource address so count/for_each
// modules resolve too: aws_s3_bucket.logs[0].id, aws_s3_bucket.logs["prod"].arn.
const AWS_RES_REF = /^(aws_[a-z0-9_]+)\.([a-z_][a-z0-9_-]*)(?:\[[^\]]+\])?\.(\w+)$/i;
// Captures the variable name plus any chained `.field` / `[N]` access so
// `var.config.bucket_name` and `var.zones[0]` both resolve. The captured group
// is used as the lookup key directly (plan overlay flattens with the same syntax).
const VAR_REF = /^var\.([a-z0-9_]+(?:\.[a-z0-9_]+|\[\d+\])*)$/i;
const LOCAL_REF = /^local\.([a-z0-9_]+)$/i;
const DATA_REF = /^data\.([a-z0-9_]+)\.([a-z0-9_]+)(?:\[[^\]]+\])?\.(\w+)$/i;
// Remote-state refs have an extra `.outputs.` segment that DATA_REF can't match.
const REMOTE_STATE_REF = /^data\.terraform_remote_state\.([a-z0-9_]+)\.outputs\.(\w+)$/i;
// Matches single- and nested-module output references, with optional `[...]`
// indexing on each module segment so count/for_each modules resolve too:
//   module.foo.bucket_id
//   module.foo[0].bucket_id
//   module.outer.module.inner.x
const MODULE_REF = /^(?:module\.[a-z0-9_]+(?:\[[^\]]+\])?\.)+\w+$/i;

// CFN sentinel slug -> UnresolvableReason. 'complex' reuses the TF
// complex-interpolation reason (an Fn::Join/FindInMap that mixes static and
// dynamic pieces is the same situation as a composite TF interpolation).
const CFN_SENTINEL_REASONS: Record<string, UnresolvableReason> = {
  'import-value': 'cfn-import-value',
  'dynamic-reference': 'cfn-dynamic-reference',
  'pseudo-parameter': 'cfn-pseudo-parameter',
  'fn-not-static': 'cfn-fn-not-static',
  complex: 'complex-interpolation',
};

/**
 * Resolve a Terraform expression into one of three outcomes:
 *   - literal:      a concrete string value we can compare against
 *   - address:      a resource address (used when the literal name uses interpolation)
 *   - unresolvable: needs runtime data (var with no default, SSM, module output, etc.)
 *
 * Returns undefined only when expr is not a string.
 *
 * When `overlay` is provided, plan-resolved values take precedence over static
 * HCL resolution, except when the plan itself reports the value is unknown
 * (`after_unknown`) or sensitive (`after_sensitive`) - those cases return
 * INCONCLUSIVE with a precise reason rather than a fabricated literal.
 */
export function resolveExpression(
  expr: unknown,
  files: ParsedFile[],
  sourceField = 'unknown',
  sourceFilePath?: string,
  overlay?: PlanOverlay,
): ResolutionResult | undefined {
  if (typeof expr !== 'string') return undefined;

  // Pure literal - no interpolation, no bare ref syntax
  if (!expr.includes('${') && !looksLikeBareRef(expr)) {
    return { kind: 'literal', value: expr };
  }

  // Composite interpolation like "logs-${var.env}" or "${var.a}-${var.b}"
  const interpMatch = expr.match(INTERP);
  if (!interpMatch && expr.includes('${')) {
    return { kind: 'unresolvable', expression: expr, reason: 'complex-interpolation', sourceField };
  }

  const inner = interpMatch ? interpMatch[1] : expr;

  // CFN normaliser sentinel: ${cfn:<reason-slug>:<detail>} marks a value only
  // CloudFormation can resolve at deploy time (Fn::ImportValue, dynamic
  // references, pseudo parameters, non-static intrinsics). Mapped to a precise
  // reason so findings explain the CFN-specific cause. Never produced by
  // Terraform input, so this match cannot shadow a real TF expression.
  const cfnMatch = inner.match(/^cfn:([a-z-]+):/);
  if (cfnMatch) {
    const reason = CFN_SENTINEL_REASONS[cfnMatch[1]] ?? 'unknown-format';
    return { kind: 'unresolvable', expression: expr, reason, sourceField };
  }

  // aws_<type>.<name>.<attr>
  const awsMatch = inner.match(AWS_RES_REF);
  if (awsMatch) {
    const [, resourceType, resourceName, attribute] = awsMatch;
    if (overlay) {
      const overlayResult = lookupOverlayResource(
        `${resourceType}.${resourceName}`,
        attribute,
        sourceField,
        expr,
        overlay,
      );
      if (overlayResult) {
        // A concrete plan value is the most precise answer - prefer it.
        if (overlayResult.kind === 'literal') return overlayResult;
        // Otherwise the plan only reports that the *value* is computed-at-apply
        // (after_unknown) or sensitive - it has not changed *which* resource this
        // reference points at. When that resource is actually declared in the
        // scanned HCL we trust the HCL-derived identity (its address) rather than
        // degrading to INCONCLUSIVE, so address-based matching (log bucket / log
        // group) works under --plan exactly as it does for a source-only scan.
        // With no HCL to anchor on, keep the plan's honest unknown/sensitive
        // verdict. See CLAUDE.md "HCL-anchored resolution".
        if (awsResourceDeclared(resourceType, resourceName, files)) {
          const staticResult = resolveAwsRef(resourceType, resourceName, attribute, files);
          if (staticResult.kind === 'address') return staticResult;
        }
        return overlayResult;
      }
    }
    return resolveAwsRef(resourceType, resourceName, attribute, files);
  }

  // var.X - overlay first (concrete value supplied via -var or tfvars),
  // then same-module HCL default.
  const varMatch = inner.match(VAR_REF);
  if (varMatch) {
    if (overlay) {
      const v = overlay.variables.get(varMatch[1]);
      if (v !== undefined) return { kind: 'literal', value: String(v) };
    }
    const value = resolveVariableDefault(varMatch[1], files, sourceFilePath);
    if (value !== undefined) return { kind: 'literal', value };
    return { kind: 'unresolvable', expression: expr, reason: 'var-no-default', sourceField };
  }

  // local.X - locals are never in the plan overlay (they collapse into the
  // resources that consume them). Static-only.
  const localMatch = inner.match(LOCAL_REF);
  if (localMatch) {
    const value = resolveLocal(localMatch[1], files, sourceFilePath);
    if (value !== undefined) return { kind: 'literal', value };
    return { kind: 'unresolvable', expression: expr, reason: 'local-not-literal', sourceField };
  }

  // data.terraform_remote_state.<name>.outputs.<key> - the 5-segment form that
  // DATA_REF cannot match. Plan resolves these when the backend was reachable;
  // unreachable is a platform-team concern, not user-fixable, so it stays
  // INCONCLUSIVE even under --plan --strict-account-logging.
  const remoteStateMatch = inner.match(REMOTE_STATE_REF);
  if (remoteStateMatch) {
    const [, remoteStateName, outputKey] = remoteStateMatch;
    if (overlay) {
      const key = `data.terraform_remote_state.${remoteStateName}`;
      const planResource = overlay.resources.get(key);
      if (planResource) {
        const nestedPath = `outputs.${outputKey}`;
        if (planResource.unknownPaths.has(nestedPath) || planResource.unknownPaths.has('outputs')) {
          return { kind: 'unresolvable', expression: expr, reason: 'plan-known-after-apply', sourceField };
        }
        if (planResource.sensitivePaths.has(nestedPath) || planResource.sensitivePaths.has('outputs')) {
          return { kind: 'unresolvable', expression: expr, reason: 'plan-sensitive-redacted', sourceField };
        }
        const outputs = planResource.values['outputs'];
        if (outputs && typeof outputs === 'object') {
          const value = (outputs as Record<string, unknown>)[outputKey];
          if (typeof value === 'string') {
            if (value === '(sensitive value)') {
              return { kind: 'unresolvable', expression: expr, reason: 'plan-sensitive-redacted', sourceField };
            }
            return { kind: 'literal', value };
          }
          if (typeof value === 'number' || typeof value === 'boolean') return { kind: 'literal', value: String(value) };
        }
      }
      return { kind: 'unresolvable', expression: expr, reason: 'plan-remote-state-unreachable', sourceField };
    }
    return { kind: 'unresolvable', expression: expr, reason: 'data-source-other', sourceField };
  }

  // data.<type>.<name>.<attr> - plan resolves these when the data source
  // produced concrete attributes; otherwise stays unresolvable.
  const dataMatch = inner.match(DATA_REF);
  if (dataMatch) {
    const [, dataType, dataName, attribute] = dataMatch;
    if (overlay) {
      const overlayResult = lookupOverlayResource(
        `data.${dataType}.${dataName}`,
        attribute,
        sourceField,
        expr,
        overlay,
      );
      if (overlayResult) return overlayResult;
    }
    const reason: UnresolvableReason =
      dataType === 'aws_ssm_parameter' ? 'data-source-ssm' : 'data-source-other';
    return { kind: 'unresolvable', expression: expr, reason, sourceField };
  }

  // module.<name>.<output> (single- or nested-module). Plan-resolved outputs
  // win over the generic unresolvable, mirroring how aws_/data_/var refs are
  // promoted to literals when planned_values carries the concrete value.
  if (MODULE_REF.test(inner)) {
    if (overlay) {
      // Strip `[...]` so refs to count/for_each module instances find the
      // first-write-wins entry the parser captured under the normalised key.
      const key = inner.replace(/\[[^\]]*\]/g, '');
      const out = overlay.outputs.get(key);
      if (out) {
        if (out.sensitive) {
          return { kind: 'unresolvable', expression: expr, reason: 'plan-sensitive-redacted', sourceField };
        }
        return { kind: 'literal', value: String(out.value) };
      }
    }
    return { kind: 'unresolvable', expression: expr, reason: 'module-output', sourceField };
  }

  return { kind: 'unresolvable', expression: expr, reason: 'unknown-format', sourceField };
}

function lookupOverlayResource(
  key: string,
  attribute: string,
  sourceField: string,
  expr: string,
  overlay: PlanOverlay,
): ResolutionResult | undefined {
  // Prefer the per-instance index when present so count/for_each plans don't
  // silently lose non-compliant instances behind a first-write-wins summary.
  // Falls back to the legacy summary map for overlays constructed without
  // the new index (e.g. older test fixtures) so existing callers keep working.
  const instances = overlay.instancesByNormalised?.get(key);
  if (instances && instances.length > 0) {
    return lookupAcrossInstances(instances, attribute, sourceField, expr);
  }
  const planResource = overlay.resources.get(key);
  if (!planResource) return undefined;
  return lookupAcrossInstances([planResource], attribute, sourceField, expr);
}

/**
 * Resolve `attribute` across N plan instances of the same normalised resource.
 *
 * Decision order (any-instance match wins for safety filters; agreement is
 * required for a concrete literal):
 *   1. any instance has unknown on the attribute  -> plan-known-after-apply
 *   2. any instance has sensitive on the attribute -> plan-sensitive-redacted
 *   3. all instances yield the *same* scalar      -> literal
 *   4. instances yield *different* scalars         -> plan-instances-divergent
 *   5. no instance yields a scalar                 -> undefined (fall through)
 *
 * Step 1/2 are conservative (over-mark): if instance [0] has a concrete value
 * and instance [1] is unknown, we still return INCONCLUSIVE for the un-indexed
 * reference rather than fabricate [0]'s value as the answer.
 */
function lookupAcrossInstances(
  instances: PlanResource[],
  attribute: string,
  sourceField: string,
  expr: string,
): ResolutionResult | undefined {
  for (const inst of instances) {
    const effectiveAttr = aliasAttribute(inst.type, attribute);
    if (
      inst.unknownPaths.has(attribute) ||
      inst.unknownPaths.has(effectiveAttr)
    ) {
      return {
        kind: 'unresolvable',
        expression: expr,
        reason: 'plan-known-after-apply',
        sourceField,
      };
    }
  }
  for (const inst of instances) {
    const effectiveAttr = aliasAttribute(inst.type, attribute);
    if (
      inst.sensitivePaths.has(attribute) ||
      inst.sensitivePaths.has(effectiveAttr)
    ) {
      return {
        kind: 'unresolvable',
        expression: expr,
        reason: 'plan-sensitive-redacted',
        sourceField,
      };
    }
  }

  const scalarValues = new Set<string>();
  let sensitiveSentinelSeen = false;
  for (const inst of instances) {
    const effectiveAttr = aliasAttribute(inst.type, attribute);
    const raw = getNestedValue(inst.values, effectiveAttr);
    if (typeof raw === 'string') {
      if (raw === '(sensitive value)') {
        sensitiveSentinelSeen = true;
        continue;
      }
      scalarValues.add(raw);
    } else if (typeof raw === 'number' || typeof raw === 'boolean') {
      scalarValues.add(String(raw));
    }
    // null / undefined / object: no scalar contribution from this instance.
  }

  if (sensitiveSentinelSeen) {
    return {
      kind: 'unresolvable',
      expression: expr,
      reason: 'plan-sensitive-redacted',
      sourceField,
    };
  }
  if (scalarValues.size === 1) {
    return { kind: 'literal', value: [...scalarValues][0] };
  }
  if (scalarValues.size > 1) {
    return {
      kind: 'unresolvable',
      expression: expr,
      reason: 'plan-instances-divergent',
      sourceField,
    };
  }
  return undefined;
}

function aliasAttribute(resourceType: string, attribute: string): string {
  if (resourceType === 'aws_s3_bucket' && (attribute === 'id' || attribute === 'arn')) {
    return 'bucket';
  }
  if (
    resourceType === 'aws_cloudwatch_log_group' &&
    (attribute === 'id' || attribute === 'arn')
  ) {
    return 'name';
  }
  return attribute;
}

function looksLikeBareRef(s: string): boolean {
  return AWS_RES_REF.test(s) || /^(var|local|data|module)\./.test(s);
}

function resolveAwsRef(
  resourceType: string,
  resourceName: string,
  attribute: string,
  files: ParsedFile[],
): ResolutionResult {
  for (const file of files) {
    const typeBlock = file.json.resource?.[resourceType];
    if (!typeBlock) continue;
    const bodies = typeBlock[resourceName];
    if (!bodies) continue;
    const body = Array.isArray(bodies) ? bodies[0] : bodies;

    if (resourceType === 'aws_s3_bucket' && (attribute === 'id' || attribute === 'arn' || attribute === 'bucket')) {
      const bucketName = getNestedValue(body, 'bucket');
      if (typeof bucketName === 'string' && !bucketName.includes('${')) {
        return { kind: 'literal', value: bucketName };
      }
      return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
    }

    if (resourceType === 'aws_cloudwatch_log_group' && (attribute === 'name' || attribute === 'id' || attribute === 'arn')) {
      const name = getNestedValue(body, 'name');
      if (typeof name === 'string' && !name.includes('${')) {
        return { kind: 'literal', value: name };
      }
      return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
    }

    const value = getNestedValue(body, attribute);
    if (typeof value === 'string') {
      if (!value.includes('${')) return { kind: 'literal', value };
      return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
    }
  }

  // Resource not present in scanned files - still return its address so downstream
  // matching by address can succeed if the resource is defined elsewhere.
  return { kind: 'address', value: `${resourceType}.${resourceName}`, resourceType, resourceName };
}

/**
 * True when `<resourceType>.<resourceName>` is declared in any scanned HCL file.
 * Used to decide whether an HCL-derived resource address is trustworthy enough
 * to override a plan's known-after-apply / sensitive verdict (the "anchor on HCL
 * only when it is accurate" rule).
 */
function awsResourceDeclared(
  resourceType: string,
  resourceName: string,
  files: ParsedFile[],
): boolean {
  for (const file of files) {
    const typeBlock = file.json.resource?.[resourceType];
    if (typeBlock && typeBlock[resourceName] !== undefined) return true;
  }
  return false;
}

/**
 * Resolve a `var.X` or `local.X` reference to its underlying scalar value
 * (number, boolean, or literal string) by reading the variable default or the
 * locals block, scoped to the same module directory as `sourceFilePath`.
 *
 * When `overlay` is supplied, plan-resolved variable values win over HCL
 * defaults. Used for fields hcl2json emits as numbers/booleans
 * (`retention_in_days = var.log_retention_days`).
 *
 * Returns undefined when the expression is not a simple var/local ref or when
 * the underlying default is itself an expression / not present.
 */
export function resolveScalarReference(
  expr: unknown,
  files: ParsedFile[],
  sourceFilePath?: string,
  overlay?: PlanOverlay,
): { kind: 'literal'; value: string | number | boolean } | undefined {
  if (typeof expr !== 'string') return undefined;

  const interpMatch = expr.match(INTERP);
  if (!interpMatch && expr.includes('${')) return undefined;
  const inner = interpMatch ? interpMatch[1] : expr;

  const varMatch = inner.match(VAR_REF);
  if (varMatch) {
    if (overlay) {
      const v = overlay.variables.get(varMatch[1]);
      if (v !== undefined) return { kind: 'literal', value: v };
    }
    const value = readVariableScalarDefault(varMatch[1], files, sourceFilePath);
    if (value !== undefined) return { kind: 'literal', value };
    return undefined;
  }

  const localMatch = inner.match(LOCAL_REF);
  if (localMatch) {
    const value = readLocalScalar(localMatch[1], files, sourceFilePath);
    if (value !== undefined) return { kind: 'literal', value };
    return undefined;
  }

  return undefined;
}

/**
 * Resolve an expression, with a fallback that looks up the containing
 * resource's plan-resolved attribute when static resolution gives back
 * `unresolvable` (complex-interpolation, var-no-default with no overlay var,
 * local-not-literal).
 *
 * Use this from callers (e.g. extractBucket) that know which concrete
 * resource attribute the expression eventually populates. The fallback reads
 * `overlay.resources[containingAddress].values[attributePath]` - a real
 * post-resolution value - so it cannot fabricate a wrong literal.
 *
 * Unknown/sensitive filters from the overlay still apply: a plan that marks
 * the attribute computed-at-apply-time returns INCONCLUSIVE with
 * `plan-known-after-apply`, not the raw null.
 */
export function resolveOrPlanFallback(
  expr: unknown,
  containingAddress: string,
  attributePath: string,
  files: ParsedFile[],
  sourceField: string,
  sourceFilePath?: string,
  overlay?: PlanOverlay,
): ResolutionResult | undefined {
  const direct = resolveExpression(expr, files, sourceField, sourceFilePath, overlay);
  if (!direct) return undefined;
  if (direct.kind !== 'unresolvable') return direct;
  if (!overlay) return direct;

  const fallback = lookupOverlayResource(
    containingAddress,
    attributePath,
    sourceField,
    typeof expr === 'string' ? expr : String(expr),
    overlay,
  );
  if (fallback) return fallback;
  return direct;
}

function readVariableScalarDefault(
  pathExpr: string,
  files: ParsedFile[],
  sourceFilePath?: string,
): string | number | boolean | undefined {
  const segments = parseVarPath(pathExpr);
  if (segments.length === 0) return undefined;
  const [name, ...rest] = segments;
  if (typeof name !== 'string') return undefined;
  const sourceDir = sourceFilePath ? path.dirname(sourceFilePath) : undefined;
  for (const file of files) {
    if (sourceDir && path.dirname(file.filePath) !== sourceDir) continue;
    const variables = file.json.variable;
    if (!variables) continue;
    const block = variables[name];
    if (!block) continue;
    const body = Array.isArray(block) ? block[0] : block;
    const def = (body as Record<string, unknown> | undefined)?.default;
    if (def === undefined) continue;
    const value = navigateVariablePath(def, rest);
    if (typeof value === 'number' || typeof value === 'boolean') return value;
    if (typeof value === 'string' && !value.includes('${') && !looksLikeBareRef(value)) return value;
  }
  return undefined;
}

function readLocalScalar(
  name: string,
  files: ParsedFile[],
  sourceFilePath?: string,
): string | number | boolean | undefined {
  const sourceDir = sourceFilePath ? path.dirname(sourceFilePath) : undefined;
  for (const file of files) {
    if (sourceDir && path.dirname(file.filePath) !== sourceDir) continue;
    const localsBlocks = file.json.locals;
    if (!Array.isArray(localsBlocks)) continue;
    for (const block of localsBlocks) {
      if (typeof block !== 'object' || block === null) continue;
      const value = (block as Record<string, unknown>)[name];
      if (typeof value === 'number' || typeof value === 'boolean') return value;
      if (typeof value === 'string' && !value.includes('${') && !looksLikeBareRef(value)) return value;
    }
  }
  return undefined;
}

function resolveVariableDefault(
  pathExpr: string,
  files: ParsedFile[],
  sourceFilePath?: string,
): string | undefined {
  const segments = parseVarPath(pathExpr);
  if (segments.length === 0) return undefined;
  const [name, ...rest] = segments;
  if (typeof name !== 'string') return undefined;
  const sourceDir = sourceFilePath ? path.dirname(sourceFilePath) : undefined;
  for (const file of files) {
    if (sourceDir && path.dirname(file.filePath) !== sourceDir) continue;
    const variables = file.json.variable;
    if (!variables) continue;
    const block = variables[name];
    if (!block) continue;
    const body = Array.isArray(block) ? block[0] : block;
    const def = (body as Record<string, unknown> | undefined)?.default;
    if (def === undefined) continue;
    const value = navigateVariablePath(def, rest);
    if (typeof value === 'string' && !value.includes('${')) return value;
  }
  return undefined;
}

/**
 * Split a variable reference path like `config.s3.bucket_name` or
 * `zones[0].name` into segments. Numeric brackets become numbers; everything
 * else is a string key. Returns [] if the input is malformed.
 */
function parseVarPath(pathExpr: string): Array<string | number> {
  const segments: Array<string | number> = [];
  let current = '';
  let i = 0;
  while (i < pathExpr.length) {
    const c = pathExpr[i];
    if (c === '.') {
      if (current) {
        segments.push(current);
        current = '';
      }
      i++;
    } else if (c === '[') {
      if (current) {
        segments.push(current);
        current = '';
      }
      const end = pathExpr.indexOf(']', i);
      if (end === -1) return [];
      const idx = Number(pathExpr.slice(i + 1, end));
      if (!Number.isInteger(idx) || idx < 0) return [];
      segments.push(idx);
      i = end + 1;
    } else {
      current += c;
      i++;
    }
  }
  if (current) segments.push(current);
  return segments;
}

/**
 * Walk a parsed-HCL value following a sequence of object keys and list indices.
 * Auto-unwraps single-element arrays at each step because hcl2json wraps
 * `default = { ... }` as a one-element array around the object body.
 */
function navigateVariablePath(root: unknown, segments: Array<string | number>): unknown {
  let value: unknown = root;
  for (const seg of segments) {
    if (value === null || value === undefined) return undefined;
    if (Array.isArray(value) && value.length === 1 && typeof seg !== 'number') {
      value = value[0];
    }
    if (typeof seg === 'number') {
      if (!Array.isArray(value)) return undefined;
      value = value[seg];
    } else {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined;
      value = (value as Record<string, unknown>)[seg];
    }
  }
  if (Array.isArray(value) && value.length === 1) value = value[0];
  return value;
}

function resolveLocal(
  name: string,
  files: ParsedFile[],
  sourceFilePath?: string,
): string | undefined {
  const sourceDir = sourceFilePath ? path.dirname(sourceFilePath) : undefined;
  for (const file of files) {
    if (sourceDir && path.dirname(file.filePath) !== sourceDir) continue;
    const localsBlocks = file.json.locals;
    if (!Array.isArray(localsBlocks)) continue;
    for (const block of localsBlocks) {
      if (typeof block !== 'object' || block === null) continue;
      const value = (block as Record<string, unknown>)[name];
      if (typeof value === 'string' && !value.includes('${')) return value;
    }
  }
  return undefined;
}

/**
 * Human-readable explanation for an UnresolvableReason. Used in finding messages.
 */
export function explainReason(reason: UnresolvableReason): string {
  switch (reason) {
    case 'var-no-default':
      return 'Terraform variable has no static default - value is supplied at apply time.';
    case 'local-not-literal':
      return 'local value is not a static string literal.';
    case 'data-source-ssm':
      return 'value is fetched from AWS SSM Parameter Store at apply time.';
    case 'data-source-other':
      return 'value is fetched from a Terraform data source at apply time.';
    case 'module-output':
      return 'value comes from a module output and is not visible to source-level scanning.';
    case 'complex-interpolation':
      return 'expression combines multiple references - cannot determine final value statically.';
    case 'unknown-format':
      return 'expression is not in a recognized Terraform reference form.';
    case 'plan-known-after-apply':
      return 'plan marks this attribute as computed at apply time (after_unknown).';
    case 'plan-sensitive-redacted':
      return 'plan marks this attribute as sensitive - the value is redacted in the plan JSON.';
    case 'plan-deferred-data-source':
      return 'data source could not be evaluated at plan time (depends on a not-yet-created resource).';
    case 'plan-remote-state-unreachable':
      return 'terraform_remote_state backend was unreachable at plan time.';
    case 'plan-instances-divergent':
      return 'plan contains multiple instances of this resource with differing values for the referenced attribute - reference an explicit index (e.g. `aws_X.y[0]`) or restructure the expression.';
    case 'cfn-import-value':
      return 'value is imported from another CloudFormation stack (Fn::ImportValue) and is not visible to source-level scanning.';
    case 'cfn-dynamic-reference':
      return 'value is fetched from SSM Parameter Store / Secrets Manager at deploy time via a CloudFormation dynamic reference.';
    case 'cfn-pseudo-parameter':
      return 'value depends on a CloudFormation pseudo parameter (AWS::Region, AWS::AccountId, ...) resolved at deploy time.';
    case 'cfn-fn-not-static':
      return 'value is built by a CloudFormation intrinsic function that cannot be evaluated statically.';
    case 'cfn-condition-gated':
      return 'resource is created conditionally (CloudFormation Condition); static scanning cannot determine whether it will exist at deploy time.';
  }
}
