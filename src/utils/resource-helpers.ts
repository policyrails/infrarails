import * as path from 'path';
import { Finding, ParsedFile, PlanOverlay, PlanResource, ScanRule, UnresolvedRef } from '../types';
import { explainReason, resolveExpression } from '../resolver';

/**
 * Build an INCONCLUSIVE finding for a rule that depends on a Bedrock-logging
 * reference we could not resolve statically (var with no default, SSM, module
 * output, etc.). Used to make the scanner honest when source-only scanning
 * cannot verify the check - instead of silently SKIP-ing.
 */
export function inconclusiveFromUnresolved(
  rule: ScanRule,
  ref: UnresolvedRef,
  scope: 'bucket' | 'log group',
): Finding {
  return {
    ruleId: rule.id,
    status: 'INCONCLUSIVE',
    filePath: '',
    description: `Cannot verify ${rule.id} for ${scope} reference \`${ref.expression}\` (at ${ref.sourceField}): ${explainReason(ref.reason)}`,
    remediation:
      'Either reference the resource via `aws_s3_bucket.<name>.id` / `aws_cloudwatch_log_group.<name>.name` so static scanning can follow it, or run infrarails against `terraform show -json plan.json` for full apply-time resolution.',
    regulatoryReference: rule.regulatoryReference,
    nistReference: rule.nistReference,
    isoReference: rule.isoReference,
    unresolvedReason: ref.reason,
  };
}

export interface FoundResource {
  name: string;
  body: Record<string, unknown>;
  filePath: string;
  rawHcl: string;
  /**
   * 'hcl' for resources discovered from scanned HCL files (default).
   * 'plan' for resources surfaced by the plan overlay - typically buried
   * inside remote modules with no on-disk HCL in the scanned repo.
   */
  source: 'hcl' | 'plan';
  /**
   * Fully-qualified plan address (e.g. `module.logging.aws_X.this`) when
   * source is 'plan'. Undefined for HCL-sourced resources.
   */
  address?: string;
  /**
   * For a module-buried plan instance folded with an on-disk HCL block, the HCL
   * body of that block. Lets value extraction fall back to the HCL reference
   * when the plan dropped an attribute it marked computed-at-apply-time (e.g. a
   * bucket name built from the account id is absent from planned_values). The
   * HCL reference still names the resource, so we can anchor on it. Undefined
   * for HCL-sourced and genuinely plan-only (remote-module) resources.
   */
  hclBody?: Record<string, unknown>;
}

/**
 * Find all resources of a given type across all parsed files - and, when
 * `overlay` is provided, reconcile them against the plan so every logical
 * resource is returned exactly once.
 *
 * Reconciliation (one entry per logical resource, never a duplicate):
 *   - Each plan resource is keyed by its *index-stripped* address, so the
 *     several instances of a count/for_each resource collapse to one entry
 *     while distinct module calls (`module.a.x` vs `module.b.x`) stay separate.
 *   - A root-level plan resource declared in HCL is dropped in favour of the
 *     HCL block (which carries a real source line).
 *   - A module-buried plan resource that matches an on-disk HCL block (a local
 *     module walked from the scan root) is *folded* together with it: the plan
 *     instance is kept - it carries the resolved body and the full address the
 *     guardrail graph needs - but it borrows the HCL block's file path and raw
 *     source so the finding keeps a real file:line attribution, and that exact
 *     HCL block is dropped so the resource is not emitted twice. The match is
 *     by module *directory* (resolved from local module sources), never by leaf
 *     name, so two resources that share a name across modules (the ubiquitous
 *     `this`) are not conflated. See pickHclForInstance / buildDirPlanPathIndex.
 *   - A genuinely plan-only resource (e.g. buried in a remote module not on
 *     disk) has no HCL match and is returned as-is.
 *
 * Invariant (CLAUDE.md "HCL-anchored resolution"): supplying a plan never
 * removes a resource a source-only scan would have seen. Only the *exact* HCL
 * block consumed by a fold is dropped; an unrelated same-named block is kept.
 *
 * `filePath` on a plan-only entry is `plan:<full-plan-address>` so findings
 * stay attributable in audit reports even when no HCL line exists.
 */
export function findResources(
  files: ParsedFile[],
  resourceType: string,
  overlay?: PlanOverlay,
): FoundResource[] {
  const results: FoundResource[] = [];
  const hclAddresses = new Set<string>();
  // Leaf name -> every HCL block with that name. A list (not a single entry)
  // because the same leaf name legitimately recurs across modules (the `this`
  // convention); collapsing to one would lose blocks and misattribute folds.
  const hclByName = new Map<string, FoundResource[]>();

  for (const file of files) {
    const typeBlock = file.json.resource?.[resourceType];
    if (!typeBlock) continue;

    for (const [name, bodies] of Object.entries(typeBlock)) {
      const body = Array.isArray(bodies) ? bodies[0] : bodies;
      const entry: FoundResource = {
        name,
        body: body as Record<string, unknown>,
        filePath: file.filePath,
        rawHcl: file.rawHcl,
        source: 'hcl',
      };
      results.push(entry);
      hclAddresses.add(`${resourceType}.${name}`);
      const list = hclByName.get(name);
      if (list) list.push(entry);
      else hclByName.set(name, [entry]);
    }
  }

  if (!overlay) return results;

  // count/for_each yield multiple PlanResource records under one normalised
  // key; iterate every instance so we can collapse them deliberately below.
  const instanceLists = overlay.instancesByNormalised
    ? Array.from(overlay.instancesByNormalised.values())
    : [Array.from(overlay.resources.values())];

  // Map each scanned file's directory to the Terraform module path it
  // represents, so a module-buried plan instance can be paired with the
  // *correct* on-disk HCL block. Leaf-name matching alone conflates distinct
  // resources that share a name across modules (the ubiquitous `this`).
  const dirPlanPath = buildDirPlanPathIndex(files);

  // Leaf names of root-level (non-module) plan resources of this type. A root
  // resource's HCL block must never be folded into a module instance that
  // merely shares its leaf name. Pre-computed because root and module
  // instances are interleaved across the lists.
  const rootPlanNames = new Set<string>();
  for (const list of instanceLists) {
    for (const planRes of list) {
      if (planRes.type === resourceType && !planRes.address.startsWith('module.')) {
        rootPlanNames.add(planRes.name);
      }
    }
  }

  const seenInstances = new Set<string>(); // index-stripped full addresses
  const foldedHcl = new Set<FoundResource>(); // the exact HCL blocks consumed by a fold

  for (const list of instanceLists) {
    for (const planRes of list) {
      if (planRes.type !== resourceType) continue;
      // Collapse count/for_each (same address sans index) to one entry while
      // keeping distinct module calls (different module path) apart.
      const instanceKey = planRes.address.replace(/\[[^\]]*\]/g, '');
      if (seenInstances.has(instanceKey)) continue;
      seenInstances.add(instanceKey);

      const planEntry: FoundResource = {
        name: planRes.name,
        body: planRes.values as Record<string, unknown>,
        filePath: `plan:${planRes.address}`,
        rawHcl: '',
        source: 'plan',
        address: planRes.address,
      };

      if (!planRes.address.startsWith('module.')) {
        // A root resource declared in HCL wins (keeps its source line).
        if (hclAddresses.has(instanceKey)) continue;
        results.push(planEntry);
        continue;
      }

      // Module-buried instance. Fold it with the on-disk HCL block for *this*
      // instance (matched by module directory, not leaf name) so the finding
      // keeps a real file:line; that exact block is dropped below.
      const hcl = pickHclForInstance(
        planRes.address,
        planRes.type,
        planRes.name,
        hclByName,
        foldedHcl,
        dirPlanPath,
        rootPlanNames,
      );
      if (hcl) {
        planEntry.filePath = hcl.filePath;
        planEntry.rawHcl = hcl.rawHcl;
        planEntry.hclBody = hcl.body;
        foldedHcl.add(hcl);
      }
      results.push(planEntry);
    }
  }

  // Drop exactly the HCL blocks that were folded into a plan instance - nothing
  // else. Keying the drop on object identity (not leaf name) guarantees an
  // unrelated same-named resource is never removed: supplying a plan can never
  // make a resource disappear that a source-only scan would have seen.
  return foldedHcl.size === 0 ? results : results.filter((r) => !foldedHcl.has(r));
}

/**
 * Choose the on-disk HCL block that corresponds to one specific module-buried
 * plan instance. Pairing is by module *directory* (resolved from local module
 * sources), never by leaf name, so distinct same-named resources are not
 * conflated.
 *
 * Decision order:
 *   1. The candidate whose own module path equals the instance's module path
 *      (the precise, fully-wired case). Exactly one -> use it.
 *   2. Fallback for a local module scanned without its caller (its directory
 *      maps to '' because no `module {}` edge reaches it): a single, unclaimed
 *      candidate that is not a known root resource. This preserves the common
 *      "scan a module subtree directly" case.
 *   3. Otherwise undefined: leave the plan instance plan-only and drop nothing.
 *      A duplicate is acceptable; a wrong fold or a dropped resource is not.
 */
function pickHclForInstance(
  address: string,
  type: string,
  name: string,
  hclByName: Map<string, FoundResource[]>,
  foldedHcl: Set<FoundResource>,
  dirPlanPath: Map<string, string>,
  rootPlanNames: Set<string>,
): FoundResource | undefined {
  const candidates = (hclByName.get(name) ?? []).filter((c) => !foldedHcl.has(c));
  if (candidates.length === 0) return undefined;

  const idxStripped = address.replace(/\[[^\]]*\]/g, '');
  const suffix = `.${type}.${name}`;
  const modulePath = idxStripped.endsWith(suffix)
    ? idxStripped.slice(0, -suffix.length)
    : '';

  const planPathOf = (c: FoundResource): string =>
    dirPlanPath.get(path.resolve(path.dirname(c.filePath))) ?? '';

  const exact = candidates.filter((c) => planPathOf(c) === modulePath);
  if (exact.length === 1) return exact[0];
  if (exact.length > 1) return undefined; // genuinely ambiguous - do not guess

  // No directory-precise match. Fold only the unambiguous standalone case.
  if (
    candidates.length === 1 &&
    planPathOf(candidates[0]) === '' &&
    !rootPlanNames.has(name)
  ) {
    return candidates[0];
  }
  return undefined;
}

/**
 * Map each scanned file's directory (absolute) to the Terraform module path it
 * represents - `modules/eu` -> `module.eu`, nested -> `module.a.module.b` - by
 * walking local `module { source = "./..." }` declarations. A directory with no
 * incoming local-module edge maps to '' (the root module, or a standalone
 * module directory scanned without its caller). Remote-module sources have no
 * on-disk directory and never appear.
 */
function buildDirPlanPathIndex(files: ParsedFile[]): Map<string, string> {
  // childDir -> { parentDir, moduleCallName } for every local module block.
  type ModuleEdge = { parentDir: string; name: string };
  const parentEdge = new Map<string, ModuleEdge>();
  for (const file of files) {
    const moduleBlocks = file.json.module;
    if (!moduleBlocks) continue;
    const declaringDir = path.resolve(path.dirname(file.filePath));
    for (const [callName, bodies] of Object.entries(moduleBlocks)) {
      const body = Array.isArray(bodies) ? bodies[0] : bodies;
      const source = (body as Record<string, unknown>)?.source;
      if (typeof source !== 'string') continue;
      if (!source.startsWith('./') && !source.startsWith('../')) continue; // remote
      parentEdge.set(path.resolve(declaringDir, source), {
        parentDir: declaringDir,
        name: callName,
      });
    }
  }

  const planPathOf = (dir: string): string => {
    const parts: string[] = [];
    const guard = new Set<string>(); // cycle guard for pathological inputs
    let cur: string | undefined = dir;
    while (cur && parentEdge.has(cur) && !guard.has(cur)) {
      guard.add(cur);
      const edge: ModuleEdge = parentEdge.get(cur)!;
      parts.unshift(`module.${edge.name}`);
      cur = edge.parentDir;
    }
    return parts.join('.');
  };

  const out = new Map<string, string>();
  for (const file of files) {
    const dir = path.resolve(path.dirname(file.filePath));
    if (!out.has(dir)) out.set(dir, planPathOf(dir));
  }
  return out;
}

/**
 * Get a nested value from an HCL2JSON object, auto-unwrapping single-element arrays.
 * Path is dot-separated: "logging_config.s3_config.bucket_name"
 */
export function getNestedValue(obj: unknown, path: string): unknown {
  const parts = path.split('.');
  let current: unknown = obj;

  for (const part of parts) {
    if (current === null || current === undefined) return undefined;

    // Auto-unwrap single-element arrays
    if (Array.isArray(current) && current.length === 1) {
      current = current[0];
    }

    if (typeof current !== 'object' || current === null) return undefined;
    current = (current as Record<string, unknown>)[part];
  }

  // Final unwrap
  if (Array.isArray(current) && current.length === 1) {
    current = current[0];
  }

  return current;
}

/**
 * Check if a resource's bucket attribute matches one of the target bucket names.
 *
 * Targets may be:
 *   - A literal bucket name:                "my-log-bucket"
 *   - A fully-qualified resource address:   "aws_s3_bucket.logs"
 *     (used when the actual name contains unresolvable interpolations)
 *
 * If files are provided, also attempts to resolve variable/local references
 * in the bucket attribute (e.g., ${var.log_bucket}).
 */
export function matchesBucket(
  body: Record<string, unknown>,
  resourceName: string,
  targetBucketNames: string[],
  files?: ParsedFile[],
  overlay?: PlanOverlay,
): boolean {
  if (targetBucketNames.length === 0) return false;

  const bucket = getNestedValue(body, 'bucket');

  // Check the "bucket" attribute directly (literal name match)
  if (typeof bucket === 'string' && targetBucketNames.includes(bucket)) {
    return true;
  }

  // Check if the resource name itself matches any target literal
  if (targetBucketNames.includes(resourceName)) {
    return true;
  }

  // Check against fully-qualified address targets: "aws_s3_bucket.<resourceName>"
  if (targetBucketNames.includes(`aws_s3_bucket.${resourceName}`)) {
    return true;
  }

  // Check if the bucket attribute is a reference (e.g. "${aws_s3_bucket.logs.id}")
  // and one of the targets is that resource's address
  if (typeof bucket === 'string') {
    const refMatch = bucket.match(
      /^\$\{(aws_s3_bucket\.[a-z0-9_]+)\.[^}]+\}$|^(aws_s3_bucket\.[a-z0-9_]+)\.[a-z0-9_]+$/
    );
    if (refMatch) {
      const resourceAddr = refMatch[1] ?? refMatch[2];
      if (targetBucketNames.includes(resourceAddr)) return true;
    }
  }

  // If files provided, try resolving variable/local references. With an
  // overlay, this also picks up plan-resolved aws_s3_bucket.<name>.id ->
  // literal bucket names from remote modules and var-supplied values.
  if (files && typeof bucket === 'string') {
    const result = resolveExpression(bucket, files, 'bucket', undefined, overlay);
    if (result?.kind === 'literal' && targetBucketNames.includes(result.value)) {
      return true;
    }
    if (result?.kind === 'address' && targetBucketNames.includes(result.value)) {
      return true;
    }
  }

  return false;
}

/**
 * Detect module blocks whose source is a remote registry or git URL rather than
 * a local relative path (./... or ../...).
 *
 * Resources inside remote modules are never on disk during a source-only scan,
 * so infrarails cannot verify their compliance. Callers should emit INCONCLUSIVE.
 */
export function findRemoteModules(
  files: ParsedFile[],
): Array<{ name: string; source: string; filePath: string }> {
  const results: Array<{ name: string; source: string; filePath: string }> = [];

  for (const file of files) {
    const moduleBlocks = file.json.module;
    if (!moduleBlocks) continue;

    for (const [name, bodies] of Object.entries(moduleBlocks)) {
      const body = Array.isArray(bodies) ? bodies[0] : bodies;
      const source = (body as Record<string, unknown>)?.source;
      if (typeof source !== 'string') continue;
      if (!source.startsWith('./') && !source.startsWith('../')) {
        results.push({ name, source, filePath: file.filePath });
      }
    }
  }

  return results;
}

/**
 * Find the approximate line number of a resource definition in raw HCL.
 */
export function findResourceLine(rawHcl: string, resourceType: string, resourceName: string): number | undefined {
  const pattern = new RegExp(
    `^\\s*resource\\s+"${escapeRegex(resourceType)}"\\s+"${escapeRegex(resourceName)}"`,
    'm'
  );
  const match = rawHcl.match(pattern);
  if (!match || match.index === undefined) return undefined;

  const lineNumber = rawHcl.substring(0, match.index).split('\n').length;
  return lineNumber;
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---------------------------------------------------------------------------
// Bedrock detection - finite lists, no regex.
//
// All Bedrock-related detection uses explicit string lists. New AWS resource
// types, IAM actions, and VPC service names are added by appending to a list,
// not by tweaking a regex. This makes additions reviewable in a one-line diff
// and prevents accidental over-matching.
// ---------------------------------------------------------------------------

/**
 * Direct Bedrock infrastructure resource types - declaring any of these in
 * Terraform deploys Bedrock infra.
 *
 * Excludes aws_bedrock_model_invocation_logging_configuration: that is the
 * LOGGING config tracked separately in context.ts.
 *
 * Update this list when AWS provider releases new Bedrock resource types.
 * Source: https://registry.terraform.io/providers/hashicorp/aws/latest/docs
 */
export const BEDROCK_DIRECT_RESOURCE_TYPES: readonly string[] = [
  // Foundation / model lifecycle
  'aws_bedrock_custom_model',
  'aws_bedrock_guardrail',
  'aws_bedrock_guardrail_version',
  'aws_bedrock_inference_profile',
  'aws_bedrock_marketplace_model_endpoint',
  'aws_bedrock_provisioned_model_throughput',
  // Bedrock Agents
  'aws_bedrockagent_agent',
  'aws_bedrockagent_agent_action_group',
  'aws_bedrockagent_agent_alias',
  'aws_bedrockagent_agent_collaborator',
  'aws_bedrockagent_agent_knowledge_base_association',
  'aws_bedrockagent_data_source',
  'aws_bedrockagent_flow',
  'aws_bedrockagent_knowledge_base',
  'aws_bedrockagent_prompt',
  'aws_bedrockagent_prompt_version',
] as const;

/**
 * Read-only Bedrock data sources. Their presence indicates *intent* to use
 * Bedrock at runtime even when no aws_bedrock_* resource is declared
 * (e.g. a Lambda passes data.aws_bedrock_foundation_model.claude.id as an env var).
 */
export const BEDROCK_DATA_SOURCE_TYPES: readonly string[] = [
  'aws_bedrock_foundation_model',
  'aws_bedrock_foundation_models',
  'aws_bedrock_inference_profile',
  'aws_bedrock_inference_profiles',
] as const;

/**
 * Inline IAM policy resource types whose `policy` attribute is a JSON string.
 * Walked by findIamBedrockGrants to detect SDK-driven Bedrock usage.
 */
const INLINE_IAM_POLICY_RESOURCE_TYPES = [
  'aws_iam_policy',
  'aws_iam_role_policy',
  'aws_iam_user_policy',
  'aws_iam_group_policy',
] as const;

/**
 * IAM action strings that grant Bedrock access. Exact-string match against
 * `actions` (or `action`) entries in IAM policy documents and inline JSON
 * policies. The wildcard `bedrock:*` is included as a literal so we never
 * have to interpret patterns.
 *
 * Update when AWS adds new Bedrock IAM actions.
 */
export const BEDROCK_IAM_ACTIONS: readonly string[] = [
  'bedrock:Converse',
  'bedrock:ConverseStream',
  'bedrock:CreateModelInvocationJob',
  'bedrock:GetAsyncInvoke',
  'bedrock:InvokeAgent',
  'bedrock:InvokeFlow',
  'bedrock:InvokeInlineAgent',
  'bedrock:InvokeModel',
  'bedrock:InvokeModelWithResponseStream',
  'bedrock:ListAsyncInvokes',
  'bedrock:Retrieve',
  'bedrock:RetrieveAndGenerate',
  'bedrock:StartAsyncInvoke',
  'bedrock:*',
] as const;

/**
 * Trailing tokens for VPC endpoint service_name. The full string is
 * com.amazonaws.<region>.<service>; we compare on the suffix.
 */
export const BEDROCK_VPC_ENDPOINT_SUFFIXES: readonly string[] = [
  '.bedrock',
  '.bedrock-agent',
  '.bedrock-agent-runtime',
  '.bedrock-runtime',
] as const;

/**
 * Argument names commonly used to wire Bedrock-logging destinations through a
 * module call. Matched as keys (left side) of inputs in module bodies.
 */
export const BEDROCK_LOGGING_INPUT_KEYS: readonly string[] = [
  // Generic logging-destination inputs.
  'cloudwatch_log_group',
  'cloudwatch_log_group_arn',
  'cloudwatch_log_group_name',
  'log_bucket',
  'log_bucket_arn',
  'log_bucket_id',
  'log_bucket_name',
  'log_destination',
  'log_destination_arn',
  'logging_destination',
  // Bedrock-specific inputs.
  'bedrock_log_bucket',
  'bedrock_log_group',
  'bedrock_logging_bucket',
  'bedrock_logging_log_group',
  'bedrock_logging_role_arn',
  'embedding_data_delivery_enabled',
  'image_data_delivery_enabled',
  'invocation_logging',
  'model_invocation_logging',
  'text_data_delivery_enabled',
  'video_data_delivery_enabled',
] as const;

/**
 * Tokens that, when found in a module's local name (the X in `module "X"`),
 * indicate the module is in the Bedrock / GenAI scope.
 */
export const BEDROCK_MODULE_NAME_TOKENS: readonly string[] = [
  'ai_logging',
  'bedrock',
  'gen_ai',
  'genai',
  'invocation_logging',
  'llm',
  'model_invocation',
] as const;

/**
 * Conventional `terraform_remote_state` data-source names whose outputs hold
 * account-baseline / central-logging configuration.
 */
export const BASELINE_REMOTE_STATE_NAMES: readonly string[] = [
  'account_baseline',
  'audit',
  'audit_logging',
  'baseline',
  'central_logging',
  'compliance',
  'logging',
  'observability',
  'org_baseline',
  'platform',
  'security',
  'shared_services',
] as const;

/**
 * Find all direct-usage Bedrock resources. Returns a flat list of
 * `{ resourceAddress, type, name, filePath }`.
 */
export function findBedrockResources(
  files: ParsedFile[],
  overlay?: PlanOverlay,
): Array<{ resourceAddress: string; type: string; name: string; filePath: string }> {
  const results: Array<{ resourceAddress: string; type: string; name: string; filePath: string }> = [];
  for (const type of BEDROCK_DIRECT_RESOURCE_TYPES) {
    for (const r of findResources(files, type, overlay)) {
      results.push({ resourceAddress: `${type}.${r.name}`, type, name: r.name, filePath: r.filePath });
    }
  }
  return results;
}

/**
 * Find all Bedrock data-source references (data "aws_bedrock_foundation_model" "x" {}).
 */
export function findBedrockDataSources(
  files: ParsedFile[],
): Array<{ dataAddress: string; type: string; name: string; filePath: string }> {
  const results: Array<{ dataAddress: string; type: string; name: string; filePath: string }> = [];
  for (const file of files) {
    const dataBlocks = file.json.data;
    if (!dataBlocks) continue;
    for (const type of BEDROCK_DATA_SOURCE_TYPES) {
      const block = dataBlocks[type];
      if (!block) continue;
      for (const name of Object.keys(block)) {
        results.push({ dataAddress: `data.${type}.${name}`, type, name, filePath: file.filePath });
      }
    }
  }
  return results;
}

/**
 * Find IAM policies (data sources or inline) granting Bedrock actions.
 * Caller treats hits as INDIRECT Bedrock usage (SDK-driven workloads).
 *
 * For inline JSON policies that contain unparseable interpolations, returns
 * nothing for that resource - silent miss is preferable to false signal.
 */
export function findIamBedrockGrants(
  files: ParsedFile[],
): Array<{ resourceAddress: string; actions: string[]; filePath: string }> {
  const results: Array<{ resourceAddress: string; actions: string[]; filePath: string }> = [];

  // 1. data "aws_iam_policy_document" blocks
  for (const file of files) {
    const docs = file.json.data?.aws_iam_policy_document;
    if (!docs) continue;
    for (const [name, bodies] of Object.entries(docs)) {
      const body = Array.isArray(bodies) ? bodies[0] : bodies;
      const matched = collectBedrockActionsFromStatementBlocks(body);
      if (matched.length > 0) {
        results.push({
          resourceAddress: `data.aws_iam_policy_document.${name}`,
          actions: matched,
          filePath: file.filePath,
        });
      }
    }
  }

  // 2. Inline policy resources - `policy` attribute is a JSON string.
  for (const type of INLINE_IAM_POLICY_RESOURCE_TYPES) {
    for (const r of findResources(files, type)) {
      const policy = getNestedValue(r.body, 'policy');
      if (typeof policy !== 'string') continue;
      const matched = collectBedrockActionsFromJsonPolicy(policy);
      if (matched.length > 0) {
        results.push({
          resourceAddress: `${type}.${r.name}`,
          actions: matched,
          filePath: r.filePath,
        });
      }
    }
  }

  return results;
}

function collectBedrockActionsFromStatementBlocks(body: unknown): string[] {
  if (typeof body !== 'object' || body === null) return [];
  const stmtField = (body as Record<string, unknown>).statement;
  if (stmtField === undefined) return [];

  const statements: unknown[] = Array.isArray(stmtField) ? stmtField : [stmtField];
  const matched = new Set<string>();

  for (const stmt of statements) {
    if (typeof stmt !== 'object' || stmt === null) continue;
    const actionsField = (stmt as Record<string, unknown>).actions;
    const actionField = (stmt as Record<string, unknown>).action;

    const candidates: unknown[] = [];
    if (Array.isArray(actionsField)) candidates.push(...actionsField);
    else if (actionsField !== undefined) candidates.push(actionsField);
    if (Array.isArray(actionField)) candidates.push(...actionField);
    else if (actionField !== undefined) candidates.push(actionField);

    for (const a of candidates) {
      if (typeof a === 'string' && (BEDROCK_IAM_ACTIONS as readonly string[]).includes(a)) {
        matched.add(a);
      }
    }
  }

  return [...matched].sort();
}

function collectBedrockActionsFromJsonPolicy(policyJson: string): string[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(policyJson);
  } catch {
    return [];
  }
  if (typeof parsed !== 'object' || parsed === null) return [];
  const stmts = (parsed as Record<string, unknown>).Statement;
  const statements: unknown[] = Array.isArray(stmts) ? stmts : stmts !== undefined ? [stmts] : [];

  const matched = new Set<string>();
  for (const stmt of statements) {
    if (typeof stmt !== 'object' || stmt === null) continue;
    const actionField = (stmt as Record<string, unknown>).Action;
    const candidates: unknown[] = Array.isArray(actionField)
      ? actionField
      : actionField !== undefined
        ? [actionField]
        : [];
    for (const a of candidates) {
      if (typeof a === 'string' && (BEDROCK_IAM_ACTIONS as readonly string[]).includes(a)) {
        matched.add(a);
      }
    }
  }
  return [...matched].sort();
}

/**
 * Find aws_vpc_endpoint resources whose service_name targets a Bedrock service.
 * If service_name is interpolated (var/local), attempts to resolve it.
 */
export function findBedrockVpcEndpoints(
  files: ParsedFile[],
): Array<{ resourceAddress: string; serviceName: string; filePath: string }> {
  const results: Array<{ resourceAddress: string; serviceName: string; filePath: string }> = [];

  for (const r of findResources(files, 'aws_vpc_endpoint')) {
    const raw = getNestedValue(r.body, 'service_name');
    if (typeof raw !== 'string') continue;

    let resolved: string | undefined;
    if (matchesBedrockServiceSuffix(raw)) {
      resolved = raw;
    } else {
      const result = resolveExpression(raw, files, 'service_name', r.filePath);
      if (result?.kind === 'literal' && matchesBedrockServiceSuffix(result.value)) {
        resolved = result.value;
      }
    }
    if (resolved !== undefined) {
      results.push({
        resourceAddress: `aws_vpc_endpoint.${r.name}`,
        serviceName: resolved,
        filePath: r.filePath,
      });
    }
  }

  return results;
}

function matchesBedrockServiceSuffix(s: string): boolean {
  for (const suffix of BEDROCK_VPC_ENDPOINT_SUFFIXES) {
    if (s.endsWith(suffix)) return true;
  }
  return false;
}

/**
 * Find module calls (local or remote) that look Bedrock-logging-related -
 * either the local module name contains a Bedrock token, OR the module body
 * passes one of the BEDROCK_LOGGING_INPUT_KEYS as an input.
 *
 * Used by S-12.1.1 to emit INCONCLUSIVE rather than FAIL when Bedrock logging
 * is plausibly being configured externally to the scanned files.
 */
export function findBedrockRelatedModuleCalls(files: ParsedFile[]): Array<{
  name: string;
  source: string | undefined;
  isRemote: boolean;
  matchedTokens: string[];
  matchedInputKeys: string[];
  filePath: string;
}> {
  const results: Array<{
    name: string;
    source: string | undefined;
    isRemote: boolean;
    matchedTokens: string[];
    matchedInputKeys: string[];
    filePath: string;
  }> = [];

  for (const file of files) {
    const moduleBlocks = file.json.module;
    if (!moduleBlocks) continue;

    for (const [name, bodies] of Object.entries(moduleBlocks)) {
      const body = (Array.isArray(bodies) ? bodies[0] : bodies) as Record<string, unknown>;
      const sourceVal = body?.source;
      const source = typeof sourceVal === 'string' ? sourceVal : undefined;
      const isRemote =
        typeof source === 'string' && !source.startsWith('./') && !source.startsWith('../');

      const matchedTokens = matchModuleNameTokens(name);
      const matchedSourceTokens = source ? matchModuleNameTokens(source) : [];

      const inputKeys = body ? Object.keys(body) : [];
      const matchedInputKeys = inputKeys.filter((k) =>
        (BEDROCK_LOGGING_INPUT_KEYS as readonly string[]).includes(k),
      );

      if (
        matchedTokens.length === 0 &&
        matchedSourceTokens.length === 0 &&
        matchedInputKeys.length === 0
      ) {
        continue;
      }

      // Surface source-token matches via matchedTokens so callers (and the
      // remote-module wall) can describe *why* the module was flagged without
      // a new field on the result shape.
      const allTokens = Array.from(new Set([...matchedTokens, ...matchedSourceTokens]));

      results.push({
        name,
        source,
        isRemote,
        matchedTokens: allTokens,
        matchedInputKeys,
        filePath: file.filePath,
      });
    }
  }

  return results;
}

function matchModuleNameTokens(name: string): string[] {
  const normalized = name.toLowerCase();
  const matched: string[] = [];
  for (const token of BEDROCK_MODULE_NAME_TOKENS) {
    if (normalized.includes(token)) matched.push(token);
  }
  return matched;
}

/**
 * Find `data "terraform_remote_state" "X"` blocks where X looks like an
 * account-baseline / central-logging stack reference.
 */
export function findBaselineRemoteState(
  files: ParsedFile[],
): Array<{ dataAddress: string; name: string; matchedToken: string; filePath: string }> {
  const results: Array<{ dataAddress: string; name: string; matchedToken: string; filePath: string }> = [];

  for (const file of files) {
    const remoteStates = file.json.data?.terraform_remote_state;
    if (!remoteStates) continue;
    for (const name of Object.keys(remoteStates)) {
      const lower = name.toLowerCase();
      const matchedToken = BASELINE_REMOTE_STATE_NAMES.find((tok) => lower.includes(tok));
      if (!matchedToken) continue;
      results.push({
        dataAddress: `data.terraform_remote_state.${name}`,
        name,
        matchedToken,
        filePath: file.filePath,
      });
    }
  }

  return results;
}

/**
 * Find resource attribute *values* of the form
 * `data.terraform_remote_state.<X>.outputs.<Y>` where Y is a Bedrock-logging
 * input key. Catches "I'm pulling the log bucket from the baseline stack."
 *
 * Returns one entry per (referencing-resource, target-output) pair.
 */
export function findBedrockLoggingReferences(files: ParsedFile[]): Array<{
  resourceAddress: string;
  remoteStateName: string;
  outputKey: string;
  filePath: string;
}> {
  const results: Array<{
    resourceAddress: string;
    remoteStateName: string;
    outputKey: string;
    filePath: string;
  }> = [];

  for (const file of files) {
    const resourceTree = file.json.resource;
    if (!resourceTree) continue;
    for (const [type, byName] of Object.entries(resourceTree)) {
      for (const [name, bodies] of Object.entries(byName)) {
        const body = Array.isArray(bodies) ? bodies[0] : bodies;
        for (const ref of collectRemoteStateRefs(body)) {
          if (
            (BEDROCK_LOGGING_INPUT_KEYS as readonly string[]).includes(ref.outputKey)
          ) {
            results.push({
              resourceAddress: `${type}.${name}`,
              remoteStateName: ref.remoteStateName,
              outputKey: ref.outputKey,
              filePath: file.filePath,
            });
          }
        }
      }
    }
  }

  return results;
}

/**
 * Walk every string value inside `obj` and yield any
 * data.terraform_remote_state.<name>.outputs.<key> reference found.
 * No regex - splits on "." and checks segment positions.
 */
function collectRemoteStateRefs(obj: unknown): Array<{ remoteStateName: string; outputKey: string }> {
  const out: Array<{ remoteStateName: string; outputKey: string }> = [];
  visitStrings(obj, (s) => {
    const stripped = stripInterpolationWrapper(s);
    const parts = stripped.split('.');
    // data.terraform_remote_state.<name>.outputs.<key>[.<rest>...]
    if (parts.length < 5) return;
    if (parts[0] !== 'data') return;
    if (parts[1] !== 'terraform_remote_state') return;
    if (parts[3] !== 'outputs') return;
    out.push({ remoteStateName: parts[2], outputKey: parts[4] });
  });
  return out;
}

function visitStrings(value: unknown, visit: (s: string) => void): void {
  if (typeof value === 'string') {
    visit(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) visitStrings(v, visit);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) visitStrings(v, visit);
  }
}

function stripInterpolationWrapper(s: string): string {
  if (s.startsWith('${') && s.endsWith('}')) return s.slice(2, -1);
  return s;
}
