import { ParsedFile, PlanOverlay, ConfigReferenceGraph } from '../types';
import { findResources, getNestedValue } from './resource-helpers';
import { isUnresolvedScalar } from './literal';

// How a Bedrock Agent's guardrail_configuration.guardrail_identifier resolves
// against the guardrails declared in the scanned Terraform.
//
//   declared           - a resource reference (aws_bedrock_guardrail.<name>.id)
//                        whose target IS declared in scope. The correct, fully
//                        verifiable idiom.
//   declared-via-module- the guardrail_identifier is an indirect expression
//                        (var / module output) that the plan `configuration`
//                        reference graph traces, across module boundaries, to a
//                        declared aws_bedrock_guardrail. Used when the wired
//                        value is known-after-apply so value resolution fails
//                        but the reference chain still proves attachment.
//   reference-external - a resource reference whose target is NOT in scope
//                        (it may live in a separate platform/security stack).
//   literal            - a literal ID or ARN. A guardrail's guardrail_id is a
//                        known-after-apply computed value, so a literal can
//                        never be matched back to a declared resource - opaque.
//   unresolved         - a var/local/data/module expression we cannot resolve
//                        statically.
//   none               - no guardrail_configuration block, or an empty/unset
//                        guardrail_identifier.
export type GuardrailLink =
  | { kind: 'declared'; guardrail: string }
  | { kind: 'declared-via-module'; guardrail: string; versionPin: VersionPin }
  | { kind: 'reference-external'; guardrail: string }
  | { kind: 'literal' }
  | { kind: 'unresolved' }
  | { kind: 'none' };

// Whether a version-pinned guardrail could be confirmed from the reference
// chain. 'versioned' = the chain reaches an aws_bedrock_guardrail_version
// resource (a numbered, immutable pin). 'unknown' = it does not (could be a
// literal "DRAFT" or a value the chain does not expose) - treat conservatively.
export type VersionPin = 'versioned' | 'unknown';

export interface GuardrailGraph {
  // Agent resource name -> how its guardrail_identifier resolves.
  agentToGuardrail: Map<string, GuardrailLink>;
  // Declared-guardrail resource name -> names of agents that attach it by
  // reference. `declared` and `declared-via-module` links contribute;
  // literal/external/unresolved links cannot be tied to a specific in-scope
  // guardrail.
  guardrailToAgents: Map<string, string[]>;
}

// aws_bedrock_guardrail.<name>.(guardrail_id|id|arn) - the reference forms an
// agent uses to wire a declared guardrail. Matched against the inner
// expression after any `${...}` wrapper hcl2json emits is stripped.
const GUARDRAIL_REF = /^aws_bedrock_guardrail\.([a-z_][a-z0-9_-]*)\.(?:guardrail_id|id|arn)$/i;

function stripInterpolation(value: string): string {
  const match = value.match(/^\$\{(.+)\}$/);
  return match ? match[1].trim() : value;
}

/**
 * Build the agent <-> guardrail reference graph for the scanned Terraform.
 *
 * Linking is done by *parsing the resource address* out of an agent's
 * guardrail_identifier expression - it needs no plan resolution. The optional
 * `overlay` is passed through to `findResources` purely for **visibility** of
 * agents and guardrails buried in remote modules; it does NOT resolve a
 * newly-created guardrail's computed `guardrail_id` (known-after-apply), so a
 * literal/ARN identifier stays `literal` even under --plan.
 *
 * Consumed by S-9.x.1 (referential integrity, Decision A) and S-9.x.3
 * (attaching-agent enrichment, Decisions B/C).
 */
export function buildGuardrailGraph(
  files: ParsedFile[],
  overlay?: PlanOverlay,
): GuardrailGraph {
  const declaredGuardrails = new Set(
    findResources(files, 'aws_bedrock_guardrail', overlay).map((g) => g.name),
  );

  const agentToGuardrail = new Map<string, GuardrailLink>();
  const guardrailToAgents = new Map<string, string[]>();

  // An agent can surface more than once for the same name - e.g. when a local
  // module's HCL is scanned *and* the plan overlay surfaces the same resource
  // (one with an unresolved var ref, one with a known-after-apply value). Keep
  // the strongest classification per name so the result is order-independent
  // and a resolvable plan instance is never clobbered by a weaker HCL one.
  for (const agent of findResources(files, 'aws_bedrockagent_agent', overlay)) {
    const link = classifyIdentifier(
      agent.body,
      declaredGuardrails,
      agent.address,
      overlay?.configReferences,
    );
    const existing = agentToGuardrail.get(agent.name);
    if (!existing || linkStrength(link) > linkStrength(existing)) {
      agentToGuardrail.set(agent.name, link);
    }
  }

  // Derive guardrailToAgents from the final per-agent links so a name that
  // resolved (declared / declared-via-module) is recorded exactly once.
  for (const [agentName, link] of agentToGuardrail) {
    if (link.kind === 'declared' || link.kind === 'declared-via-module') {
      const attached = guardrailToAgents.get(link.guardrail) ?? [];
      attached.push(agentName);
      guardrailToAgents.set(link.guardrail, attached);
    }
  }

  return { agentToGuardrail, guardrailToAgents };
}

function classifyIdentifier(
  agentBody: Record<string, unknown>,
  declaredGuardrails: Set<string>,
  agentAddress: string | undefined,
  configRefs: ConfigReferenceGraph | undefined,
): GuardrailLink {
  const config = getNestedValue(agentBody, 'guardrail_configuration');
  if (config === undefined || config === null) return { kind: 'none' };

  const identifier = getNestedValue(config, 'guardrail_identifier');

  // A direct resource reference (`${aws_bedrock_guardrail.x.id}`) is resolvable
  // by address parsing. Tested before isUnresolvedScalar because the wrapped
  // form is also an unresolved scalar.
  if (typeof identifier === 'string' && identifier.trim() !== '') {
    const refMatch = stripInterpolation(identifier).match(GUARDRAIL_REF);
    if (refMatch) {
      const guardrail = refMatch[1];
      return declaredGuardrails.has(guardrail)
        ? { kind: 'declared', guardrail }
        : { kind: 'reference-external', guardrail };
    }
    if (!isUnresolvedScalar(identifier)) {
      // A literal ID or ARN: opaque, cannot be tied to a declared resource.
      return { kind: 'literal' };
    }
    // Indirect expression (var/local/module): fall through to the config walk.
  }

  // Indirect or known-after-apply identifier: trace the plan configuration
  // reference graph across module boundaries to a declared guardrail.
  const viaModule = resolveViaConfig(agentAddress, declaredGuardrails, configRefs);
  if (viaModule) return viaModule;

  if (typeof identifier === 'string' && isUnresolvedScalar(identifier)) {
    return { kind: 'unresolved' };
  }
  // No identifier value (e.g. known-after-apply in plan) and no resolvable
  // reference chain.
  return { kind: 'none' };
}

// Trace `guardrail_configuration`'s reference chain through the plan
// configuration graph to a declared aws_bedrock_guardrail. Returns a
// declared-via-module link (with version-pin status) or undefined when the
// chain cannot be resolved (no graph, no agent address, or no terminal that
// names an in-scope guardrail). Edge-based, so it survives known-after-apply.
function resolveViaConfig(
  agentAddress: string | undefined,
  declaredGuardrails: Set<string>,
  configRefs: ConfigReferenceGraph | undefined,
): GuardrailLink | undefined {
  if (!agentAddress || !configRefs) return undefined;
  // The configuration block is pre-expansion, so its keys carry no instance
  // index; a plan address does (e.g. `...recruiter[0]` for count/for_each).
  // Strip indices so an indexed agent instance still matches its config entry.
  const key = `${agentAddress.replace(/\[[^\]]*\]/g, '')}#guardrail_configuration`;
  const start = configRefs.resourceAttrs.get(key);
  if (!start || start.length === 0) return undefined;

  const seen = new Set<string>();
  const stack = [...start];
  let guardrail: string | undefined;
  let versionPin: VersionPin = 'unknown';
  let steps = 0;

  while (stack.length > 0 && steps++ < MAX_WALK_STEPS) {
    const node = stack.pop()!;
    if (seen.has(node)) continue;
    seen.add(node);

    if (node.startsWith('res:')) {
      const leaf = node.slice(4); // "<type>.<name>"
      const dot = leaf.indexOf('.');
      if (dot === -1) continue;
      const type = leaf.slice(0, dot);
      const name = leaf.slice(dot + 1);
      if (type === 'aws_bedrock_guardrail' && declaredGuardrails.has(name)) {
        guardrail = name;
      } else if (type === 'aws_bedrock_guardrail_version') {
        versionPin = 'versioned';
      }
    } else if (node.startsWith('out:')) {
      const next = configRefs.moduleOutputs.get(node.slice(4));
      if (next) stack.push(...next);
    } else if (node.startsWith('var:')) {
      const next = configRefs.varBindings.get(node.slice(4));
      if (next) stack.push(...next);
    }
  }

  return guardrail ? { kind: 'declared-via-module', guardrail, versionPin } : undefined;
}

// Cycle guard is the `seen` set; this caps total work on pathological graphs.
const MAX_WALK_STEPS = 1000;

// Ranks link kinds so the most informative classification wins when the same
// agent name is seen more than once (HCL vs plan instance). A guardrail tied to
// a concrete in-scope resource (declared / declared-via-module) outranks an
// external reference, an opaque literal, and the no-information states.
function linkStrength(link: GuardrailLink): number {
  switch (link.kind) {
    case 'declared':
      return 5;
    case 'declared-via-module':
      return 4;
    case 'reference-external':
      return 3;
    case 'literal':
      return 2;
    case 'unresolved':
      return 1;
    case 'none':
      return 0;
  }
}
