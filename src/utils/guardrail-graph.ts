import { ParsedFile, PlanOverlay } from '../types';
import { findResources, getNestedValue } from './resource-helpers';
import { isUnresolvedScalar } from './literal';

// How a Bedrock Agent's guardrail_configuration.guardrail_identifier resolves
// against the guardrails declared in the scanned Terraform.
//
//   declared           - a resource reference (aws_bedrock_guardrail.<name>.id)
//                        whose target IS declared in scope. The correct, fully
//                        verifiable idiom.
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
  | { kind: 'reference-external'; guardrail: string }
  | { kind: 'literal' }
  | { kind: 'unresolved' }
  | { kind: 'none' };

export interface GuardrailGraph {
  // Agent resource name -> how its guardrail_identifier resolves.
  agentToGuardrail: Map<string, GuardrailLink>;
  // Declared-guardrail resource name -> names of agents that attach it by
  // reference. Only `declared` links contribute; literal/external/unresolved
  // links cannot be tied to a specific in-scope guardrail.
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

  for (const agent of findResources(files, 'aws_bedrockagent_agent', overlay)) {
    const link = classifyIdentifier(agent.body, declaredGuardrails);
    agentToGuardrail.set(agent.name, link);

    if (link.kind === 'declared') {
      const attached = guardrailToAgents.get(link.guardrail) ?? [];
      attached.push(agent.name);
      guardrailToAgents.set(link.guardrail, attached);
    }
  }

  return { agentToGuardrail, guardrailToAgents };
}

function classifyIdentifier(
  agentBody: Record<string, unknown>,
  declaredGuardrails: Set<string>,
): GuardrailLink {
  const config = getNestedValue(agentBody, 'guardrail_configuration');
  if (config === undefined || config === null) return { kind: 'none' };

  const identifier = getNestedValue(config, 'guardrail_identifier');
  if (typeof identifier !== 'string' || identifier.trim() === '') {
    return { kind: 'none' };
  }

  // Reference form must be tested before isUnresolvedScalar: a
  // `${aws_bedrock_guardrail.x.id}` expression is *also* an unresolved scalar
  // (it carries a `${`), but we can resolve it by address parsing.
  const refMatch = stripInterpolation(identifier).match(GUARDRAIL_REF);
  if (refMatch) {
    const guardrail = refMatch[1];
    return declaredGuardrails.has(guardrail)
      ? { kind: 'declared', guardrail }
      : { kind: 'reference-external', guardrail };
  }

  if (isUnresolvedScalar(identifier)) return { kind: 'unresolved' };

  // A literal ID or ARN: opaque, cannot be tied to a declared resource.
  return { kind: 'literal' };
}
