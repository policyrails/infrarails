import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import {
  findResources,
  findBedrockResources,
  findBedrockDataSources,
  findIamBedrockGrants,
  findBedrockVpcEndpoints,
} from '../utils/resource-helpers';

const REGULATORY_REFERENCE = 'EU AI Act Article 9 - Risk management system for high-risk AI systems';
const NIST_REFERENCE =
  'NIST AI RMF 1.0: MEASURE 2.6 (AI system safety); MAP 5.1 (likelihood and magnitude of impacts); GOVERN 1.4 (transparent risk-management policies)';
const ISO_REFERENCE =
  'ISO/IEC 42001:2023 Annex A: A.6.1.2 (objectives for AI system); A.6.2.4 (verification and validation); A.6.2.5 (deployment)';

const RATIONALE =
  'Bedrock Guardrails are the AWS-native enforcement point for content filters, denied topics, ' +
  'PII redaction, and grounding checks. Article 9 requires an operative risk-management system ' +
  'for high-risk AI; deploying Bedrock without any guardrail declared in the same Terraform tree ' +
  'leaves the scanner unable to confirm that a control surface exists at all.';

// Companion to S-9.x.1. S-9.x.1 verifies guardrail *attachment* on Bedrock
// Agents - a strong, attachment-level signal. This rule asks the weaker
// presence-level question: "Bedrock is being used somewhere in this Terraform;
// is at least one aws_bedrock_guardrail declared anywhere?" It is intentionally
// WARN-only for two reasons:
//
//   1. Guardrails are commonly defined in a separate platform/security stack
//      and referenced via output / cross-account ARN. A single-repo scan
//      cannot see those definitions.
//   2. Even when no guardrail is declared in IaC at all, Article 9 may still
//      be satisfied by application-layer controls (the SDK-call layer this
//      static scanner cannot read).
//
// Treating "no guardrail declared here" as FAIL would generate false positives
// across most real enterprise estates. WARN with a clear remediation message
// that names both possibilities is the honest signal.
const NO_GUARDRAIL_REMEDIATION =
  'Either declare an aws_bedrock_guardrail (and aws_bedrock_guardrail_version) ' +
  'in this Terraform tree and reference it from your Bedrock Agents (see S-9.x.1) ' +
  'or, for SDK-driven InvokeModel/Converse calls, pass the guardrailIdentifier ' +
  'parameter on every call. If guardrails are defined in a separate security/' +
  'platform stack, scan that stack too or document the cross-stack arrangement. ' +
  `Why: ${RATIONALE}`;

const PASS_RUNTIME_CAVEAT =
  'Note: this confirms a guardrail is declared in IaC, not that it is attached ' +
  'to every model invocation. SDK-driven InvokeModel/Converse calls must still ' +
  'pass guardrailIdentifier in application code; that is not verifiable from ' +
  'Terraform. See S-9.x.1 for Agent-attachment verification.';

export const guardrailPresenceRule: ScanRule = {
  id: 'S-9.x.2',
  description:
    'When Bedrock is in use, at least one aws_bedrock_guardrail should be declared in scanned Terraform (presence-level signal; attachment is covered by S-9.x.1 for Agents and is application-code-only for raw SDK calls)',
  severity: 'WARN',
  regulatoryReference: REGULATORY_REFERENCE,
  nistReference: NIST_REFERENCE,
  isoReference: ISO_REFERENCE,

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    const overlay = context.planOverlay;
    // "Bedrock workload" = anything that suggests model invocation will happen.
    // Exclude guardrail types themselves so the check doesn't become circular
    // (a Terraform that declares only a guardrail and nothing else would
    // otherwise trigger the rule and immediately PASS it).
    const directWorkload = findBedrockResources(files, overlay).filter(
      (r) => r.type !== 'aws_bedrock_guardrail' && r.type !== 'aws_bedrock_guardrail_version',
    );
    const iam = findIamBedrockGrants(files);
    const vpc = findBedrockVpcEndpoints(files);
    const dataSources = findBedrockDataSources(files);

    const hasBedrockSignal =
      directWorkload.length > 0 ||
      iam.length > 0 ||
      vpc.length > 0 ||
      dataSources.length > 0;

    if (!hasBedrockSignal) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock workload detected (no Bedrock resources, IAM grants, VPC endpoints, or data sources). Guardrail-presence check skipped.',
          remediation: '',
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    // Consult the plan overlay (as S-9.x.3 does) so guardrails declared inside
    // modules - visible only in the plan, not the raw HCL of the scanned
    // directory - are counted. Without it this rule reports a false "no guardrail
    // declared" WARN while S-9.x.3 inspects the very same guardrail's body.
    const guardrails = findResources(files, 'aws_bedrock_guardrail', overlay);

    if (guardrails.length === 0) {
      const signals: string[] = [];
      if (directWorkload.length > 0) {
        signals.push(`${directWorkload.length} direct Bedrock resource(s)`);
      }
      if (iam.length > 0) signals.push(`${iam.length} IAM grant(s) for Bedrock actions`);
      if (vpc.length > 0) signals.push(`${vpc.length} VPC endpoint(s) to Bedrock`);
      if (dataSources.length > 0) signals.push(`${dataSources.length} Bedrock data source(s)`);

      // Anchor the WARN to the Bedrock usage that triggered it, so the alert
      // points the reviewer at the resource needing a guardrail rather than the
      // repo root. Order mirrors the signals message above. directWorkload may
      // carry a `plan:<address>` filePath when the workload is module-buried
      // (overlay-sourced); the IAM/VPC/data-source helpers are HCL-only.
      const triggerPath =
        directWorkload[0]?.filePath ??
        iam[0]?.filePath ??
        vpc[0]?.filePath ??
        dataSources[0]?.filePath ??
        '';

      return [
        {
          ruleId: this.id,
          status: 'WARN',
          filePath: triggerPath,
          description: `Bedrock usage detected (${signals.join(', ')}) but no aws_bedrock_guardrail resource is declared anywhere in the scanned Terraform.`,
          remediation: NO_GUARDRAIL_REMEDIATION,
          regulatoryReference: REGULATORY_REFERENCE,
          nistReference: NIST_REFERENCE,
          isoReference: ISO_REFERENCE,
        },
      ];
    }

    return [
      {
        ruleId: this.id,
        status: 'PASS',
        filePath: guardrails[0].filePath,
        description: `${guardrails.length} aws_bedrock_guardrail resource(s) declared in scanned Terraform: ${guardrails.map((g) => g.name).join(', ')}. ${PASS_RUNTIME_CAVEAT}`,
        remediation: '',
        regulatoryReference: REGULATORY_REFERENCE,
        nistReference: NIST_REFERENCE,
        isoReference: ISO_REFERENCE,
      },
    ];
  },
};
