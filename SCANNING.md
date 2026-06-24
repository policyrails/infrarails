# infrarails - How the scanner handles your code

The hardest part of static compliance scanning isn't matching resource types - it's distinguishing *"this is genuinely missing"* from *"this lives somewhere I can't see."* The scanner tells you which one you're looking at. For installation, usage, rules, and CI integration, see the [README](README.md); for the internal pipeline, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Verdicts by scenario

| Scenario | Verdict |
|---|---|
| Bedrock + `aws_bedrock_model_invocation_logging_configuration` in the same tree, ≥ 1 modality enabled (or all modality toggles unset, which is AWS's enable-all default) | `S-12.1.1: PASS` |
| Logging resource exists but every `*_data_delivery_enabled = false` | `S-12.1.1: FAIL` (no events will be written) |
| Bedrock used, no logging config in scanned files | `INCONCLUSIVE` by default; `FAIL` under `--strict-account-logging` |
| Bedrock log group with `retention_in_days = 7` + `aws_cloudwatch_log_subscription_filter` to Datadog/Splunk | `S-12.1.2a: WARN` (forwarder-aware remediation) |
| Indirect Bedrock signals only (IAM grants for `bedrock:*`, VPC endpoint to `bedrock-runtime`, `aws_bedrock_foundation_model` data source) | Always `INCONCLUSIVE` - the deploying resource may live in another stack |
| Local modules (`source = "./modules/..."`) | Scanned recursively into the same context |
| Remote modules (registry/git/http/bitbucket) - no plan | Flagged via `S-12.x.5`; `S-12.1.1` emits `INCONCLUSIVE` rather than misleading `SKIP` if Bedrock might live inside |
| Remote modules - with `--plan` | Resources visible via `planned_values.child_modules[]`; rules evaluate them directly, `S-12.x.5` auto-SKIPs |
| `.tf.json` (cdktf, Terragrunt) | Parsed alongside `.tf` - same internal representation |
| CloudFormation template with inline S3 bucket config | Bucket split into the TF-shaped companion resources (encryption/versioning/lifecycle/object-lock) so the same S3 rules evaluate it |
| CFN resource guarded by `Condition:` | `INCONCLUSIVE` (`cfn-condition-gated`) - the control may not exist at deploy time |
| CFN-only Bedrock usage, no logging config | `S-12.1.1: INCONCLUSIVE` explaining CFN cannot declare invocation logging (no FAIL, even in strict mode) |
| Nested stack (`AWS::CloudFormation::Stack`) that looks Bedrock-related | Flagged via `S-12.x.5`, like a remote Terraform module |

## Bedrock Guardrails - Agent-attached vs SDK runtime

The three guardrail rules form a **presence → attachment → body** progression - three angles on one concept, so a clean run means a guardrail exists, is wired to the agent, *and* actually blocks something:

- `S-9.x.2` is the weakest presence check - "is *any* guardrail declared anywhere?" - that WARNs rather than FAILs, since guardrails commonly live in a separate security stack.
- `S-9.x.1` covers Agent attachment via `guardrail_configuration` on `aws_bedrockagent_agent`. It verifies `guardrail_identifier` is non-empty and `guardrail_version` is numbered (not `"DRAFT"`). A guardrail attached *by reference* to a definition in scope now PASSes (the correct Terraform idiom); a reference to a guardrail not in the scanned tree WARNs ("may live in another stack").
- `S-9.x.3` inspects the guardrail *body*: attaching a guardrail with every action set to `NONE` passes `S-9.x.1`/`S-9.x.2` but provides no control surface. It WARNs when either mandatory surface (a `PROMPT_ATTACK` filter, a harmful-content filter) is absent or permissive, and PASSes only when both block.
- None of the three verify SDK-level `guardrailIdentifier` parameters on `InvokeModel`/`Converse`. That's application code, not IaC, and is called out in the rules' remediation messages so a passing `S-9.x.1` is never read as covering SDK-driven workloads.

## Variables, locals, and data sources

Variables, locals, and data sources are resolved when possible. The resolver returns one of three outcomes:

| Expression | Behavior |
|---|---|
| `"literal-bucket"` | Used directly |
| `var.bucket_name` with `default = "x"` | Resolved to `"x"` |
| `var.bucket_name` with no default | INCONCLUSIVE (`var-no-default`) |
| `local.bucket = "x"` | Resolved to `"x"` |
| `aws_s3_bucket.logs.id` | Resolved to that bucket's `bucket` attribute, if scanned |
| `data.aws_ssm_parameter.X.value` | INCONCLUSIVE (`data-source-ssm`) |
| `module.X.output_name` | INCONCLUSIVE (`module-output`) |
| `prefix-${var.X}` | INCONCLUSIVE (`complex-interpolation`) |

Variable resolution is **module-scoped** - a `var.foo` in `./modules/bedrock_logging/main.tf` only resolves against `variable` blocks in that same directory.

The decision to emit INCONCLUSIVE vs FAIL is driven **only** by what is statically present - no naming-convention heuristics. A `data.terraform_remote_state.<anything>` reference, a module called `bedrock_logging`, or an input key like `log_bucket` does **not** influence the verdict, because any naming-based suppression is a false positive waiting to happen. If logging really lives in another stack, scan that stack too - or accept the default `INCONCLUSIVE`.
