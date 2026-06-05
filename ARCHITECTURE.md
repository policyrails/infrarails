# infrarails - Architecture

This document describes the internal pipeline of `infrarails`. For installation, usage, rules, and CI integration, see the [README](README.md).

---

## Pipeline overview

`infrarails` is a small, layered TypeScript pipeline. Each layer has a narrow contract, which makes the rule logic easy to read and the failure modes easy to reason about.

```
   +------------------+        +-------------------+
   |  CLI (commander) |        |  --plan <file>    |   optional
   |  src/index.ts    |        |  src/plan-parser  |   (Terraform JSON
   +--------+---------+        +---------+---------+    show -json output)
            |                            |
            |                            v
            |                  +---------+---------+
            |                  |    PlanOverlay    |   resources / deletions /
            |                  +---------+---------+   variables / flags
            v                            |
   +--------+---------+                  |
   |     Parser       |                  |
   |  .tf  -> hcl2json|                  |
   |  .tf.json -> JSON|                  |
   +--------+---------+                  |
            | ParsedFile[]               |
            v                            v
   +--------+---------+        +---------+---------+
   |     Resolver     +<-------+   overlay arg     |   resolveExpression / Scalar /
   |  src/resolver.ts |        |  (optional)       |   OrPlanFallback consult overlay
   +--------+---------+        +-------------------+   before HCL walk
            |
   +--------v---------+
   | Two-phase Runner |   src/runner.ts
   |                  |
   |  Phase 1 rules --+--> populate ScanContext via src/context.ts
   |  Phase 2 rules --+--> consume ScanContext (bucket / log-group names,
   |                  |    unresolved refs, strictAccountLogging, planOverlay)
   |                  |
   |  Post-pass  -----+--> when --plan + --strict-account-logging, escalate
   |                  |    user-fixable INCONCLUSIVE -> FAIL (see Plan mode)
   +--------+---------+
            | Finding[]
   +--------v---------+
   |    Formatter     |   src/formatter.ts - terminal, JSON, SARIF, HTML, or PDF
   +------------------+
```

The CLI ([src/index.ts](src/index.ts)) validates `--format` against the five supported values (`terminal`, `json`, `sarif`, `html`, `pdf`) and exits with code `2` on an unknown value, so an older globally-installed binary asked for `pdf` cannot silently fall through to terminal mode and write ANSI text into a `.pdf` file. PDF additionally requires `-o`: it is binary and cannot be sensibly streamed to a TTY.

### PDF rendering

PDF output is generated procedurally with [`pdfkit`](https://pdfkit.org/) rather than by rendering HTML through a headless browser. Reasons:

- **No Chromium dependency.** Shipping a headless browser would add ~150MB and require system libraries (`libnss3`, `libatk1.0-0`, ...) that are awkward in CI containers and Lambda layers.
- **Deterministic layout.** Procedural drawing gives stable pagination across runs, which matters for diffing reports.
- **Portable.** `pdfkit` is pure JS, so the same code path works on macOS, Linux, and inside WSL without per-OS install steps.

The trade-off is that the PDF and HTML formatters do not share a renderer - the layout is reimplemented using `pdfkit` primitives (text, rounded rects, framework-coloured pills) rather than CSS. Both formats follow the same visual language (status pills, grouped sections, framework refs) but neither is a translation of the other.

### Platform note: how the parser invokes hcl2json

The parser ([src/parser.ts](src/parser.ts)) invokes `hcl2json` via `spawnSync('hcl2json', [], { input: rawHcl })` - piping the HCL source over stdin with no shell in between. This is portable across macOS, Linux, and native Windows:

- **No `/bin/bash` dependency** - earlier revisions used `execSync` with `shell: '/bin/bash'` and a here-string (`hcl2json <<< '...'`), which broke native Windows. The current call uses no shell, so Node resolves the executable directly (`hcl2json` on POSIX, `hcl2json.exe` on win32).
- **No temp files** - the `.tf` source is piped over stdin, so we never write to disk between the file read and `hcl2json`.
- **No quote-escaping** - the previous bash here-string had to escape single quotes in the HCL source, which is a known footgun on configurations containing arbitrary string literals. Stdin avoids the problem entirely.

Errors surface with the file path, the `hcl2json` exit status, and the captured stderr, so a syntax error in a single `.tf` file produces a debuggable message rather than a raw `Error: Command failed`.

---

## Why two phases?

Most rules need to know *which buckets and log groups Bedrock is actually writing to* before they can check encryption, versioning, retention, etc. Phase 1 (currently just `S-12.1.1`) walks `aws_bedrock_model_invocation_logging_configuration` blocks and resolves their `bucket_name` / `log_group_name` fields into a `ScanContext`. Phase 2 rules use that context to scope their checks - e.g. `S-12.x.2a` only flags encryption gaps on buckets actually receiving Bedrock logs, not every bucket in the repo.

This split is what lets the scanner stay quiet about resources that aren't part of the AI logging path: a CI artifact bucket without KMS encryption is not a Bedrock-logging finding, and Phase 2 rules know that because Phase 1 told them.

An optional third pass runs only when both `--plan` and `--strict-account-logging` are set; see [Strict-mode INCONCLUSIVE escalation](#strict-mode-inconclusive-escalation) below.

---

## The resolver

The resolver is what makes the scanner robust on real-world Terraform. A `bucket_name` field can be a literal, a `var.X`, a `local.Y`, a reference to another `aws_s3_bucket`, an SSM parameter, a module output, or a complex interpolation. The resolver classifies each into one of three outcomes:

| Outcome | Example | What rules do with it |
|---|---|---|
| **literal** | `"prod-ai-audit-logs"` | Use the value directly |
| **address** | `aws_s3_bucket.logs.id` resolved to its `bucket` attribute | Use the resolved name |
| **unresolvable** | `var.bucket_name` (no default), `data.aws_ssm_parameter.X.value`, `module.logging.bucket` | Emit `INCONCLUSIVE` instead of guessing |

The unresolvable cases get categorised with a reason code so the finding message can tell the operator *why* the value couldn't be checked statically. This matters at audit time - "we couldn't verify because the bucket name comes from SSM" is a different remediation than "we couldn't verify because the variable has no default."

| Reason | Source |
|---|---|
| `var-no-default` | `var.X` referenced but no `default` declared in the same module |
| `local-not-literal` | `local.Y` is an expression rather than a literal value |
| `data-source-ssm` / `data-source-other` | `data.<type>.<name>.<attr>` not resolvable from HCL |
| `module-output` | `module.X.output_name` not resolvable from HCL |
| `complex-interpolation` | Mixed-literal-and-reference string like `"${var.X}-suffix"` |
| `unknown-format` | Expression shape not parsed by the resolver |
| `plan-known-after-apply` | Attribute is in `resource_changes.after_unknown` - Terraform itself doesn't know the value until AWS materialises the resource |
| `plan-sensitive-redacted` | Attribute is in `resource_changes.after_sensitive` or reads `"(sensitive value)"` - `terraform show -json` deliberately redacts these |
| `plan-deferred-data-source` | Data source can only be evaluated at apply time (depends on a not-yet-created resource) |
| `plan-remote-state-unreachable` | `data.terraform_remote_state` couldn't fetch its backend at plan time |

The first seven reasons can arise without a plan; the last four only when `--plan` is supplied. The Plan mode section below explains which of these escalate to `FAIL` under `--strict-account-logging` and which stay `INCONCLUSIVE` because Terraform itself cannot know the answer.

Variable resolution is **module-scoped** - a `var.foo` in `./modules/bedrock_logging/main.tf` only resolves against `variable` blocks in that same directory, not against unrelated `variable "foo"` declarations elsewhere in the tree.

---

## Scanner directory traversal

The parser recursively walks the target directory and parses every `.tf` and `.tf.json` file it finds. **Local modules are scanned as part of the same pass** (e.g. `./modules/bedrock_logging/main.tf` is read alongside the root). The following directories are skipped automatically:

```
node_modules, venv, env, __pycache__,
examples, test, tests, testdata, fixtures, vendor,
.* (any dotfile/dir)
```

Remote modules (registry, git, http) are not fetched - their HCL contents are invisible to a static scan. Without `--plan`, `S-12.x.5` flags them as `INCONCLUSIVE` and `S-12.1.1` factors them into its own INCONCLUSIVE reasoning. With `--plan`, the plan's `planned_values.child_modules[]` exposes every resource those modules actually create at fully-qualified addresses (e.g. `module.bedrock_logging.aws_cloudwatch_log_group.this`), so the rule engine evaluates them directly via the overlay; the two "we couldn't see inside" INCONCLUSIVEs are suppressed because the plan has answered the question.

---

## ScanContext

`src/context.ts` builds a `ScanContext` after Phase 1 runs. Phase 2 rules read it to scope their checks. The shape:

| Field | Type | Purpose |
|---|---|---|
| `bedrockLoggingDetected` | `boolean` | Did Phase 1 find an `aws_bedrock_model_invocation_logging_configuration` resource? Logging-related Phase 2 rules (`cw-retention`, `s3-lifecycle`, `s3-versioning`, `s3-encryption`) SKIP when false; rules with their own detection logic (e.g. `agent-guardrail`, `guardrail-presence`, `cloudtrail`, `module-wall`, `plan-deletions`) ignore it. |
| `logBucketNames` | `string[]` | Resolved S3 bucket names that Bedrock writes to (literals or fully-qualified addresses). Used to scope `S-12.x.1`, `S-12.x.2a`, `S-12.1.2b`. |
| `logGroupNames` | `string[]` | Resolved CloudWatch log group names that Bedrock writes to. Used to scope `S-12.1.2a`. |
| `unresolvedBucketRefs` | `UnresolvedRef[]` | Bucket references that could not be resolved statically. Phase 2 rules emit `INCONCLUSIVE` per ref. |
| `unresolvedGroupRefs` | `UnresolvedRef[]` | Log-group references that could not be resolved statically. Same handling. |
| `strictAccountLogging` | `boolean` | When true, missing logging is `FAIL` instead of `INCONCLUSIVE`. The flag is the only knob that flips this verdict - no naming-based heuristics (cross-stack remote-state references, baseline-named modules, logging-shaped input keys) downgrade it. Also gates the `S-12.1.2a` WARN→FAIL escalation (forwarder-aware) and the runner-side INCONCLUSIVE→FAIL post-pass when combined with `planOverlay`. |
| `planOverlay` | `PlanOverlay \| undefined` | Set when `--plan` was supplied. Holds resolved attribute values, deletion records, root-module variables, and the `noActionableChanges` flag. Passed into `findResources`, the resolver, and the `plan-deletions` rule. Undefined in default (source-only) mode. |

---

## Plan mode

When `--plan <file>` is supplied, the CLI parses the Terraform plan JSON (output of `terraform show -json tfplan.bin`) into a `PlanOverlay` and threads it through the pipeline alongside the parsed HCL. HCL stays the primary input - the overlay is purely additive. Without `--plan`, behaviour is byte-identical to the source-only mode described above.

### What the overlay carries

The overlay is built by `src/plan-parser.ts` from three blocks of the plan JSON:

| Source block | What it gives us |
|---|---|
| `planned_values.root_module` (recursive into `child_modules`) | Fully-resolved `PlanResource` entries keyed by normalised address. Indexed addresses (`aws_s3_bucket.logs[0]`, `aws_s3_bucket.logs["prod"]`) collapse to the same key. |
| `resource_changes` | `PlanDeletion` entries for `actions: ["delete"]` plus `replaceWithCreate` for create+delete pairs; `unknownPaths` and `sensitivePaths` (dotted paths flattened from `after_unknown` / `after_sensitive`) for the safety filters in the resolver. |
| `variables` (root) | Resolves `var.X` references that have no static default in HCL. |

A few edge cases:

- **Errored plans** (`errored: true`) are refused up-front (exit 2 with a specific stderr message).
- **No-change plans** - no create/update/delete actions, produced by `-refresh-only` or by a normal plan against already-converged infra - set `flags.noActionableChanges` and emit a stderr note. Deletion-safety analysis is skipped because there are no destroys to evaluate.
- **`-target=...` plans are not auto-detected.** Terraform narrows `planned_values` and `resource_changes` together so they never disagree, and the parser has no HCL inventory to compare against. Audit-grade gates should pass a full `terraform plan`.

### How the resolver consumes the overlay

`resolveExpression`, `resolveScalarReference`, and the new `resolveOrPlanFallback` helper accept an optional `overlay?: PlanOverlay` argument. When present, the resolver consults the overlay **before** walking HCL:

- `var.X` → check `overlay.variables.get(X)` first.
- `aws_<type>.<name>.<attr>` → check `overlay.resources.get("<type>.<name>")` first; read the resolved attribute from `values`.
- `data.<type>.<name>.<attr>` → previously always unresolvable; now resolved when the data source appears in `planned_values`.
- `module.<name>.<output>` → resolved when the module output is materialised on a downstream resource.

Three safety filters guard against false PASSes:

1. **Indexed addresses** are normalised before lookup (`aws_s3_bucket.logs[0]` → `aws_s3_bucket.logs`).
2. **Unknown attributes** (in `unknownPaths`) return `plan-known-after-apply` rather than the raw `null` from `values`, so auto-generated bucket names don't trigger spurious FAILs.
3. **Sensitive attributes** (in `sensitivePaths`, or with the literal string `"(sensitive value)"`) return `plan-sensitive-redacted` rather than comparing rules against Terraform's redaction placeholder.

`resolveOrPlanFallback` adds one more lookup for callers that know the *containing* resource address and attribute path: when an expression itself can't be resolved (`complex-interpolation`, `local-not-literal`) but the containing resource is in the overlay, the helper reads the final value from `values.<attribute.path>` directly. This eliminates the three most common INCONCLUSIVEs whenever a plan is loaded.

### How rules consume the overlay

`findResources(files, type, overlay?)` is the central change. Phase 2 rules call it as they always have - but when an overlay is present, the helper additionally iterates `overlay.resources` and returns a merged list with an explicit `source: 'hcl' | 'plan'` marker. Rules read the same `body` / `values` map either way, so most rules need no plan-specific code. `filePath` for plan-sourced findings is set to `plan:<address>` so audit trails remain concrete even when the resource has no HCL line in the scanned repo.

Two rules read the overlay directly:

- `S-12.x.del` (`plan-deletions`) walks `overlay.deletions` and emits FAIL/WARN per the deletion-finding table in [docs/plan-mode-design.md §4](docs/plan-mode-design.md). SKIPs when `overlay` is undefined.
- `S-12.x.5` (`module-wall`) and `S-12.1.1` (`bedrock-logging`) both check `context.planOverlay` to suppress their "remote module is opaque" INCONCLUSIVE: when the overlay is present, the remote module's contents have already been searched via `findResources`, so absence of Bedrock signals there is a real SKIP rather than honest uncertainty.

### HCL-anchored resolution (identity vs values)

When a plan is supplied, the scanned **HCL stays the anchor for identity and structure** - what each resource *is*, and which resource a reference names. The overlay only fills in **values** HCL cannot resolve statically (a `var` with no default, a computed name, a `local`) and **surfaces resources with no on-disk HCL at all** (those buried in a remote registry/git module). The plan never overrides HCL on a question of identity.

- **Identity override only when HCL is accurate.** A reference like `s3_config.bucket_name = aws_s3_bucket.logs.id` names a specific resource. The plan may report that name as computed-at-apply (`after_unknown`), but that concerns the *value*, not *which* resource it is: when `aws_s3_bucket.logs` is declared in the scanned HCL, resolution anchors on the HCL address, so bucket/log-group matching runs under `--plan` exactly as it does source-only. With no HCL to trust (remote-module-only), the plan's honest `plan-known-after-apply` verdict stands and the finding is INCONCLUSIVE rather than a fabricated identity. See `awsResourceDeclared` and the `aws_*` branch in [src/resolver.ts](src/resolver.ts).
- **`hclBody` fold-back.** A plan body for a *local* module-buried resource can drop an attribute it marked computed-at-apply (e.g. `s3_config.bucket_name` is absent from `planned_values`). The on-disk HCL block is folded onto the plan entry as `FoundResource.hclBody` ([src/utils/resource-helpers.ts](src/utils/resource-helpers.ts)), and `extractRef` in [src/context.ts](src/context.ts) falls back to that HCL reference, so the scanner never wrongly concludes "logging does not use S3" when it plainly does.

Net rule of thumb: **identity and structure come from HCL; resolved scalar values come from the plan; remote-module-only resources come from the plan.** Supplying a plan must never make the scanner *less* certain than scanning source alone.

### Strict-mode INCONCLUSIVE escalation

After all rules run, `runScan` performs a post-pass when both `--plan` and `--strict-account-logging` are set. The rationale: with a plan in hand the user has eliminated most resolver-driven uncertainty, and `--strict-account-logging` asserts "this scanned tree is the entire estate", so a remaining INCONCLUSIVE is either a fixable user choice or something Terraform itself genuinely cannot know. The post-pass escalates the former and leaves the latter.

| Reason | Behaviour under `--plan` + `--strict-account-logging` |
|---|---|
| `var-no-default`, `local-not-literal`, `data-source-ssm`, `data-source-other`, `module-output`, `complex-interpolation` | Escalate to FAIL - the user can supply a default, restructure the expression, or rerun a full plan |
| `plan-deferred-data-source`, `plan-remote-state-unreachable` | Escalate to FAIL - fix the plan invocation, dependency order, or backend auth |
| `plan-known-after-apply` | Stay INCONCLUSIVE - AWS generates the value post-create; nothing the user can do at plan time |
| `plan-sensitive-redacted` | Stay INCONCLUSIVE - escalating would punish correct secret handling |

The escalator only touches expression-driven INCONCLUSIVEs - those carrying an `unresolvedReason` tag set by `inconclusiveFromUnresolved`.

Structural INCONCLUSIVEs without that tag are left alone. Example: `buildIndirectOnlyInconclusive` in [src/rules/bedrock-logging.ts](src/rules/bedrock-logging.ts), where Bedrock-adjacent signals (IAM/VPC) appear but no resource does. The plan cannot answer these - the actual usage may be in SDK code the scanner cannot see.

Rules that *should* escalate under strict mode (e.g. the in-rule `if (context.strictAccountLogging)` branches in `S-12.1.1` and `S-12.x.4`) already do so at the rule layer.

### Plan-mode security note

Plan files contain resolved variable values - including anything passed via `-var`. Treat them as ephemeral build artefacts: gitignore, do not paste into PR comments, and prefer in-CI generation over committed fixtures. The CLI prints a one-line summary to stderr on successful overlay load so operators can sanity-check the resource and deletion counts before trusting the resulting report.

---

## Guardrail rules and the agent-guardrail graph

The three Article 9 rules form a **presence -> attachment -> body** progression over AWS Bedrock Guardrails, so a clean run means a guardrail exists, is wired to an agent, *and* actually blocks something:

- **`S-9.x.2` (presence, WARN)** - is *any* `aws_bedrock_guardrail` declared in the scanned tree? WARN-only, since guardrails often live in a separate security stack.
- **`S-9.x.1` (attachment, FAIL)** - does each `aws_bedrockagent_agent` carry a `guardrail_configuration` with a non-empty `guardrail_identifier` and a numbered (non-`DRAFT`) version?
- **`S-9.x.3` (body, WARN)** - does the guardrail body enforce the two mandatory surfaces, a `PROMPT_ATTACK` filter and a harmful-content filter at `MEDIUM`/`HIGH`? Attaching a guardrail whose every action is `NONE` passes the first two rules but provides no control surface.

`S-9.x.1` and `S-9.x.3` share one helper, `buildGuardrailGraph` in [src/utils/guardrail-graph.ts](src/utils/guardrail-graph.ts), which walks the parsed files once and returns the reference graph in both directions:

| Field | Maps | Used by |
|---|---|---|
| `agentToGuardrail` | agent resource name -> a `GuardrailLink` (`declared`, `declared-via-module`, `reference-external`, `literal`, `unresolved`, or `none`) | `S-9.x.1` referential-integrity verdict |
| `guardrailToAgents` | declared-guardrail name -> the agents that attach it by reference | `S-9.x.3` blast-radius and the "attached to no agent" SDK-blind-spot note |

Linking is done by **parsing the resource address out of the agent's `guardrail_identifier`** (e.g. `aws_bedrock_guardrail.<name>.id`), so it needs no plan resolution. The optional `overlay` argument does two things: it gives `findResources` **visibility** of agents and guardrails buried in remote modules, and its `configReferences` let the `declared-via-module` case trace an indirect identifier (a `var` or `module` output) across module boundaries to a declared guardrail when the wired value itself is known-after-apply. A freshly-created guardrail's computed `guardrail_id` stays `literal` even under `--plan`, because a known-after-apply value can never be matched back to a declared resource.

None of the three rules inspect SDK-level `guardrailIdentifier` arguments on `InvokeModel`/`Converse` - that is application code, not Terraform, and each rule's remediation says so, so a passing `S-9.x.1` is never mistaken for SDK coverage.

---

## Adding a new rule

Each rule lives in `src/rules/` and implements the `ScanRule` interface from `src/types.ts`. The rule ID follows an `S-<article>.<x>.<y>` naming convention where `<article>` is the EU AI Act article number the rule maps to (e.g. `S-9.x.1` for Article 9 risk-management rules, `S-12.1.2a` for Article 12 logging rules). The rule includes `regulatoryReference`, `nistReference`, and `isoReference` strings mapping to specific controls. Register the new rule in [src/rules/index.ts](src/rules/index.ts).

Set `phase1: true` only if the rule needs to populate `ScanContext` for other rules to consume (currently just `S-12.1.1`). Most new rules should be Phase 2 - they read context built in Phase 1 and inspect specific resource types. A Phase 2 rule that wants to see resources buried inside remote modules should pass `context.planOverlay` to `findResources` (and `resolveExpression` / `resolveOrPlanFallback` for expression-driven fields); the rule body is otherwise identical to a source-only rule.

A rule that only makes sense when a plan is supplied (like `S-12.x.del`, which reads `context.planOverlay.deletions`) should check `context.planOverlay` up-front and emit a single `SKIP` finding when it's undefined, so source-only runs do not see a confusing `INCONCLUSIVE` for a question the rule cannot answer.

Test fixtures for end-to-end scenarios live under [test/fixtures/bedrock-logging-combos/](test/fixtures/bedrock-logging-combos/) - each subdirectory is a self-contained Terraform configuration that exercises one scenario (e.g. `cross-stack-baseline-logging`, `remote-module-bedrock-logging`, `strict-mode-fail`). Plan-mode fixtures pair an HCL configuration with a synthetic `plan.json` under [test/fixtures/plan-mode/](test/fixtures/plan-mode/) and are exercised by [test/e2e/cli.test.ts](test/e2e/cli.test.ts).
