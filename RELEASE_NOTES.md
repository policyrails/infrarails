# Release Notes

## v0.4.0 - CloudFormation support (dual-IaC scanning)

This release teaches infrarails to read **AWS CloudFormation** alongside Terraform. Every existing rule now runs unchanged against both dialects: CloudFormation templates (YAML/JSON, including SAM and `cdk synth` output) are normalised into the same internal representation the Terraform parser produces, so a mixed directory - a Terraform module next to a SAM template - scans as one estate. The release also adds report branding, restructures finding output into labelled context lines, and folds in SARIF and PDF fixes.

### Added

- **CloudFormation scanning.** `.yaml`, `.yml`, and `.json` templates are parsed, their intrinsics resolved where static, and fed through the same two-phase rule engine as Terraform. An inline `AWS::S3::Bucket` is split into the TF-shaped companion resources (encryption / versioning / lifecycle / object-lock) so the existing S3 rules evaluate it with no rule changes.
- **`--input <mode>` flag** (`auto` | `tf` | `cfn`, default `auto`). `auto` detects dialect per file by extension **plus content shape** - a `.json` is treated as CloudFormation only if it declares `AWSTemplateFormatVersion`, a `Transform`, or a `Resources` map of `AWS::*` types, so a `package.json` or Kubernetes manifest is skipped rather than misparsed. `tf` / `cfn` force a single dialect for CI pipelines that need a hard guarantee about what was scanned.
- **Static intrinsic resolution** for `!Ref` to defaulted parameters and all-static `!Sub` / `!Join` / `!FindInMap` / `!Select` / `!Split` / `!Base64`. Non-static intrinsics resolve to `INCONCLUSIVE` with a precise reason code: `cfn-import-value` (`Fn::ImportValue`), `cfn-dynamic-reference` (`{{resolve:ssm:...}}`), `cfn-pseudo-parameter`, and `cfn-fn-not-static` (`Fn::If` and friends).
- **Mixed-source reports.** Each finding carries a `[terraform]` / `[cloudformation]` chip so a single report over a mixed estate stays unambiguous about which dialect a finding came from.
- **infrarails branding** - an SVG logo now heads the README and the HTML / PDF reports.

### CloudFormation honesty (deliberate INCONCLUSIVEs)

The scanner stays conservative about what a static read of CloudFormation can and cannot prove:

- **`Conditions` are never evaluated.** A resource guarded by `Condition:` may not exist at deploy time, so rules report it `INCONCLUSIVE` (`cfn-condition-gated`) rather than trusting its properties.
- **Bedrock invocation logging cannot be declared in CloudFormation** - there is no CFN resource type for it (AWS's own pattern uses a Lambda-backed custom resource). When all Bedrock usage is CFN-sourced and no logging config is in scope, `S-12.1.1` stays `INCONCLUSIVE` even under `--strict-account-logging`, and the remediation points at `PutModelInvocationLoggingConfiguration` or a Terraform stack.
- **Nested stacks** (`AWS::CloudFormation::Stack`) are treated like remote Terraform modules: not fetched, flagged by `S-12.x.5` when they look Bedrock-related. `Fn::ImportValue` of a baseline-named export counts as cross-stack evidence the same way `terraform_remote_state` does.
- **A malformed file that plausibly *is* a CFN template is a hard error (exit `2`), not a silent skip.**
- **`--plan` stays Terraform-only.** CloudFormation change sets are a separate, future feature.

### Changed / Fixed

- **Finding output restructured into labelled context lines.** Findings now carry structured `context[]` / `scopeNote` fields instead of concatenating supporting detail into one description string. The terminal / HTML / PDF formatters render these as aligned labelled rows (e.g. "Still enforcing", "Not configured", "Attachment", "Scope"), so the verdict line stays terse and the supporting evidence is scannable. Affects `S-9.x.3` and the Bedrock-logging findings.
- **SARIF and PDF fixes** rolled in alongside the dual-IaC work, with new formatter regression tests.

### Verification

- **500/500 unit + e2e tests pass** (up from 397 in v0.3.0), including new CloudFormation suites: template parsing, intrinsic resolution, normalisation into the shared shape, presentation / chip rendering, end-to-end CFN scans, and mixed TF + CFN fixtures.

### Docs

- README gains a **Supported inputs** table, a CloudFormation-specifics section, and per-dialect verdict rows in "How the scanner handles your code"; ARCHITECTURE documents the normalisation layer. Sample PDF screenshots were regenerated against current output.

---

## v0.3.0 — Guardrail-body enforcement (Article 9) and corrected retention citations

This release completes the Bedrock guardrail progression — *presence → attachment → **body*** — with a new rule that inspects what a guardrail actually does, not just that one exists. It also corrects two regulatory citations to the Articles the obligations genuinely come from, fixes a finding-formatter bug that silently dropped articles from multi-citation rules, and makes `--plan` resolution more reliable for module-buried resources.

### Added

- **`S-9.x.3` (WARN) — guardrail-body enforcement.** `S-9.x.1`/`S-9.x.2` confirm a guardrail is *attached* and *declared* but never look inside it, so a guardrail with every action set to `NONE` passed both while providing no control surface. `S-9.x.3` inspects each `aws_bedrock_guardrail` body with a tiered model:
  - **Mandatory surfaces gate the verdict** — a `PROMPT_ATTACK` prompt-injection filter and a harmful-content filter at `MEDIUM`/`HIGH`.
  - **Supporting surfaces are scored as context, never penalised on absence** — PII (including `ANONYMIZE`), contextual grounding, and denied topics.
  - `var`/`local` values are resolved via the resolver; a mandatory surface backed by an unresolvable expression is `INCONCLUSIVE` and carries `unresolvedReason`, so strict-mode escalation works.
  - Findings name the **attaching agents** (blast radius) and append an SDK-blind-spot note for unattached guardrails.
  - Citations verified verbatim against the EU AI Act vault: **Art. 9(2)(d), 9(5)(b), 15(4), 15(5) para 3**.
- **`buildGuardrailGraph` helper** — a shared agent ↔ guardrail reference graph now backs both the attachment rule (`S-9.x.1`) and the new body rule.

### Changed / Fixed

- **Retention rules now cite the correct Article.** `S-12.1.2a` (CloudWatch retention) and `S-12.1.2b` (S3 lifecycle) previously attributed their duration floor to Article 12 and said "no specific number is named." The 180-day floor actually derives from **Art. 19(1)** — logs "shall be kept for a period appropriate to the intended purpose … of at least six months." Remediation text, header comments, and `regulatoryReference` metadata in both rules now cite Art. 19(1) with the correct quote. **Rule IDs and verdict logic are unchanged.**
- **`S-9.x.1` no longer mis-flags a resolvable reference.** A guardrail reference that resolves to a declared resource now `PASS`es (it was wrongly `INCONCLUSIVE` because of the `${…}` wrapper); a reference to an external/undeclared guardrail `WARN`s.
- **`S-9.x.2` is plan-overlay aware.** A guardrail declared inside a module — visible only in the plan, not the raw HCL of the scanned directory — used to trip a false "no guardrail declared" WARN while `S-9.x.3` was busy inspecting that same guardrail's body. The presence lookup now threads `context.planOverlay` so both rules agree on whether the guardrail exists, and the WARN's `filePath` anchors to the triggering Bedrock resource instead of repo root.
- **Multi-article citation pills no longer mangle or drop articles.** The finding formatter split EU AI Act citations on the first ` - `, assuming a single-citation shape. `S-9.x.3` cites four articles in paren form, so the parser swallowed the prose into the id and silently dropped `Art. 9(5)(b)`, `15(4)`, and `15(5)`. Citations now render one numbers-only pill per article. This also restores the dropped second article on dash-form multi-citations (`s3-versioning`, `s3-encryption`). Raw `regulatoryReference` in JSON/SARIF output is untouched.

### Plan-mode (`--plan`) resolution

- **Configuration reference graph.** The plan parser now distils the plan `configuration` block into a pre-qualified edge graph (resource-attribute, module-output, and call-site variable bindings). Because it records what an attribute *references* rather than what it resolves to, the graph survives `known-after-apply`, letting bucket/log-group matching anchor on HCL identity for module-buried and computed-name resources. This keeps `--plan` strictly *more* informative than a source-only scan, never less certain. See the new `module-computed-bucket` fixture.

### Internal

- **CLI version is injected from `package.json` at build time** via tsup (`__APP_VERSION__`), replacing a hardcoded literal that had drifted to `0.2.1`.
- Package description broadened to "Article 9 & 12".
- README and ARCHITECTURE updated for the guardrail-body rule and plan-mode resolution.

### Verification

- **397/397 unit + e2e tests pass** (up from 317 in v0.2.1), including new suites for the guardrail graph, the hard-rails rule, the config-reference plan parser, and the formatter citation regressions.

---

## v0.2.1 — SARIF output compatible with GitHub Code Scanning

Hot-fix for SARIF reports rejected by `github/codeql-action/upload-sarif` when the scanner was run with `--plan`. Two GitHub-specific ingestion rules were being violated by the v0.2.0 emitter — both now satisfied.

### Fixed

- **`plan:<address>` URIs no longer leak into SARIF output.** Findings sourced from the Terraform plan overlay (resources buried in remote modules, deletion findings) previously emitted `artifactLocation.uri` values like `plan:module.foo.aws_X.y`. GitHub Code Scanning treats unknown URI schemes as unresolvable, silently strips the location, and then drops the entire result for having no remaining locations. These are now rewritten to a synthetic `%SRCROOT%`-anchored location with the original plan address preserved in `properties.planAddress` so audit citations are not lost.
- **Results with zero locations are no longer emitted.** Tree-wide PASS/SKIP/INCONCLUSIVE findings (e.g. "no Bedrock in scanned tree", "plan does not destroy any resources") used to ship with `locations: []`, triggering GitHub's `locationFromSarifResult: expected at least one location` rejection. They now carry a synthetic scan-root anchor so the upload succeeds and the finding surfaces at directory level.
- **`originalUriBaseIds` declared on each run.** Anchors all `%SRCROOT%`-bearing relative URIs against the checkout root in line with the SARIF 2.1.0 spec and CodeQL convention.
- **Defensive invariant.** The emitter now throws if any result is constructed without ≥1 location, so future regressions fail loudly in tests rather than silently producing GitHub-rejected SARIF.

### Behaviour notes for existing users

- **No-`--plan` runs are byte-identical to v0.2.0** for every HCL-anchored URI. The only additive changes are the new `originalUriBaseIds` block on the run and synthetic locations on the handful of tree-wide PASS/SKIP findings that GitHub was already discarding.
- **JSON, terminal, HTML, and PDF output are unchanged.** `Finding.filePath` retains the `plan:<address>` form for these formats — the rewrite is scoped to the SARIF emitter only.
- **CI consumers using `github/codeql-action/upload-sarif` no longer need the `jq` post-processing workaround** described in the issue tracker. Strip it from your workflow once you upgrade.

### Verification

- 317/317 unit + e2e tests pass (5 new SARIF regression tests).
- All four GitHub-rejection invariants validated against real plan-mode fixture output: no `plan:` URIs leak, every result has ≥1 location, `originalUriBaseIds["%SRCROOT%"]` is declared, plan addresses preserved in `properties.planAddress`.

### Caveat

Plan-only findings (resources discovered only via `--plan`, with no on-disk HCL) surface as directory-level alerts rather than file-anchored PR annotations, because there is no `.tf` line number to point at. This is strictly better than the v0.2.0 behaviour of dropping them entirely. A future release may map plan addresses back to HCL when source is available.

---

## v0.1.0 — Initial release

`infrarails` v0.1.0 is the first public release: a static compliance scanner for AWS AI infrastructure declared in Terraform. It reads `.tf` and `.tf.json` source files and reports whether the AWS Bedrock primitives backing **EU AI Act** Article 9 (risk management) and Article 12 (logging and traceability) are in place, with cross-references to **NIST AI RMF 1.0** and **ISO/IEC 42001:2023**.

> See [README.md](README.md) for the full feature description, install instructions, and rule reference.

### Highlights

- **9 compliance rules** mapped to EU AI Act Articles 9 & 12, with NIST AI RMF and ISO/IEC 42001 cross-references on every finding.
- **Two-phase rule engine** — Phase 1 builds a `ScanContext` (the buckets and log groups Bedrock writes to); Phase 2 rules consume that context to scope their checks.
- **Conservative-by-design verdicts** — `INCONCLUSIVE` is a first-class status, not a hidden pass. When the scanner cannot prove a control, it says so.
- **Forwarder-aware retention checks** — `S-12.1.2a` detects `aws_cloudwatch_log_subscription_filter` targeting the Bedrock log group and adjusts its WARN message accordingly.
- **Cross-stack topology handling** — `--strict-account-logging` flips missing-logging from `INCONCLUSIVE` to `FAIL` for teams whose scanned tree is the whole estate; the default avoids false positives for account-baseline patterns.
- **Local modules walked transparently; remote modules flagged** via `S-12.x.5` (`INCONCLUSIVE` per remote source — registry/git/http/bitbucket).
- **Variable, local, and resource-attribute resolution** with module-scoped variable lookup (no cross-module variable bleed) and explicit reason codes for unresolvable expressions (`var-no-default`, `data-source-ssm`, `module-output`, `complex-interpolation`).
- **Four output formats**: `terminal` (colour-coded, grouped by status), `json` (machine-readable for CI), `html` (single-file, collapsible sections, framework pills, print CSS), and `pdf` (paginated, `pdfkit`-rendered, no headless Chromium).
- **Cross-platform**: native macOS, Linux, and Windows (PowerShell / `cmd.exe`); WSL supported.
- **Three exit codes** for clean CI gating: `0` clean, `1` blocking findings (FAIL/WARN; plus INCONCLUSIVE under default strict mode), `2` tool error.

### Rules in this release

| Rule ID | Severity | Article | Check |
|---|---|---|---|
| `S-9.x.1` | FAIL | 9 | Bedrock Agents must have a versioned guardrail attached (numbered version, not `DRAFT`) |
| `S-9.x.2` | WARN | 9 | When Bedrock is in use, at least one `aws_bedrock_guardrail` should be declared in the scanned tree |
| `S-12.1.1` | FAIL | 12 | AWS Bedrock model invocation logging is configured when Bedrock is in use |
| `S-12.1.2a` | WARN | 12 | CloudWatch retention >= 180 days, or a forwarder subscription filter is detected |
| `S-12.1.2b` | FAIL | 12 | S3 lifecycle policy >= 180 days (FAIL <180; WARN 180–364; PASS >=365) |
| `S-12.x.1` | FAIL | 12 | S3 log bucket has versioning (or object lock) enabled |
| `S-12.x.2a` | FAIL | 12 | S3 log bucket has KMS server-side encryption configured |
| `S-12.x.4` | FAIL | 12 | A CloudTrail trail is present and enabled |
| `S-12.x.5` | WARN | 12 | Flags remote modules whose contents the scanner cannot inspect |

### CLI

```bash
infrarails <directory> [options]
```

| Flag | Description |
|---|---|
| `-f, --format <terminal\|json\|html\|pdf>` | Output format. `pdf` requires `-o`. |
| `-o, --output <file>` | Write the rendered report to a file. |
| `--no-strict` | Treat `INCONCLUSIVE` as non-blocking. |
| `--strict-account-logging` | Treat missing Bedrock logging as `FAIL` instead of `INCONCLUSIVE`. |
| `--version`, `-h, --help` | Standard. |

### Install

```bash
# npm (recommended)
npm install -g infrarails

# Prerequisite on PATH
brew install hcl2json   # macOS — see README for Linux/Windows
```

Requires Node 18+ to run the published CLI; contributors running the test suite need Node 20.x, 22.x, or 24+ (vitest 4.x).

### Known limitations

- Static IaC scanning only — runtime guardrail attachment via the `InvokeModel` / `Converse` SDK `guardrailIdentifier` parameter is **not** verifiable from Terraform and is explicitly out of scope (called out in `S-9.x.1` / `S-9.x.2` remediation messages).
- Remote modules (registry, git, http, bitbucket) are flagged but never fetched.
- Expressions backed by SSM data sources, module outputs, or complex interpolations resolve to `INCONCLUSIVE` with a reason code rather than a confident verdict.
- A fully passing run is a **necessary but not sufficient** condition for EU AI Act / NIST AI RMF / ISO 42001 conformance. See the disclaimer in [README.md](README.md#disclaimer).

### What's next

- **Sprint 1B (in progress)** — `--plan` mode: scan `terraform show -json` plan/state output. Plan output contains fully-resolved values, which eliminates most `INCONCLUSIVE` findings and is the recommended path for CI compliance gates.
- **Sprint 1C (planned)** — CDK and CloudFormation support; additional Bedrock Agent guardrail rules.

### License

Apache-2.0. See [LICENSE](LICENSE).
