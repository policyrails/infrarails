import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { ensureHcl2Json } from './utils/hcl2json-check';
import { IacInputMode, parseAllIaCFiles } from './parser';
import { runScan } from './runner';
import { parsePlanFile } from './plan-parser';
import { PlanOverlay } from './types';
import { formatTerminal, formatJson, formatHtml, formatPdf, formatSarif } from './formatter';
import { applyCfnPresentation } from './cfn/presentation';

// Injected at build time by tsup from package.json (see tsup.config.ts).
declare const __APP_VERSION__: string;

const program = new Command();

program
  .name('infrarails')
  .description('Scan Terraform and CloudFormation files for EU AI Act Article 12 compliance gaps')
  .version(__APP_VERSION__)
  .argument('<directory>', 'Directory containing Terraform (.tf/.tf.json) and/or CloudFormation (.yaml/.yml/.json) files')
  .option(
    '-f, --format <format>',
    'Output format: terminal, json, sarif, html, pdf',
    'terminal',
  )
  .option('-o, --output <file>', 'Write report to a file (required for pdf)')
  .option(
    '--no-strict',
    'Treat INCONCLUSIVE as PASS for exit code (default: exit 1)',
  )
  .option(
    '--strict-account-logging',
    'Assert the scanned tree is the entire estate: escalates missing-logging and forwarder-less retention findings to FAIL. With --plan, also escalates user-fixable INCONCLUSIVE findings to FAIL.',
    false,
  )
  .option(
    '--plan <file>',
    'Terraform plan JSON (`terraform show -json tfplan.bin`) — resolves variables and scans resources inside modules',
  )
  .option(
    '--input <mode>',
    'Input dialect: auto (detect per file), tf (Terraform only), cfn (CloudFormation only)',
    'auto',
  )
  .addHelpText(
    'after',
    `
Examples
  $ infrarails ./terraform
  $ infrarails ./terraform --plan tfplan.json -f sarif -o report.sarif
  $ infrarails ./terraform --no-strict          # don't fail CI on INCONCLUSIVE

Exit codes
  0  all PASS (or --no-strict with no FAIL/WARN)
  1  any FAIL/WARN, or INCONCLUSIVE in strict mode (default)
  2  usage/parse error

Strict flags (independent axes)
  --no-strict                only affects exit code
  --strict-account-logging   only affects finding status (needs --plan)
`,
  )
  .action(async (
    directory: string,
    options: {
      format: string;
      output?: string;
      strict: boolean;
      strictAccountLogging: boolean;
      plan?: string;
      input: string;
    },
  ) => {
    const VALID_INPUT_MODES: IacInputMode[] = ['auto', 'tf', 'cfn'];
    if (!VALID_INPUT_MODES.includes(options.input as IacInputMode)) {
      console.error(
        `Error: unknown input mode "${options.input}". Valid modes: ${VALID_INPUT_MODES.join(', ')}.`,
      );
      process.exit(2);
    }
    const inputMode = options.input as IacInputMode;

    // Check hcl2json is installed (needed for the Terraform path only).
    if (inputMode !== 'cfn') ensureHcl2Json();

    // Validate format up-front - silent fall-through to terminal mode hides bugs
    // (e.g. an older globally-installed binary asked for "pdf" and writes ANSI
    // text into a .pdf file, producing an unopenable artifact).
    const VALID_FORMATS = ['terminal', 'json', 'sarif', 'html', 'pdf'];
    if (!VALID_FORMATS.includes(options.format)) {
      console.error(
        `Error: unknown format "${options.format}". Valid formats: ${VALID_FORMATS.join(', ')}.`,
      );
      process.exit(2);
    }

    // PDF is binary - it cannot be sensibly streamed to a terminal, so require -o.
    if (options.format === 'pdf' && !options.output) {
      console.error(
        'Error: --format pdf requires an output file. Pass -o report.pdf.',
      );
      process.exit(2);
    }

    // Resolve directory path
    const dir = path.resolve(directory);
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      console.error(`Error: "${dir}" is not a valid directory.`);
      process.exit(2);
    }

    // Validate and parse --plan up-front. Failures are exit-code-2 with
    // explicit stderr so CI users see the problem instead of silent
    // fall-through to source-only mode.
    let overlay: PlanOverlay | undefined;
    if (options.plan) {
      const planPath = path.resolve(options.plan);
      if (!fs.existsSync(planPath) || !fs.statSync(planPath).isFile()) {
        console.error(`Error: plan file not found: ${planPath}`);
        process.exit(2);
      }
      try {
        overlay = parsePlanFile(planPath);
      } catch (err) {
        console.error(
          `Error: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exit(2);
      }
      if (overlay.flags.noActionableChanges) {
        console.error(
          'Note: plan has no create/update/delete actions (refresh-only, or current ' +
            'state already matches config). Compliance verdicts reflect current cloud ' +
            'state as known to Terraform; deletion-safety analysis is skipped. Rerun ' +
            'against a normal apply plan if you need to verify post-apply compliance.',
        );
      }
      console.error(
        `Info: plan overlay loaded (${overlay.resources.size} resources, ` +
          `${overlay.deletions.size} deletions, ${overlay.variables.size} variables).`,
      );
    }

    // Collect and parse all IaC files (Terraform + CloudFormation).
    // Malformed CFN templates are a hard error (exit 2): a compliance scanner
    // must not silently skip a template it was pointed at.
    let parsedFiles;
    try {
      parsedFiles = parseAllIaCFiles(dir, inputMode);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(2);
    }
    if (parsedFiles.length === 0) {
      console.log('No Terraform or CloudFormation files found in the specified directory.');
      process.exit(0);
    }

    // Run scan. Findings are composed in the canonical TF vocabulary; the
    // presentation pass re-voices CFN-sourced findings in CFN vocabulary
    // (AWS::Bedrock::Guardrail "GR", GuardrailVersion, ...) for every output
    // format, leaving TF-sourced findings untouched.
    const findings = applyCfnPresentation(
      runScan(parsedFiles, {
        strictAccountLogging: options.strictAccountLogging,
        plan: overlay,
      }),
      parsedFiles.map((f) => f.filePath),
    );

    // Format output - PDF is a Buffer, others are strings.
    let rendered: string | Buffer;
    if (options.format === 'json') {
      rendered = formatJson(findings);
    } else if (options.format === 'sarif') {
      rendered = formatSarif(findings);
    } else if (options.format === 'html') {
      rendered = formatHtml(findings);
    } else if (options.format === 'pdf') {
      try {
        rendered = await formatPdf(findings);
      } catch (err) {
        console.error(
          `Error generating PDF: ${err instanceof Error ? err.message : String(err)}`,
        );
        process.exit(2);
      }
    } else {
      rendered = formatTerminal(findings);
    }

    if (options.output) {
      const outPath = path.resolve(options.output);
      // Buffer for PDF, utf-8 string for everything else.
      if (Buffer.isBuffer(rendered)) {
        fs.writeFileSync(outPath, rendered);
      } else {
        fs.writeFileSync(outPath, rendered, 'utf-8');
      }
      console.error(`Report written to ${outPath}`);
    } else {
      // Only string outputs reach this branch - PDF is gated above.
      console.log(rendered as string);
      // Footgun guard: if user asked for html/json without -o and stdout is a TTY,
      // they probably forgot to redirect and just dumped raw markup into the
      // terminal. Print a one-line tip to stderr so it does not contaminate
      // piped output.
      if (
        (options.format === 'html' ||
          options.format === 'json' ||
          options.format === 'sarif') &&
        process.stdout.isTTY
      ) {
        console.error(
          `\nTip: pass -o report.${options.format} to save the report to a file instead of printing to the terminal.`,
        );
      }
      // Discoverability hint when running in the default terminal format from a TTY.
      // Skipped on pipes/redirects so scripted invocations stay clean. PDF is
      // recommended for sharing because Windows SmartScreen flags HTML on UNC
      // paths (\\wsl.localhost\..., network shares) but not PDFs.
      if (options.format === 'terminal' && process.stdout.isTTY) {
        console.error(
          '\nTip: also available as --format json | sarif | html | pdf (use -o report.<ext> to save).' +
            '\n     SARIF uploads to GitHub Code Scanning; PDF is recommended for sharing.',
        );
      }
    }

    // Exit code: 1 for FAIL/WARN, plus INCONCLUSIVE in strict mode (default).
    // INCONCLUSIVE is treated as blocking by default because for a compliance tool,
    // "we couldn't verify" should not be reported as PASS to a CI pipeline.
    const hasBlocking = findings.some(
      (f) =>
        f.status === 'FAIL' ||
        f.status === 'WARN' ||
        (options.strict && f.status === 'INCONCLUSIVE'),
    );
    process.exit(hasBlocking ? 1 : 0);
  });

program.parse();
