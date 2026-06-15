// ---------------------------------------------------------------------------
// CFN intrinsic-function translation.
//
// Converts canonicalised CFN values ({ Ref: X }, { 'Fn::GetAtt': [...] }, ...)
// into the Terraform-shaped strings the rest of the pipeline already speaks:
//
//   { Ref: <Parameter> }            -> "${var.<Parameter>}"
//   { Ref: <Resource> }             -> "${<tf_type>.<LogicalId>.id}"
//   { 'Fn::GetAtt': [id, 'Arn'] }   -> "${<tf_type>.<LogicalId>.arn}"
//   { 'Fn::Sub': '${P}-x' }         -> "${var.P}-x"  (composite -> resolver
//                                      reports complex-interpolation, same as TF)
//   all-static Join/Select/Split/   -> resolved literal
//     Base64/FindInMap
//
// Anything CloudFormation cannot answer statically becomes a *sentinel*
// expression "${cfn:<reason-slug>:<detail>}" that src/resolver.ts maps to a
// precise UnresolvableReason (cfn-import-value, cfn-dynamic-reference,
// cfn-pseudo-parameter, cfn-fn-not-static) -> INCONCLUSIVE, never a
// fabricated value. This mirrors how unresolvable Terraform expressions are
// reported and keeps the "honest about gaps" contract from the design doc.
// ---------------------------------------------------------------------------

/** Marker for { Ref: 'AWS::NoValue' } - the property is treated as unset. */
export const NO_VALUE: unique symbol = Symbol('cfn-no-value');

export type CfnSentinelSlug =
  | 'import-value'
  | 'dynamic-reference'
  | 'pseudo-parameter'
  | 'fn-not-static'
  | 'complex';

export function cfnSentinel(slug: CfnSentinelSlug, detail: string): string {
  // Strip characters that would break the ${...} wrapper.
  const safe = detail.replace(/[${}]/g, '').trim();
  return `\${cfn:${slug}:${safe}}`;
}

export interface TranslationContext {
  /** Parameter name -> declaration ({ Type, Default, ... }). */
  parameters: Record<string, Record<string, unknown>>;
  /** Logical id -> mapped Terraform type, or undefined when unmapped. */
  resourceTfType: Map<string, string | undefined>;
  /** Mappings section, for static Fn::FindInMap resolution. */
  mappings: Record<string, unknown>;
}

/**
 * Translate a canonicalised CFN value into its TF-shaped equivalent.
 * Recurses through arrays/objects; may return NO_VALUE for Ref AWS::NoValue
 * (callers drop the property).
 */
export function translateValue(value: unknown, ctx: TranslationContext): unknown {
  if (value === null || value === undefined) return value;

  if (typeof value === 'string') {
    // CFN dynamic references ({{resolve:ssm:/path}}) live inside plain strings.
    if (value.includes('{{resolve:')) {
      return cfnSentinel('dynamic-reference', value);
    }
    return value;
  }
  if (typeof value !== 'object') return value;

  if (Array.isArray(value)) {
    return value.map((v) => translateValue(v, ctx)).filter((v) => v !== NO_VALUE);
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length === 1 && (keys[0] === 'Ref' || keys[0] === 'Condition' || keys[0].startsWith('Fn::'))) {
    return translateIntrinsic(keys[0], obj[keys[0]], ctx);
  }

  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj)) {
    const translated = translateValue(v, ctx);
    if (translated !== NO_VALUE) out[k] = translated;
  }
  return out;
}

function translateIntrinsic(fn: string, arg: unknown, ctx: TranslationContext): unknown {
  switch (fn) {
    case 'Ref':
      return translateRef(arg, ctx);
    case 'Fn::GetAtt':
      return translateGetAtt(arg, ctx);
    case 'Fn::Sub':
      return translateSub(arg, ctx);
    case 'Fn::ImportValue':
      return translateImportValue(arg, ctx);
    case 'Fn::If': {
      const cond = Array.isArray(arg) && typeof arg[0] === 'string' ? arg[0] : '';
      return cfnSentinel('fn-not-static', `If ${cond}`.trim());
    }
    case 'Fn::FindInMap':
      return translateFindInMap(arg, ctx);
    case 'Fn::Join':
      return translateJoin(arg, ctx);
    case 'Fn::Select':
      return translateSelect(arg, ctx);
    case 'Fn::Split':
      return translateSplit(arg, ctx);
    case 'Fn::Base64':
      return translateBase64(arg, ctx);
    case 'Fn::GetAZs':
    case 'Fn::Cidr':
    case 'Condition':
      return cfnSentinel('fn-not-static', fn.replace(/^Fn::/, ''));
    default:
      return cfnSentinel('fn-not-static', fn.replace(/^Fn::/, ''));
  }
}

function translateRef(arg: unknown, ctx: TranslationContext): unknown {
  if (typeof arg !== 'string') return cfnSentinel('fn-not-static', 'Ref');
  if (arg === 'AWS::NoValue') return NO_VALUE;
  if (arg.startsWith('AWS::')) return cfnSentinel('pseudo-parameter', arg);
  if (Object.prototype.hasOwnProperty.call(ctx.parameters, arg)) {
    return `\${var.${arg}}`;
  }
  if (ctx.resourceTfType.has(arg)) {
    const tfType = ctx.resourceTfType.get(arg);
    if (tfType) return `\${${tfType}.${arg}.id}`;
    return cfnSentinel('fn-not-static', `Ref ${arg}`);
  }
  return cfnSentinel('fn-not-static', `Ref ${arg}`);
}

function translateGetAtt(arg: unknown, ctx: TranslationContext): unknown {
  let logicalId: string | undefined;
  let attr: string | undefined;
  if (Array.isArray(arg) && typeof arg[0] === 'string') {
    logicalId = arg[0];
    attr = arg
      .slice(1)
      .map((a) => String(a))
      .join('.');
  } else if (typeof arg === 'string') {
    const dot = arg.indexOf('.');
    logicalId = dot === -1 ? arg : arg.slice(0, dot);
    attr = dot === -1 ? '' : arg.slice(dot + 1);
  }
  if (!logicalId) return cfnSentinel('fn-not-static', 'GetAtt');

  const tfType = ctx.resourceTfType.get(logicalId);
  // Dotted attributes (nested-stack Outputs.X) and unmapped resource types
  // cannot be expressed as a TF reference - keep the honest sentinel.
  if (!tfType || !attr || attr.includes('.')) {
    return cfnSentinel('fn-not-static', `GetAtt ${logicalId}.${attr ?? ''}`);
  }
  return `\${${tfType}.${logicalId}.${pascalToSnake(attr)}}`;
}

function translateImportValue(arg: unknown, ctx: TranslationContext): unknown {
  const name = translateValue(arg, ctx);
  if (typeof name === 'string' && !name.includes('${')) {
    return cfnSentinel('import-value', name);
  }
  return cfnSentinel('import-value', '(dynamic export name)');
}

const SUB_PIECE = /\$\{([^}]+)\}/g;

function translateSub(arg: unknown, ctx: TranslationContext): unknown {
  let template: string | undefined;
  let vars: Record<string, unknown> = {};
  if (typeof arg === 'string') {
    template = arg;
  } else if (Array.isArray(arg) && typeof arg[0] === 'string') {
    template = arg[0];
    if (arg[1] !== null && typeof arg[1] === 'object' && !Array.isArray(arg[1])) {
      vars = arg[1] as Record<string, unknown>;
    }
  }
  if (template === undefined) return cfnSentinel('fn-not-static', 'Sub');

  let staticText = '';
  let pieceCount = 0;
  let unresolvedPiece: string | undefined;
  const out = template.replace(SUB_PIECE, (whole, inner: string) => {
    // ${!Literal} is CFN's escape for a literal "${Literal}".
    if (inner.startsWith('!')) return `\${${inner.slice(1)}}`;
    pieceCount++;
    const name = inner.trim();

    if (Object.prototype.hasOwnProperty.call(vars, name)) {
      const translated = translateValue(vars[name], ctx);
      if (
        typeof translated === 'number' ||
        typeof translated === 'boolean' ||
        (typeof translated === 'string' && !translated.includes('${'))
      ) {
        return String(translated);
      }
      if (typeof translated === 'string') return translated; // a ${...} ref piece
      unresolvedPiece = name;
      return whole;
    }
    if (name.startsWith('AWS::')) {
      unresolvedPiece = name;
      return whole; // pseudo parameter - non-static piece
    }
    if (Object.prototype.hasOwnProperty.call(ctx.parameters, name)) {
      return `\${var.${name}}`;
    }
    const dot = name.indexOf('.');
    const logicalId = dot === -1 ? name : name.slice(0, dot);
    const attr = dot === -1 ? 'id' : name.slice(dot + 1);
    const tfType = ctx.resourceTfType.get(logicalId);
    if (tfType && !attr.includes('.')) {
      return `\${${tfType}.${logicalId}.${dot === -1 ? 'id' : pascalToSnake(attr)}}`;
    }
    unresolvedPiece = name;
    return whole;
  });
  staticText = template.replace(SUB_PIECE, '');

  if (!out.includes('${')) return out; // everything substituted to literals

  // A template that is exactly one unresolvable piece with no static text
  // gets a precise sentinel instead of a vague complex-interpolation.
  if (pieceCount === 1 && unresolvedPiece && staticText === '') {
    return unresolvedPiece.startsWith('AWS::')
      ? cfnSentinel('pseudo-parameter', unresolvedPiece)
      : cfnSentinel('fn-not-static', `Sub \${${unresolvedPiece}}`);
  }
  // Composite (or single TF-style ref spanning the whole string): hand the
  // string to the resolver, which treats it exactly like the TF equivalent.
  return out;
}

function translateFindInMap(arg: unknown, ctx: TranslationContext): unknown {
  if (!Array.isArray(arg) || arg.length < 3) return cfnSentinel('complex', 'FindInMap');
  const [m, k1, k2] = arg.map((a) => translateValue(a, ctx));
  if (
    typeof m === 'string' &&
    typeof k1 === 'string' &&
    typeof k2 === 'string' &&
    !m.includes('${') &&
    !k1.includes('${') &&
    !k2.includes('${')
  ) {
    const map = ctx.mappings[m];
    if (map !== null && typeof map === 'object' && !Array.isArray(map)) {
      const level1 = (map as Record<string, unknown>)[k1];
      if (level1 !== null && typeof level1 === 'object' && !Array.isArray(level1)) {
        const found = (level1 as Record<string, unknown>)[k2];
        if (found !== undefined) return translateValue(found, ctx);
      }
    }
  }
  return cfnSentinel('complex', 'FindInMap');
}

function translateJoin(arg: unknown, ctx: TranslationContext): unknown {
  if (!Array.isArray(arg) || arg.length !== 2 || typeof arg[0] !== 'string' || !Array.isArray(arg[1])) {
    return cfnSentinel('complex', 'Join');
  }
  const delimiter = arg[0];
  const pieces: string[] = [];
  for (const item of arg[1]) {
    const t = translateValue(item, ctx);
    if (t === NO_VALUE) continue;
    if (typeof t === 'string' || typeof t === 'number' || typeof t === 'boolean') {
      pieces.push(String(t));
    } else {
      return cfnSentinel('complex', 'Join');
    }
  }
  // All-literal joins collapse to a literal; joins containing ${...} pieces
  // become a composite string the resolver reports as complex-interpolation
  // (or resolves, when the composite is a single full-string reference).
  return pieces.join(delimiter);
}

function translateSelect(arg: unknown, ctx: TranslationContext): unknown {
  if (!Array.isArray(arg) || arg.length !== 2) return cfnSentinel('complex', 'Select');
  const idx = typeof arg[0] === 'string' ? Number(arg[0]) : arg[0];
  const list = translateValue(arg[1], ctx);
  if (typeof idx === 'number' && Number.isInteger(idx) && Array.isArray(list) && idx >= 0 && idx < list.length) {
    return list[idx];
  }
  return cfnSentinel('complex', 'Select');
}

function translateSplit(arg: unknown, ctx: TranslationContext): unknown {
  if (!Array.isArray(arg) || arg.length !== 2 || typeof arg[0] !== 'string') {
    return cfnSentinel('complex', 'Split');
  }
  const target = translateValue(arg[1], ctx);
  if (typeof target === 'string' && !target.includes('${')) {
    return target.split(arg[0]);
  }
  return cfnSentinel('complex', 'Split');
}

function translateBase64(arg: unknown, ctx: TranslationContext): unknown {
  const target = translateValue(arg, ctx);
  if (typeof target === 'string' && !target.includes('${')) {
    return Buffer.from(target, 'utf-8').toString('base64');
  }
  return cfnSentinel('complex', 'Base64');
}

/**
 * PascalCase / camelCase -> snake_case with acronym handling:
 * "SSEAlgorithm" -> "sse_algorithm", "KMSMasterKeyID" -> "kms_master_key_id",
 * "RetentionInDays" -> "retention_in_days", "Arn" -> "arn".
 */
export function pascalToSnake(name: string): string {
  return name
    .replace(/([A-Z]+)(?=[A-Z][a-z])/g, '$1_')
    .replace(/([a-z0-9])(?=[A-Z])/g, '$1_')
    .toLowerCase();
}
