#!/usr/bin/env node
// email-domain-check firma.ee [--lang en] [--json] [--selector name,...]
//
// Prints what email-domain-check.mjs finds. Exit code 1 means an error was
// found or the check could not run.
import { checkEmailDomain, CheckError, VERSION } from './email-domain-check.mjs';

const USAGE = `email-domain-check ${VERSION}: reads a domain's public e-mail records (MX, SPF, DKIM, DMARC, MTA-STS).

  email-domain-check firma.ee [--lang en] [--json] [--selector name,...]

  --lang en          English texts (Estonian by default)
  --json             the whole report as JSON
  --selector names   also look for these DKIM key names, comma-separated
                     (a sent message names its key: DKIM-Signature: s=...)

It only asks public DNS. Exit code 1 means an error was found or the check
could not run.`;

function parseArgs(argv) {
  const opts = { lang: 'et', json: false, selectors: [], input: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') opts.help = true;
    else if (arg === '--json') opts.json = true;
    else if (arg === '--lang') opts.lang = argv[++i] === 'en' ? 'en' : 'et';
    else if (arg === '--selector') opts.selectors.push(...String(argv[++i] ?? '').split(','));
    else if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`);
    else if (opts.input === null) opts.input = arg;
    else throw new Error(`one domain at a time (${arg})`);
  }
  return opts;
}

const MARK = { ok: '✓', info: '·', warn: '!', error: '✗' };
const COLOR = { ok: 32, info: 2, warn: 33, error: 31 };

/** The report as terminal text, coloured when the output is a terminal. */
export function format(report, { color = false } = {}) {
  const paint = (status, text) => (color ? `\x1b[${COLOR[status]}m${text}\x1b[0m` : text);
  const lines = [report.domain, ''];
  for (const f of report.findings) {
    lines.push(`${paint(f.status, MARK[f.status])} ${f.title}`);
    if (f.text) lines.push(`  ${f.text}`);
    if (f.value) for (const line of f.value.split('\n')) lines.push(`  ${line}`);
    if (f.fix) {
      lines.push(`  → ${f.fix.text}`);
      if (f.fix.code) lines.push(`    ${f.fix.code}`);
    }
  }
  const s = report.summary;
  lines.push(
    '',
    report.lang === 'et'
      ? `${s.ok} korras, ${s.info} ${s.info === 1 ? 'vihje' : 'vihjet'}, ${s.warn} ${s.warn === 1 ? 'hoiatus' : 'hoiatust'}, ${s.error} viga`
      : `${s.ok} ok, ${s.info} ${s.info === 1 ? 'note' : 'notes'}, ${s.warn} ${s.warn === 1 ? 'warning' : 'warnings'}, ${s.error} ${s.error === 1 ? 'error' : 'errors'}`,
  );
  return lines.join('\n');
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(`email-domain-check: ${error.message}\n\n${USAGE}`);
    process.exit(2);
  }
  if (opts.help || opts.input === null) {
    console.log(USAGE);
    process.exit(opts.help ? 0 : 2);
  }
  try {
    const report = await checkEmailDomain(opts.input, { lang: opts.lang, dkimSelectors: opts.selectors });
    console.log(opts.json ? JSON.stringify(report, null, 2) : format(report, { color: process.stdout.isTTY }));
    process.exit(report.summary.error ? 1 : 0);
  } catch (error) {
    if (!(error instanceof CheckError)) throw error;
    if (opts.json) console.log(JSON.stringify({ error: { code: error.code, message: error.message } }, null, 2));
    else console.error(error.message);
    process.exit(1);
  }
}

await main();
