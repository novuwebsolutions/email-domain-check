import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  CheckError,
  checkEmailDomain,
  dmarcTags,
  mxProvider,
  organisationalDomain,
  parseDomain,
  spfTerms,
  txtValue,
} from '../email-domain-check.mjs';

const cli = fileURLToPath(new URL('../cli.mjs', import.meta.url));

/** A DNS-over-HTTPS server that knows only { 'name TYPE': [data, ...] }. */
function dns(records, { missing = [] } = {}) {
  const types = { MX: 15, TXT: 16, A: 1, AAAA: 28 };
  const queries = [];
  const fetch = async (url) => {
    const u = new URL(url);
    const name = u.searchParams.get('name');
    const type = u.searchParams.get('type');
    queries.push(`${name} ${type}`);
    const answers = records[`${name} ${type}`] ?? [];
    const body = {
      Status: missing.includes(name) ? 3 : 0,
      AD: false,
      Answer: answers.map((data) => ({ name, type: types[type], TTL: 300, data })),
    };
    return new Response(JSON.stringify(body), { headers: { 'content-type': 'application/dns-json' } });
  };
  return { fetch, queries };
}

const byId = (report) => Object.fromEntries(report.findings.map((f) => [f.id, f]));

test('parseDomain takes domains, addresses and links', () => {
  assert.equal(parseDomain('Firma.ee'), 'firma.ee');
  assert.equal(parseDomain('info@firma.ee'), 'firma.ee');
  assert.equal(parseDomain('https://www.firma.ee/kontakt?x=1'), 'firma.ee');
  assert.equal(parseDomain('www.firma.ee.'), 'firma.ee');
  assert.equal(parseDomain('õun.ee'), 'xn--un-bka.ee');
  for (const [input, code] of [
    ['', 'empty'],
    ['firma', 'invalid'],
    ['192.168.1.1', 'ip'],
    ['[::1]', 'ip'],
    ['printer.local', 'reserved'],
    ['a..ee', 'invalid'],
    ['-x.ee', 'invalid'],
  ]) {
    assert.throws(() => parseDomain(input), (e) => e instanceof CheckError && e.code === code, input);
  }
});

test('txtValue joins quoted strings and reads escapes', () => {
  assert.equal(txtValue('"v=DKIM1; p=AB" "CD"'), 'v=DKIM1; p=ABCD');
  assert.equal(txtValue('"a\\"b\\059c"'), 'a"b;c');
  assert.equal(txtValue('v=spf1 -all'), 'v=spf1 -all');
});

test('spfTerms reads qualifiers, values and prefix lengths', () => {
  assert.deepEqual(spfTerms('v=spf1 a/24 ip4:1.2.3.0/24 -include:x.ee ~all'), [
    { qualifier: '+', mechanism: 'a', value: '' },
    { qualifier: '+', mechanism: 'ip4', value: '1.2.3.0/24' },
    { qualifier: '-', mechanism: 'include', value: 'x.ee' },
    { qualifier: '~', mechanism: 'all', value: '' },
  ]);
});

test('dmarcTags, organisationalDomain and mxProvider', () => {
  assert.deepEqual(dmarcTags('v=DMARC1;p=none; rua=mailto:a@b.ee'), { v: 'DMARC1', p: 'none', rua: 'mailto:a@b.ee' });
  assert.equal(organisationalDomain('mail.firma.ee'), 'firma.ee');
  assert.equal(organisationalDomain('www.firma.com.ee'), 'firma.com.ee');
  assert.equal(mxProvider(['aspmx.l.google.com']), 'Google Workspace');
  assert.equal(mxProvider(['firma-ee.mail.protection.outlook.com']), 'Microsoft 365');
  assert.equal(mxProvider(['mx.example.ee']), null);
});

test('a domain at Zone with DMARC that only watches', async () => {
  const { fetch } = dns({
    'firma.ee MX': ['10 zonemx.eu.'],
    'firma.ee TXT': ['"v=spf1 include:_spf.zone.eu ~all"'],
    '_spf.zone.eu TXT': ['"v=spf1 ip4:217.146.64.0/20 -all"'],
    'zone._domainkey.firma.ee TXT': [`"v=DKIM1; k=rsa; p=${'A'.repeat(392)}"`],
    '_dmarc.firma.ee TXT': ['"v=DMARC1; p=none; rua=mailto:info@firma.ee"'],
  });
  const report = await checkEmailDomain('firma.ee', { fetch });
  const f = byId(report);
  assert.equal(f['mx-ok'].status, 'ok');
  assert.match(f['mx-ok'].text, /Zone/);
  assert.equal(f['spf-ok'].status, 'ok');
  assert.match(f['spf-ok'].text, /Zone/);
  assert.equal(f['dkim-ok'].status, 'ok');
  assert.equal(f['dkim-weak'], undefined);
  assert.equal(f['dmarc-none'].status, 'warn');
  assert.equal(f['dmarc-none'].fix.code, 'v=DMARC1; p=quarantine; rua=mailto:info@firma.ee');
  assert.equal(f['mta-sts-missing'].status, 'info');
  assert.deepEqual(report.summary, { ok: 3, info: 1, warn: 1, error: 0, status: 'warn' });
});

test('missing SPF gets the record of the mail service', async () => {
  const { fetch } = dns({ 'firma.ee MX': ['1 smtp.google.com.'] });
  const f = byId(await checkEmailDomain('firma.ee', { fetch }));
  assert.equal(f['spf-missing'].status, 'error');
  assert.equal(f['spf-missing'].fix.code, 'v=spf1 include:_spf.google.com ~all');
  assert.equal(f['dkim-missing'].status, 'warn');
  assert.match(f['dkim-missing'].fix.text, /Google Workspace/);
  assert.equal(f['dmarc-missing'].fix.code, 'v=DMARC1; p=none; rua=mailto:info@firma.ee');
});

test('two SPF records, +all and broken includes are errors', async () => {
  const two = dns({ 'firma.ee MX': ['10 mx.firma.ee.'], 'firma.ee TXT': ['"v=spf1 mx ~all"', '"v=spf1 include:_spf.google.com ~all"'] });
  assert.equal(byId(await checkEmailDomain('firma.ee', { fetch: two.fetch }))['spf-multiple'].status, 'error');
  const plus = dns({ 'firma.ee MX': ['10 mx.firma.ee.'], 'firma.ee TXT': ['"v=spf1 mx +all"'] });
  assert.equal(byId(await checkEmailDomain('firma.ee', { fetch: plus.fetch }))['spf-plus-all'].status, 'error');
  const broken = dns({ 'firma.ee MX': ['10 mx.firma.ee.'], 'firma.ee TXT': ['"v=spf1 include:_spf.vale.ee ~all"'] });
  const f = byId(await checkEmailDomain('firma.ee', { fetch: broken.fetch }));
  assert.equal(f['spf-broken-include'].status, 'error');
  assert.match(f['spf-broken-include'].text, /_spf\.vale\.ee/);
});

test('SPF lookups are counted through includes', async () => {
  const records = { 'firma.ee MX': ['10 mx.firma.ee.'], 'firma.ee TXT': ['"v=spf1 include:a.ee include:b.ee ~all"'] };
  records['a.ee TXT'] = ['"v=spf1 include:c.ee a mx -all"'];
  records['b.ee TXT'] = ['"v=spf1 a mx exists:x.ee include:d.ee -all"'];
  records['c.ee TXT'] = ['"v=spf1 a mx -all"'];
  records['d.ee TXT'] = ['"v=spf1 a mx -all"'];
  const f = byId(await checkEmailDomain('firma.ee', { fetch: dns(records).fetch }));
  // a.ee, b.ee + (c.ee a mx) + (a mx exists d.ee) + 2 + 2 = 13
  assert.equal(f['spf-too-many'].status, 'error');
  assert.match(f['spf-too-many'].text, /13/);
});

test('a domain without mail is told to say so', async () => {
  const f = byId(await checkEmailDomain('firma.ee', { fetch: dns({}).fetch }));
  assert.equal(f['spf-parked'].status, 'warn');
  assert.equal(f['spf-parked'].fix.code, 'v=spf1 -all');
  assert.equal(f['dmarc-missing'].fix.code, 'v=DMARC1; p=reject; rua=mailto:info@firma.ee');
  assert.equal(f['dkim-missing'], undefined);
  const parked = dns({ 'firma.ee MX': ['0 .'], 'firma.ee TXT': ['"v=spf1 -all"'], '_dmarc.firma.ee TXT': ['"v=DMARC1; p=reject; rua=mailto:a@firma.ee"'] });
  const report = await checkEmailDomain('firma.ee', { fetch: parked.fetch });
  assert.equal(report.summary.status, 'ok');
  assert.ok(byId(report)['mx-null'] && byId(report)['spf-parked-ok']);
});

test('a subdomain falls back to the DMARC of its organisation', async () => {
  const { fetch } = dns({
    'uudised.firma.ee MX': ['10 mx.firma.ee.'],
    'uudised.firma.ee TXT': ['"v=spf1 mx -all"'],
    '_dmarc.firma.ee TXT': ['"v=DMARC1; p=reject; rua=mailto:a@firma.ee"'],
  });
  const f = byId(await checkEmailDomain('uudised.firma.ee', { fetch }));
  assert.equal(f['dmarc-reject'].status, 'ok');
  assert.match(f['dmarc-reject'].text, /firma\.ee/);
});

test('a domain that does not exist is a CheckError, in English too', async () => {
  const { fetch } = dns({}, { missing: ['puudub.ee'] });
  await assert.rejects(checkEmailDomain('puudub.ee', { fetch, lang: 'en' }), (e) => e.code === 'nxdomain' && /does not exist/.test(e.message));
});

test('English texts', async () => {
  const { fetch } = dns({
    'firma.ee MX': ['10 zonemx.eu.'],
    'firma.ee TXT': ['"v=spf1 include:_spf.zone.eu include:_spf.google.com ~all"'],
    '_spf.zone.eu TXT': ['"v=spf1 ip4:217.146.64.0/20 -all"'],
    '_spf.google.com TXT': ['"v=spf1 ip4:35.190.247.0/24 ~all"'],
  });
  const f = byId(await checkEmailDomain('firma.ee', { fetch, lang: 'en' }));
  assert.equal(f['spf-services'].title, 'SPF allows 2 services to send');
  assert.match(f['spf-services'].text, /^Zone and Google may send/);
});

test('the command line prints help and refuses unknown options', () => {
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0);
  assert.match(help.stdout, /email-domain-check firma\.ee/);
  const bad = spawnSync(process.execPath, [cli, '--nope'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
});
