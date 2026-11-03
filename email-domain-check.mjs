// Reads a domain's public e-mail records and says, in plain words, whether its
// mail reaches inboxes and whether a stranger can send mail in its name: the
// mail server (MX), SPF, DKIM, DMARC and MTA-STS.
//
//   import { checkEmailDomain } from './email-domain-check.mjs';
//   const report = await checkEmailDomain('firma.ee');
//
// It only asks public DNS, over HTTPS (Cloudflare first, Google if that
// fails). It never connects to the mail servers and never sends mail. It needs
// nothing but fetch, so it runs in Node 18+, Cloudflare Workers, Deno and Bun.

export const VERSION = '1.0.0';

// A check makes at most this many DNS queries. SPF records that include other
// SPF records, and the DKIM names tried, are the most of them. Cloudflare
// Workers on the free plan allow 50 outgoing requests per call.
const DNS_BUDGET = 45;
// SPF allows 10 DNS lookups; we read at most this many included records.
const SPF_INCLUDE_READS = 12;

const DOH = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const TYPE = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

// Names under which mail services publish their DKIM keys. A key under any
// other name is invisible from outside: only a received message names it
// (DKIM-Signature: s=...), and `dkimSelectors` adds such names.
const DKIM_SELECTORS = [
  'google', // Google Workspace
  'selector1', // Microsoft 365
  'selector2',
  'zone', // Zone
  'default',
  'dkim',
  'mail',
  'k1', // Mailchimp
  's1', // SendGrid
  's2',
  'key1',
  'sig1', // iCloud
  'protonmail', // Proton
  'fm1', // Fastmail
  'zmail', // Zoho
  'mxvault',
];

// Mail services by the end of their MX host names.
const MX_PROVIDERS = [
  ['google.com', 'Google Workspace'],
  ['googlemail.com', 'Google Workspace'],
  ['mail.protection.outlook.com', 'Microsoft 365'],
  ['zonemx.eu', 'Zone'],
  ['zoho.eu', 'Zoho'],
  ['zoho.com', 'Zoho'],
  ['protonmail.ch', 'Proton'],
  ['icloud.com', 'iCloud'],
  ['messagingengine.com', 'Fastmail'],
  ['mx.cloudflare.net', 'Cloudflare'],
];

// Sending services by the record an SPF include names.
const SPF_SERVICES = [
  ['_spf.google.com', 'Google'],
  ['spf.protection.outlook.com', 'Microsoft 365'],
  ['_spf.zone.eu', 'Zone'],
  ['servers.mcsv.net', 'Mailchimp'],
  ['spf.mandrillapp.com', 'Mailchimp'],
  ['sendgrid.net', 'SendGrid'],
  ['mailgun.org', 'Mailgun'],
  ['amazonses.com', 'Amazon SES'],
  ['spf.brevo.com', 'Brevo'],
  ['spf.sendinblue.com', 'Brevo'],
  ['zoho.eu', 'Zoho'],
  ['zoho.com', 'Zoho'],
  ['_spf.protonmail.ch', 'Proton'],
  ['icloud.com', 'iCloud'],
  ['spf.messagingengine.com', 'Fastmail'],
  ['_spf.mlsend.com', 'MailerLite'],
  ['spf.mailjet.com', 'Mailjet'],
  ['mail.zendesk.com', 'Zendesk'],
  ['_spf.salesforce.com', 'Salesforce'],
  ['spf.smtp2go.com', 'SMTP2GO'],
  ['_spf.smaily.com', 'Smaily'],
  ['_spf.atlassian.net', 'Atlassian'],
];

// The SPF record each mail service documents for its customers.
const SPF_FOR_PROVIDER = {
  'Google Workspace': 'v=spf1 include:_spf.google.com ~all',
  'Microsoft 365': 'v=spf1 include:spf.protection.outlook.com -all',
  Zone: 'v=spf1 include:_spf.zone.eu ~all',
  Zoho: 'v=spf1 include:zoho.eu ~all',
  Proton: 'v=spf1 include:_spf.protonmail.ch ~all',
  iCloud: 'v=spf1 include:icloud.com ~all',
  Fastmail: 'v=spf1 include:spf.messagingengine.com ~all',
};

// Names that are not one organisation's domain but a registry's, so the
// organisation's own domain is one label longer (firma.com.ee).
const SHARED_SUFFIXES = new Set(['com.ee', 'pri.ee', 'med.ee', 'fie.ee', 'co.uk', 'org.uk', 'me.uk', 'com.au', 'co.nz', 'com.br', 'co.jp']);

// Names that never reach the public internet.
const RESERVED = ['localhost', 'local', 'localdomain', 'internal', 'intranet', 'lan', 'home', 'corp', 'private', 'test', 'example', 'invalid', 'onion', 'arpa'];

// ---------------------------------------------------------------------------
// Words

const NUMBER_ET = ['', 'ühel', 'kahel', 'kolmel', 'neljal', 'viiel', 'kuuel', 'seitsmel', 'kaheksal', 'üheksal', 'kümnel'];
const list = (items, lang) => {
  if (items.length < 2) return items.join('');
  const and = lang === 'et' ? ' ja ' : ' and ';
  return `${items.slice(0, -1).join(', ')}${and}${items.at(-1)}`;
};

const ERRORS = {
  et: {
    empty: 'Sisesta domeen või e-posti aadress.',
    invalid: 'See ei ole domeen. Sisesta näiteks firma.ee või info@firma.ee.',
    ip: 'Sisesta domeeni nimi, mitte IP-aadress.',
    reserved: 'Seda nime ei saa internetist kontrollida.',
    nxdomain: (d) => `Domeeni ${d} pole olemas. Kontrolli kirjapilti.`,
    dns: 'DNS ei vastanud. Proovi mõne aja pärast uuesti.',
  },
  en: {
    empty: 'Enter a domain or an e-mail address.',
    invalid: 'That is not a domain. Try firma.ee or info@firma.ee.',
    ip: 'Enter a domain name, not an IP address.',
    reserved: 'This name cannot be checked from the internet.',
    nxdomain: (d) => `The domain ${d} does not exist. Check the spelling.`,
    dns: 'DNS did not answer. Try again in a while.',
  },
};

/** An input or lookup problem; `code` is stable, `message` is for people. */
export class CheckError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'CheckError';
    this.code = code;
  }
}

const fail = (lang, code, ...args) => {
  const text = (ERRORS[lang] ?? ERRORS.en)[code];
  return new CheckError(code, typeof text === 'function' ? text(...args) : text);
};

const TEXT = {
  et: {
    'mx-ok': (f) => ({
      title: 'E-posti server on olemas',
      text: f.provider ? `Kirjad sinu domeenile tulevad teenusesse ${f.provider}.` : 'Kirjad sinu domeenile jõuavad e-posti serverisse.',
      value: f.mx.map((m) => `MX ${m.pref} ${m.host}`).join('\n'),
    }),
    'mx-null': () => ({
      title: 'Domeen ei võta kirju vastu',
      text: 'MX-kirje ütleb selgelt, et sellele domeenile kirju ei saadeta. See on õige domeenil, mis e-posti ei kasuta.',
    }),
    'mx-missing': () => ({
      title: 'E-posti serverit pole',
      text: 'Domeenil pole MX-kirjet, nii et sellele saadetud kirjad ei jõua kuhugi. Kui kasutad selle domeeniga e-posti, lisa MX-kirje, mille annab sinu e-posti teenus. Kui ei kasuta, on see korras.',
    }),
    'spf-ok': (f) => ({
      title: 'SPF on olemas',
      text: `${f.services.length ? `Sinu nimel tohivad kirju saata ${list(f.services, 'et')}. ` : ''}${f.all === '-' ? 'Teiste serverite kirjad lükatakse tagasi.' : 'Teiste serverite kirjad märgitakse kahtlaseks.'}`,
      value: f.record,
    }),
    'spf-services': (f) => ({
      title: `SPF lubab saata ${NUMBER_ET[f.services.length] ?? f.services.length} teenusel`,
      text: `Sinu nimel tohivad kirju saata ${list(f.services, 'et')}. Kui mõnda neist enam ei kasuta, võta see kirjest välja. Iga liigne teenus on veel üks koht, kust saab sinu nimel kirju saata.`,
    }),
    'spf-missing': (f) => ({
      title: 'SPF puudub',
      text: 'Kusagil pole kirjas, millised serverid tohivad sinu nimel kirju saata. Gmail ja Outlook panevad selliseid kirju sageli rämpsposti ning võltsijal on lihtne sinu nimel kirjutada.',
      fix: f.suggestion
        ? { text: `Lisa domeenile ${f.domain} TXT-kirje:`, code: f.suggestion }
        : { text: `Küsi oma e-posti teenuselt täpne SPF-kirje ja lisa see domeenile ${f.domain} TXT-kirjena. Tavaliselt on see kujul v=spf1 include:… ~all.` },
    }),
    'spf-parked': (f) => ({
      title: 'Domeen ei saada kirju, aga ei ütle seda',
      text: 'Domeenil pole e-posti serverit ega SPF-kirjet. Siis saab igaüks selle nimel kirju saata.',
      fix: { text: `Kui seda domeeni e-postiks ei kasuta, lisa domeenile ${f.domain} TXT-kirje, mis keelab kõik saatjad:`, code: 'v=spf1 -all' },
    }),
    'spf-parked-ok': () => ({
      title: 'Domeen ütleb, et ei saada kirju',
      text: 'SPF-kirje v=spf1 -all keelab kõik saatjad. Seda domeeni ei saa võltsimiseks kasutada.',
    }),
    'spf-multiple': (f) => ({
      title: 'Mitu SPF-kirjet',
      text: `Domeenil on ${f.count} SPF-kirjet. Lubatud on ainult üks, muidu loetakse SPF vigaseks ja sinu kirjad kukuvad kontrollist läbi.`,
      fix: { text: 'Pane kirjed üheks kokku: üks v=spf1 algusesse, kõik include-osad järjest ja lõppu üks ~all.' },
      value: f.records.join('\n'),
    }),
    'spf-plus-all': (f) => ({
      title: 'SPF lubab kõiki',
      text: 'Kirje lõpus on +all. See lubab igal serveril maailmas sinu nimel kirju saata.',
      fix: { text: 'Muuda kirje lõpp kujule ~all.' },
      value: f.record,
    }),
    'spf-neutral': (f) => ({
      title: 'SPF ei keela midagi',
      text: 'Kirje lõpp ?all ütleb, et teiste serverite kohta pole arvamust. Võltsitud kirjad lähevad läbi.',
      fix: { text: 'Muuda kirje lõpp kujule ~all.' },
      value: f.record,
    }),
    'spf-no-all': (f) => ({
      title: 'SPF-il pole lõppu',
      text: 'Kirje ei ütle, mida teha kirjadega teistelt serveritelt.',
      fix: { text: 'Lisa kirje lõppu ~all.' },
      value: f.record,
    }),
    'spf-too-many': (f) => ({
      title: 'SPF-is on liiga palju päringuid',
      text: `Kirje kontrollimiseks on vaja ${f.lookups} DNS-päringut, lubatud on 10. Üle selle loetakse SPF vigaseks ja kirjad võivad minna rämpsposti.`,
      fix: { text: 'Võta kirjest välja teenused, mida enam ei kasuta.' },
      value: f.record,
    }),
    'spf-near-limit': (f) => ({
      title: 'SPF on piiri lähedal',
      text: `Kirje kontrollimiseks on vaja ${f.lookups} DNS-päringut 10 lubatust. Uue teenuse lisamine võib piiri ületada.`,
    }),
    'spf-broken-include': (f) => ({
      title: 'SPF viitab kirjele, mida pole',
      text: `Osa include:${f.include} ei leia SPF-kirjet. Selle pärast loetakse kogu SPF vigaseks.`,
      fix: { text: 'Kontrolli nime kirjapilti või võta see osa välja.' },
      value: f.record,
    }),
    'spf-ptr': () => ({
      title: 'SPF kasutab vananenud ptr-osa',
      text: 'ptr on aeglane ja paljud postiserverid eiravad seda.',
      fix: { text: 'Asenda ptr ip4- või include-osaga.' },
    }),
    'spf-unread': () => ({
      title: 'SPF on väga pikk',
      text: 'Kirje viitab nii paljudele teistele kirjetele, et kõiki me läbi ei lugenud.',
    }),
    'dkim-ok': (f) => ({
      title: 'Kirjadel on digiallkiri (DKIM)',
      text: `Leidsime ${f.selectors.length > 1 ? 'võtmed' : 'võtme'} ${list(f.selectors, 'et')}. Täpselt saab allkirja kontrollida ainult päris kirjast.`,
    }),
    'dkim-weak': (f) => ({
      title: 'DKIM-võti on lühike',
      text: `Võti ${f.selector} on 1024-bitine või lühem. Soovitus on 2048 bitti.`,
      fix: { text: 'Loo e-posti teenuse halduses uus, 2048-bitine võti ja pane see DNS-i vana asemele.' },
    }),
    'dkim-revoked': (f) => ({
      title: 'DKIM-võti on tühistatud',
      text: `Võti ${f.selector} on DNS-is olemas, aga tühi. Kui seda võtit kasutatakse, siis allkiri ei kehti.`,
    }),
    'dkim-missing': (f) => ({
      title: 'DKIM-võtit ei leidnud',
      text: 'Me ei leidnud digiallkirja võtit tavalistest kohtadest. Ilma DKIM-ita lähevad kirjad kergemini rämpsposti ja DMARC ei saa korralikult töötada. Kui DKIM on sees teise nimega võtmega, me seda ei näe: nime leiad saadetud kirja päisest (DKIM-Signature: s=…).',
      fix: {
        text:
          f.provider === 'Google Workspace'
            ? 'Google Workspace\'i halduses: Apps → Google Workspace → Gmail → Authenticate email. Loo võti ja lisa DNS-i TXT-kirje, mille Google annab.'
            : f.provider === 'Microsoft 365'
              ? 'Microsoft 365: Defender portal → Email authentication settings → DKIM. Lülita domeenile sisse ja lisa DNS-i kaks CNAME-kirjet, mille Microsoft annab.'
              : 'Lülita DKIM sisse oma e-posti teenuse halduses ja lisa DNS-i kirje, mille see annab.',
      },
    }),
    'dmarc-reject': (f) => ({
      title: 'DMARC kaitseb sinu nime',
      text: `Reegel on p=reject: võltsitud kirjad lükatakse tagasi.${f.pct < 100 ? ` Reegel kehtib ${f.pct}% kirjadele.` : ''}${f.inherited ? ` Reegel tuleb domeenilt ${f.inherited}.` : ''}`,
      value: f.record,
    }),
    'dmarc-quarantine': (f) => ({
      title: 'DMARC kaitseb sinu nime',
      text: `Reegel on p=quarantine: võltsitud kirjad lähevad rämpsposti.${f.pct < 100 ? ` Reegel kehtib ${f.pct}% kirjadele.` : ''}${f.inherited ? ` Reegel tuleb domeenilt ${f.inherited}.` : ''}`,
      value: f.record,
    }),
    'dmarc-none': (f) => ({
      title: 'DMARC ainult jälgib',
      text: `Kirje on olemas, aga selle reegel on p=none. Kui keegi saadab võltsitud kirja aadressilt ${f.sample}, näiteks võlts-arve sinu kliendile, jõuab see ikkagi kohale.`,
      fix: {
        text: `${f.reports.length ? `Vaata paar nädalat aruandeid, mis tulevad ${f.reports.length > 1 ? 'aadressidele' : 'aadressile'} ${list(f.reports, 'et')}.` : 'Lisa kirjesse aruannete aadress ja vaata paar nädalat aruandeid.'} Kui seal on ainult sinu enda kirjad, muuda DNS-is kirje _dmarc.${f.domain} selliseks:`,
        code: f.suggestion,
      },
      value: f.record,
    }),
    'dmarc-missing': (f) => ({
      title: 'DMARC puudub',
      text: 'Pole reeglit, mida teha kirjadega, mis teesklevad, et tulevad sinult. Gmail, Yahoo ja Outlook nõuavad DMARC-it suurematelt saatjatelt ja RIA soovitab seda kõigile.',
      fix: {
        text: `Lisa TXT-kirje nimega _dmarc.${f.domain}. Alusta jälgimisest ja pane aruannete aadressiks postkast, mida loed. Kui paari nädala aruanded on puhtad, muuda p=none asemele p=quarantine.`,
        code: f.suggestion,
      },
    }),
    'dmarc-multiple': (f) => ({
      title: 'Mitu DMARC-kirjet',
      text: 'Lubatud on ainult üks. Praegu eiravad postiserverid neid kõiki.',
      fix: { text: `Jäta nime _dmarc.${f.domain} alla alles üks kirje.` },
      value: f.records.join('\n'),
    }),
    'dmarc-invalid': (f) => ({
      title: 'DMARC-kirje on vigane',
      text: 'Kirjest puudub reegel p= või see on vale. Postiserverid eiravad sellist kirjet.',
      fix: { text: `Kirje peab olema kujul:`, code: f.suggestion },
      value: f.record,
    }),
    'dmarc-no-reports': (f) => ({
      title: 'DMARC-aruandeid ei tule',
      text: 'Kirjes pole rua= aadressi, nii et sa ei näe, kes sinu nimel kirju saadab.',
      fix: { text: 'Lisa kirje lõppu aruannete aadress, näiteks:', code: f.suggestion },
    }),
    'mta-sts-ok': (f) => ({
      title: 'Kirjad liiguvad krüpteeritult (MTA-STS)',
      text: `MTA-STS on sees${f.tlsrpt ? ' ja TLS-aruanded tulevad' : ''}.`,
    }),
    'mta-sts-missing': () => ({
      title: 'MTA-STS pole sees',
      text: 'MTA-STS nõuab, et teised postiserverid saadaksid sulle kirju ainult krüpteeritult. Väikefirmale pole see kohustuslik.',
    }),
  },
  en: {
    'mx-ok': (f) => ({
      title: 'The domain has a mail server',
      text: f.provider ? `Mail to your domain goes to ${f.provider}.` : 'Mail to your domain reaches a mail server.',
      value: f.mx.map((m) => `MX ${m.pref} ${m.host}`).join('\n'),
    }),
    'mx-null': () => ({
      title: 'The domain accepts no mail',
      text: 'Its MX record says plainly that no mail is delivered to it. That is right for a domain that does not use e-mail.',
    }),
    'mx-missing': () => ({
      title: 'No mail server',
      text: 'The domain has no MX record, so mail sent to it goes nowhere. If you use e-mail on this domain, add the MX record your mail service gives you. If you do not, this is fine.',
    }),
    'spf-ok': (f) => ({
      title: 'SPF is in place',
      text: `${f.services.length ? `${list(f.services, 'en')} may send mail in your name. ` : ''}${f.all === '-' ? 'Mail from other servers is rejected.' : 'Mail from other servers is marked suspicious.'}`,
      value: f.record,
    }),
    'spf-services': (f) => ({
      title: `SPF allows ${f.services.length} services to send`,
      text: `${list(f.services, 'en')} may send mail in your name. If you no longer use one of them, take it out of the record. Every service you do not need is one more place mail in your name can come from.`,
    }),
    'spf-missing': (f) => ({
      title: 'No SPF',
      text: 'Nothing says which servers may send mail in your name. Gmail and Outlook often put such mail in spam, and anyone can easily write in your name.',
      fix: f.suggestion
        ? { text: `Add a TXT record to ${f.domain}:`, code: f.suggestion }
        : { text: `Ask your mail service for its SPF record and add it to ${f.domain} as a TXT record. It usually looks like v=spf1 include:… ~all.` },
    }),
    'spf-parked': (f) => ({
      title: 'The domain sends no mail but does not say so',
      text: 'The domain has no mail server and no SPF record, so anyone can send mail in its name.',
      fix: { text: `If you do not use this domain for e-mail, add a TXT record to ${f.domain} that allows no senders:`, code: 'v=spf1 -all' },
    }),
    'spf-parked-ok': () => ({
      title: 'The domain says it sends no mail',
      text: 'Its SPF record v=spf1 -all allows no senders, so the domain cannot be used for spoofing.',
    }),
    'spf-multiple': (f) => ({
      title: 'More than one SPF record',
      text: `The domain has ${f.count} SPF records. Only one is allowed; with more, SPF counts as broken and your mail fails the check.`,
      fix: { text: 'Merge them into one: a single v=spf1 at the start, every include after it and one ~all at the end.' },
      value: f.records.join('\n'),
    }),
    'spf-plus-all': (f) => ({
      title: 'SPF allows everyone',
      text: 'The record ends in +all, which lets every server in the world send mail in your name.',
      fix: { text: 'End the record with ~all instead.' },
      value: f.record,
    }),
    'spf-neutral': (f) => ({
      title: 'SPF forbids nothing',
      text: 'The record ends in ?all, which takes no view on other servers. Spoofed mail gets through.',
      fix: { text: 'End the record with ~all instead.' },
      value: f.record,
    }),
    'spf-no-all': (f) => ({
      title: 'SPF has no ending',
      text: 'The record does not say what to do with mail from other servers.',
      fix: { text: 'Add ~all to the end of the record.' },
      value: f.record,
    }),
    'spf-too-many': (f) => ({
      title: 'SPF needs too many lookups',
      text: `Checking the record takes ${f.lookups} DNS lookups; 10 are allowed. Past that, SPF counts as broken and mail may go to spam.`,
      fix: { text: 'Take out the services you no longer use.' },
      value: f.record,
    }),
    'spf-near-limit': (f) => ({
      title: 'SPF is close to its limit',
      text: `Checking the record takes ${f.lookups} of the 10 DNS lookups allowed. Adding one more service may break it.`,
    }),
    'spf-broken-include': (f) => ({
      title: 'SPF points to a record that does not exist',
      text: `The part include:${f.include} finds no SPF record, so the whole SPF counts as broken.`,
      fix: { text: 'Check the spelling of that name or take that part out.' },
      value: f.record,
    }),
    'spf-ptr': () => ({
      title: 'SPF uses the outdated ptr mechanism',
      text: 'ptr is slow and many mail servers ignore it.',
      fix: { text: 'Replace ptr with an ip4 or include part.' },
    }),
    'spf-unread': () => ({
      title: 'SPF is very long',
      text: 'The record points to so many other records that we did not read them all.',
    }),
    'dkim-ok': (f) => ({
      title: 'Your mail is signed (DKIM)',
      text: `We found the ${f.selectors.length > 1 ? 'keys' : 'key'} ${list(f.selectors, 'en')}. Only a real message shows whether the signature itself is right.`,
    }),
    'dkim-weak': (f) => ({
      title: 'The DKIM key is short',
      text: `The key ${f.selector} is 1024 bits or shorter. 2048 bits is recommended.`,
      fix: { text: 'Create a new 2048-bit key in your mail service and replace the old one in DNS.' },
    }),
    'dkim-revoked': (f) => ({
      title: 'A DKIM key is revoked',
      text: `The key ${f.selector} is in DNS but empty. Mail signed with it does not verify.`,
    }),
    'dkim-missing': (f) => ({
      title: 'No DKIM key found',
      text: 'We found no signing key under the usual names. Without DKIM, mail goes to spam more easily and DMARC cannot work properly. If DKIM uses a key under another name we cannot see it: a sent message names it in its header (DKIM-Signature: s=…).',
      fix: {
        text:
          f.provider === 'Google Workspace'
            ? 'In the Google Workspace admin console: Apps → Google Workspace → Gmail → Authenticate email. Generate a key and add the TXT record Google gives you.'
            : f.provider === 'Microsoft 365'
              ? 'Microsoft 365: Defender portal → Email authentication settings → DKIM. Turn it on for the domain and add the two CNAME records Microsoft gives you.'
              : 'Turn DKIM on in your mail service and add the DNS record it gives you.',
      },
    }),
    'dmarc-reject': (f) => ({
      title: 'DMARC protects your name',
      text: `The policy is p=reject: spoofed mail is refused.${f.pct < 100 ? ` It applies to ${f.pct}% of mail.` : ''}${f.inherited ? ` The policy comes from ${f.inherited}.` : ''}`,
      value: f.record,
    }),
    'dmarc-quarantine': (f) => ({
      title: 'DMARC protects your name',
      text: `The policy is p=quarantine: spoofed mail goes to spam.${f.pct < 100 ? ` It applies to ${f.pct}% of mail.` : ''}${f.inherited ? ` The policy comes from ${f.inherited}.` : ''}`,
      value: f.record,
    }),
    'dmarc-none': (f) => ({
      title: 'DMARC only watches',
      text: `The record is there, but its policy is p=none. If someone sends a spoofed message from ${f.sample}, a fake invoice to your customer for example, it is still delivered.`,
      fix: {
        text: `${f.reports.length ? `Read the reports that arrive at ${list(f.reports, 'en')} for a couple of weeks.` : 'Add a report address to the record and read the reports for a couple of weeks.'} If they show only your own mail, change the record _dmarc.${f.domain} to:`,
        code: f.suggestion,
      },
      value: f.record,
    }),
    'dmarc-missing': (f) => ({
      title: 'No DMARC',
      text: 'There is no rule for mail that pretends to come from you. Gmail, Yahoo and Outlook require DMARC from bulk senders, and it protects everyone else too.',
      fix: {
        text: `Add a TXT record named _dmarc.${f.domain}. Start by watching, with reports going to a mailbox you read. When a couple of weeks of reports are clean, change p=none to p=quarantine.`,
        code: f.suggestion,
      },
    }),
    'dmarc-multiple': (f) => ({
      title: 'More than one DMARC record',
      text: 'Only one is allowed. Mail servers now ignore them all.',
      fix: { text: `Keep a single record under _dmarc.${f.domain}.` },
      value: f.records.join('\n'),
    }),
    'dmarc-invalid': (f) => ({
      title: 'The DMARC record is broken',
      text: 'It has no p= policy, or a wrong one. Mail servers ignore such a record.',
      fix: { text: 'The record should look like:', code: f.suggestion },
      value: f.record,
    }),
    'dmarc-no-reports': (f) => ({
      title: 'No DMARC reports',
      text: 'The record has no rua= address, so you cannot see who sends mail in your name.',
      fix: { text: 'Add a report address to the end of the record, for example:', code: f.suggestion },
    }),
    'mta-sts-ok': (f) => ({
      title: 'Mail travels encrypted (MTA-STS)',
      text: `MTA-STS is on${f.tlsrpt ? ' and TLS reports are sent' : ''}.`,
    }),
    'mta-sts-missing': () => ({
      title: 'No MTA-STS',
      text: 'MTA-STS makes other mail servers send you mail only over an encrypted connection. A small business does not need it.',
    }),
  },
};

// ---------------------------------------------------------------------------
// DNS

/**
 * One DNS query over HTTPS (the JSON form both Cloudflare and Google answer):
 * { status, ad, answers: [{ name, type, ttl, data }] }. Status 0 is an answer,
 * 3 a name that does not exist. `ad` is true when the answer is DNSSEC-signed.
 */
export async function dnsQuery(name, type, { fetch = globalThis.fetch.bind(globalThis), doh = DOH, timeoutMs = 5000 } = {}) {
  let lastError;
  for (const endpoint of doh) {
    try {
      const response = await fetch(`${endpoint}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`, {
        headers: { accept: 'application/dns-json' },
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const json = await response.json();
      if (typeof json.Status !== 'number') throw new Error('not a DNS answer');
      // SERVFAIL from one resolver can be that resolver's problem.
      if (json.Status === 2 && endpoint !== doh.at(-1)) throw new Error('SERVFAIL');
      return {
        status: json.Status,
        ad: json.AD === true,
        answers: (json.Answer ?? []).map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: String(a.data ?? '') })),
      };
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`DNS query ${name} ${type} failed: ${lastError?.message}`, { cause: lastError });
}

/** A TXT answer's text: "v=DKIM1; p=MIIB" "rest" → v=DKIM1; p=MIIBrest. */
export function txtValue(data) {
  if (!data.startsWith('"')) return data;
  let out = '';
  let i = 0;
  while (i < data.length) {
    if (data[i] !== '"') {
      i++;
      continue;
    }
    i++;
    while (i < data.length && data[i] !== '"') {
      if (data[i] === '\\' && i + 1 < data.length) {
        const digits = /^\d{3}/.exec(data.slice(i + 1, i + 4));
        if (digits) {
          out += String.fromCharCode(Number(digits[0]));
          i += 4;
        } else {
          out += data[i + 1];
          i += 2;
        }
        continue;
      }
      out += data[i++];
    }
    i++;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Reading the records

/**
 * The domain to check from what someone typed: firma.ee, info@firma.ee,
 * https://www.firma.ee/kontakt. "www." is dropped, since mail uses the bare
 * domain. Throws a CheckError for anything that is not a public domain name.
 */
export function parseDomain(input, lang = 'et') {
  let text = String(input ?? '').trim().toLowerCase();
  if (!text) throw fail(lang, 'empty');
  if (text.length > 300) throw fail(lang, 'invalid');
  if (/^[a-z][a-z0-9+.-]*:\/\//.test(text)) {
    try {
      text = new URL(text).hostname;
    } catch {
      throw fail(lang, 'invalid');
    }
  } else {
    if (text.includes('@')) text = text.slice(text.lastIndexOf('@') + 1);
    text = text.split(/[/?#]/)[0];
  }
  let host;
  try {
    // The URL parser turns an IDN (õun.ee) into its ASCII form (xn--un-...).
    host = new URL(`http://${text}`).hostname.replace(/\.$/, '');
  } catch {
    throw fail(lang, 'invalid');
  }
  if (host.startsWith('[') || /^\d+(\.\d+){3}$/.test(host)) throw fail(lang, 'ip');
  if (host.startsWith('www.')) host = host.slice(4);
  const labels = host.split('.');
  if (labels.length < 2 || host.length > 253) throw fail(lang, 'invalid');
  if (labels.some((l) => !/^(?!-)[a-z0-9-]{1,63}(?<!-)$/.test(l))) throw fail(lang, 'invalid');
  if (!/^(?:[a-z]{2,63}|xn--[a-z0-9-]+)$/.test(labels.at(-1))) throw fail(lang, 'invalid');
  if (RESERVED.some((r) => host === r || host.endsWith(`.${r}`))) throw fail(lang, 'reserved');
  return host;
}

/** firma.ee for mail.firma.ee; firma.com.ee for www.firma.com.ee. */
export function organisationalDomain(domain) {
  const labels = domain.split('.');
  const size = SHARED_SUFFIXES.has(labels.slice(-2).join('.')) ? 3 : 2;
  return labels.slice(-size).join('.');
}

const nameMatches = (host, suffix) => host === suffix || host.endsWith(`.${suffix}`);

/** The mail service an MX host belongs to, if it is a known one. */
export function mxProvider(hosts) {
  for (const host of hosts) {
    const known = MX_PROVIDERS.find(([suffix]) => nameMatches(host, suffix));
    if (known) return known[1];
  }
  return null;
}

/** The terms of an SPF record: [{ qualifier, mechanism, value }]. */
export function spfTerms(record) {
  return record
    .trim()
    .split(/\s+/)
    .slice(1)
    .map((term) => {
      // a/24 and mx/24 carry a prefix length, ip4:1.2.3.0/24 a value with one.
      const m = /^([+?~-]?)([a-z0-9]+)(?:[:=](.*)|\/.*)?$/i.exec(term);
      if (!m) return { qualifier: '', mechanism: term.toLowerCase(), value: '' };
      return { qualifier: m[1] || '+', mechanism: m[2].toLowerCase(), value: m[3] ?? '' };
    });
}

/** The tags of a DMARC record: { v, p, rua, pct, ... }. */
export function dmarcTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const at = part.indexOf('=');
    if (at < 0) continue;
    const key = part.slice(0, at).trim().toLowerCase();
    if (key && !(key in tags)) tags[key] = part.slice(at + 1).trim();
  }
  return tags;
}

/** The record with one tag set to a value, the other tags kept in place. */
function withTag(record, key, value) {
  const parts = record
    .split(';')
    .map((p) => p.trim())
    .filter(Boolean);
  const at = parts.findIndex((p) => p.split('=')[0].trim().toLowerCase() === key);
  if (at >= 0) parts[at] = `${key}=${value}`;
  else parts.push(`${key}=${value}`);
  return parts.join('; ');
}

// The bits of an RSA key from its base64 SubjectPublicKeyInfo: 1024 bits is
// about 216 characters, 2048 about 392.
const keyBits = (base64) => (base64.length < 300 ? 1024 : base64.length < 600 ? 2048 : 4096);

// ---------------------------------------------------------------------------
// The check

/**
 * Checks a domain's e-mail setup. Options:
 *   lang           'et' (default) or 'en', the language of the texts
 *   dkimSelectors  more DKIM key names to look for (['s2024'])
 *   fetch          the fetch to use (for tests, or a proxy)
 *   doh            DNS-over-HTTPS endpoints, tried in order
 * Returns { tool, version, domain, checkedAt, summary, findings }. Throws a
 * CheckError when the input is no domain or DNS does not answer.
 */
export async function checkEmailDomain(input, options = {}) {
  const lang = options.lang === 'en' ? 'en' : 'et';
  const domain = parseDomain(input, lang);
  let budget = DNS_BUDGET;
  const dnsOptions = { fetch: options.fetch, doh: options.doh };
  const dns = async (name, type) => {
    if (budget <= 0) return null;
    budget--;
    try {
      return await dnsQuery(name, type, dnsOptions);
    } catch (error) {
      throw new CheckError('dns', (ERRORS[lang] ?? ERRORS.en).dns, { cause: error });
    }
  };
  const txt = async (name) => {
    const answer = await dns(name, 'TXT');
    if (!answer) return null;
    return { status: answer.status, records: answer.answers.filter((a) => a.type === TYPE.TXT).map((a) => txtValue(a.data)) };
  };

  const findings = [];
  const add = (status, id, facts = {}) => {
    const text = TEXT[lang][id](facts);
    findings.push({ id, status, title: text.title, text: text.text, fix: text.fix ?? null, value: text.value ?? null });
  };

  // The three main lookups run together.
  const [mxAnswer, rootTxt, dmarcTxt] = await Promise.all([dns(domain, 'MX'), txt(domain), txt(`_dmarc.${domain}`)]);
  if (mxAnswer.status === 3) throw fail(lang, 'nxdomain', domain);
  if (mxAnswer.status !== 0) throw fail(lang, 'dns');

  // MX
  const mx = mxAnswer.answers
    .filter((a) => a.type === TYPE.MX)
    .map((a) => {
      const [pref, host = ''] = a.data.trim().split(/\s+/);
      return { pref: Number(pref), host: host.replace(/\.$/, '').toLowerCase() };
    })
    .sort((a, b) => a.pref - b.pref);
  const nullMx = mx.length === 1 && mx[0].host === '';
  const provider = nullMx ? null : mxProvider(mx.map((m) => m.host));
  if (nullMx) add('ok', 'mx-null');
  else if (mx.length) add('ok', 'mx-ok', { mx, provider });
  const usesMail = mx.length > 0 && !nullMx;

  // SPF
  const spfRecords = (rootTxt?.records ?? []).filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (spfRecords.length > 1) {
    add('error', 'spf-multiple', { count: spfRecords.length, records: spfRecords });
  } else if (spfRecords.length === 0) {
    if (usesMail) add('error', 'spf-missing', { domain, suggestion: SPF_FOR_PROVIDER[provider] ?? null });
    else add('warn', 'spf-parked', { domain });
  } else {
    const record = spfRecords[0].trim();
    const spf = await readSpf(record, txt);
    const all = spf.all;
    const allowed = senders(spf, lang);
    if (spf.broken) add('error', 'spf-broken-include', { record, include: spf.broken });
    else if (spf.lookups > 10) add('error', 'spf-too-many', { record, lookups: spf.lookups });
    else if (all === '+') add('error', 'spf-plus-all', { record });
    else if (all === '?') add('warn', 'spf-neutral', { record });
    else if (all === null) add('warn', 'spf-no-all', { record });
    else if (!usesMail && all === '-' && allowed.length === 0) add('ok', 'spf-parked-ok');
    else add('ok', 'spf-ok', { record, all, services: allowed.length === 1 ? allowed : [] });
    if (spf.ptr) add('warn', 'spf-ptr');
    if (spf.lookups >= 9 && spf.lookups <= 10) add('info', 'spf-near-limit', { lookups: spf.lookups });
    if (allowed.length > 1 && !spf.broken && spf.lookups <= 10 && all !== '+') add('info', 'spf-services', { services: allowed });
    if (spf.unread) add('info', 'spf-unread');
  }

  // DKIM, only where the domain sends mail or has an SPF that allows senders.
  const sends = usesMail || spfRecords.some((r) => !/^v=spf1\s+-all\s*$/i.test(r.trim()));
  if (sends) {
    const selectors = [...new Set([...(options.dkimSelectors ?? []).map((s) => String(s).trim().toLowerCase()).filter(Boolean), ...DKIM_SELECTORS])];
    const keys = (
      await Promise.all(
        selectors.map(async (selector) => {
          const answer = await txt(`${selector}._domainkey.${domain}`).catch(() => null);
          const record = answer?.records.find((r) => /(^|;)\s*p=/i.test(r));
          return record ? { selector, tags: dmarcTags(record) } : null;
        }),
      )
    ).filter(Boolean);
    const live = keys.filter((k) => k.tags.p);
    if (live.length) {
      add('ok', 'dkim-ok', { selectors: live.map((k) => k.selector) });
      const weak = live.find((k) => (k.tags.k ?? 'rsa').toLowerCase() === 'rsa' && keyBits(k.tags.p.replace(/\s+/g, '')) <= 1024);
      if (weak) add('info', 'dkim-weak', { selector: weak.selector });
    } else {
      add('warn', 'dkim-missing', { provider });
    }
    const revoked = keys.find((k) => !k.tags.p);
    if (revoked) add('info', 'dkim-revoked', { selector: revoked.selector });
  }

  // DMARC, from the domain or else from its organisational domain.
  let dmarcRecords = (dmarcTxt?.records ?? []).filter((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
  let inherited = null;
  const organisation = organisationalDomain(domain);
  if (!dmarcRecords.length && organisation !== domain) {
    const parent = await txt(`_dmarc.${organisation}`).catch(() => null);
    dmarcRecords = (parent?.records ?? []).filter((r) => /^v=DMARC1\s*(;|$)/i.test(r.trim()));
    if (dmarcRecords.length) inherited = organisation;
  }
  const reportTo = `info@${domain}`;
  if (dmarcRecords.length > 1) {
    add('error', 'dmarc-multiple', { domain, records: dmarcRecords });
  } else if (dmarcRecords.length === 0) {
    // A domain that sends no mail can refuse every message in its name at once.
    add('warn', 'dmarc-missing', { domain, suggestion: `v=DMARC1; p=${sends ? 'none' : 'reject'}; rua=mailto:${reportTo}` });
  } else {
    const record = dmarcRecords[0].trim();
    const tags = dmarcTags(record);
    const policy = (tags.p ?? '').toLowerCase();
    const pct = Number.isFinite(Number(tags.pct)) && tags.pct !== undefined ? Math.max(0, Math.min(100, Number(tags.pct))) : 100;
    const reports = (tags.rua ?? '')
      .split(',')
      .map((r) => r.trim().replace(/^mailto:/i, '').replace(/!.*$/, ''))
      .filter(Boolean);
    if (!['none', 'quarantine', 'reject'].includes(policy)) {
      add('error', 'dmarc-invalid', { record, suggestion: `v=DMARC1; p=none; rua=mailto:${reportTo}` });
    } else if (policy === 'reject') {
      add('ok', 'dmarc-reject', { record, pct, inherited });
    } else if (policy === 'quarantine') {
      add('ok', 'dmarc-quarantine', { record, pct, inherited });
    } else {
      const suggestion = withTag(reports.length ? record : withTag(record, 'rua', `mailto:${reportTo}`), 'p', 'quarantine');
      add('warn', 'dmarc-none', { record, domain, sample: `info@${domain}`, reports, suggestion });
    }
    if (['none', 'quarantine', 'reject'].includes(policy) && !reports.length && !inherited) {
      add('info', 'dmarc-no-reports', { suggestion: withTag(record, 'rua', `mailto:${reportTo}`) });
    }
  }

  // MTA-STS and TLS reporting, for domains that receive mail.
  if (usesMail) {
    const [sts, tlsrpt] = await Promise.all([txt(`_mta-sts.${domain}`).catch(() => null), txt(`_smtp._tls.${domain}`).catch(() => null)]);
    const hasSts = (sts?.records ?? []).some((r) => /^v=STSv1\s*;/i.test(r.trim()));
    const hasRpt = (tlsrpt?.records ?? []).some((r) => /^v=TLSRPTv1\s*;/i.test(r.trim()));
    if (hasSts) add('ok', 'mta-sts-ok', { tlsrpt: hasRpt });
    else add('info', 'mta-sts-missing');
  }

  return report(domain, findings, lang);
}

/**
 * Follows an SPF record's include and redirect parts and counts its DNS
 * lookups the way receivers do (include, a, mx, ptr, exists and redirect each
 * cost one). Returns { all, lookups, services, broken, ptr, unread }.
 */
async function readSpf(record, txt) {
  const result = { all: null, lookups: 0, services: [], ips: [], broken: null, ptr: false, unread: false };
  const seen = new Set();
  let reads = 0;
  const walk = async (text, top) => {
    let redirect = null;
    let hasAll = false;
    const includes = [];
    for (const term of spfTerms(text)) {
      if (['include', 'a', 'mx', 'ptr', 'exists'].includes(term.mechanism)) result.lookups++;
      if (term.mechanism === 'ptr') result.ptr = true;
      if (term.mechanism === 'all') {
        hasAll = true;
        if (top) result.all = term.qualifier;
      }
      if (term.mechanism === 'redirect') {
        result.lookups++;
        redirect = term.value.toLowerCase();
      }
      if (term.mechanism === 'include' && term.value) includes.push(term.value.toLowerCase());
      if (top && (term.mechanism === 'ip4' || term.mechanism === 'ip6')) result.ips.push(term.value);
    }
    if (top) {
      // A record that hands over to another (redirect=_spf.google.com) lets
      // that service send.
      for (const include of [...includes, ...(redirect && !hasAll ? [redirect] : [])]) {
        const known = SPF_SERVICES.find(([suffix]) => nameMatches(include, suffix));
        const name = known ? known[1] : include;
        if (!result.services.includes(name)) result.services.push(name);
      }
    }
    const next = [...includes, ...(redirect && !hasAll ? [redirect] : [])];
    await Promise.all(
      next.map(async (name) => {
        if (seen.has(name) || name.includes('%')) return;
        seen.add(name);
        if (reads >= SPF_INCLUDE_READS) {
          result.unread = true;
          return;
        }
        reads++;
        // One include that does not answer leaves the rest readable.
        const answer = await txt(name).catch(() => null);
        if (!answer) {
          result.unread = true;
          return;
        }
        const spf = answer.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
        if (spf.length !== 1) {
          result.broken ??= name;
          return;
        }
        if (name === redirect && top) {
          const inner = spfTerms(spf[0]).find((t) => t.mechanism === 'all');
          if (inner) result.all = inner.qualifier;
        }
        await walk(spf[0], false);
      }),
    );
  };
  await walk(record, true);
  return result;
}

/** The senders an SPF record allows, for people: services by name, addresses as a count. */
function senders(spf, lang) {
  const ips = spf.ips.length === 1 ? spf.ips : spf.ips.length ? [lang === 'et' ? `${spf.ips.length} IP-aadressi` : `${spf.ips.length} IP addresses`] : [];
  return [...spf.services, ...ips];
}

const RANK = { error: 3, warn: 2, info: 1, ok: 0 };

function report(domain, findings, lang) {
  const summary = { ok: 0, info: 0, warn: 0, error: 0, status: 'ok' };
  for (const f of findings) {
    summary[f.status]++;
    if (RANK[f.status] > RANK[summary.status]) summary.status = f.status;
  }
  return { tool: 'email-domain-check', version: VERSION, lang, domain, checkedAt: new Date().toISOString(), summary, findings };
}
