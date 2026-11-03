# email-domain-check

Loeb domeeni avalikud e-posti kirjed ja ütleb lihtsas keeles, kas kirjad jõuavad postkasti ja kas võõras saab saata kirju sinu nimel: e-posti server (MX), SPF, DKIM, DMARC ja MTA-STS. Iga leiu juures on parandus, sageli valmis DNS-kirjena, mille saab kopeerida.

Küsib ainult avalikku DNS-i (DNS over HTTPS: Cloudflare, siis Google). Postiserveritega ei ühendu ja kirju ei saada. Vajab ainult `fetch`-i, nii et töötab Node 18+, Cloudflare Workersi, Deno ja Buniga. Sõltuvusi pole.

Proovi brauseris: [novu.ee/tooriistad/e-posti-kontroll](https://novu.ee/tooriistad/e-posti-kontroll/)

*English below.*

## Mida see kontrollib

- **MX.** Kas domeenil on e-posti server ja kelle oma (Google Workspace, Microsoft 365, Zone, Zoho, Proton jt). Null MX (`0 .`) on õige domeenil, mis kirju vastu ei võta.
- **SPF.** Täpselt üks kirje; lõpp `~all` või `-all` (`+all` ja `?all` ei kaitse); kõik `include` ja `redirect` osad loetakse läbi ja DNS-päringud loetakse kokku nagu postiserver seda teeb, sest üle 10 on SPF vigane. Ütleb, millised teenused tohivad sinu nimel saata. Puuduva kirje jaoks pakub e-posti teenuse järgi õige kirje.
- **DKIM.** Otsib võtit tavalistest nimedest (`google`, `selector1`, `selector2`, `zone`, `default`, `k1`, `s1` jt). Võtit teise nime all väljast ei näe; selle nime leiad saadetud kirja päisest (`DKIM-Signature: s=…`) ja saad lisada valikuga `dkimSelectors`. Annab teada 1024-bitisest ja tühistatud võtmest.
- **DMARC.** Täpselt üks kirje ja kehtiv `p=`. `p=none` on hoiatus koos valmis `p=quarantine` kirjega, mis jätab sinu muud seaded alles. Alamdomeeni puhul loeb ka põhidomeeni kirjet. Annab teada, kui aruandeid (`rua=`) ei tule.
- **MTA-STS ja TLS-aruanded**, domeenidel, mis kirju vastu võtavad.

Domeen, mis kirju ei kasuta (MX-i ega saatjaid pole), saab soovituse `v=spf1 -all` ja `p=reject`, et seda ei saaks võltsimiseks kasutada.

## Kasutamine

Käsurealt, ilma midagi paigaldamata:

```bash
npx github:novuwebsolutions/email-domain-check firma.ee
npx github:novuwebsolutions/email-domain-check info@firma.ee --lang en --json
```

Valikud: `--lang en` (vaikimisi eesti keel), `--json`, `--selector nimi1,nimi2`. Väljumiskood 1 tähendab, et leiti viga või kontroll ei õnnestunud.

Oma koodis (Node, Workers, Deno, Bun), kas paketina või ühe faili kopeerimisega:

```bash
npm install github:novuwebsolutions/email-domain-check
```

```js
import { checkEmailDomain, CheckError } from 'email-domain-check';

try {
  const report = await checkEmailDomain('firma.ee', { lang: 'et' });
  console.log(report.summary); // { ok: 3, info: 2, warn: 1, error: 0, status: 'warn' }
  for (const f of report.findings) console.log(f.status, f.title, f.fix?.code ?? '');
} catch (error) {
  if (error instanceof CheckError) console.log(error.code, error.message); // 'nxdomain', 'Domeeni … pole olemas.'
  else throw error;
}
```

Valikud: `lang` (`'et'` või `'en'`), `dkimSelectors` (lisanimed DKIM-võtmetele), `fetch` (oma fetch, näiteks testides) ja `doh` (DNS-over-HTTPS aadressid järjekorras).

Tulemus:

```js
{
  tool: 'email-domain-check', version: '1.0.0', lang: 'et',
  domain: 'firma.ee', checkedAt: '2026-11-03T12:00:00.000Z',
  summary: { ok, info, warn, error, status },   // status on halvim leid
  findings: [
    { id: 'dmarc-none', status: 'warn', title: 'DMARC ainult jälgib', text: '…',
      fix: { text: '…', code: 'v=DMARC1; p=quarantine; rua=mailto:info@firma.ee' }, value: 'v=DMARC1; p=none; …' },
  ],
}
```

`status` on `ok`, `info`, `warn` või `error`. `id` jääb samaks ka teises keeles, nii et selle järgi saab oma teksti näidata.

## Oma Cloudflare Workerina

Kaustas on valmis Worker (`worker.mjs`), mis vastab päringule `GET /?domain=firma.ee&lang=et` JSON-iga:

```bash
git clone https://github.com/novuwebsolutions/email-domain-check.git
cd email-domain-check
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler deploy
```

Seal on piirang külastaja IP kohta (10 kontrolli minutis, `IP_LIMIT`) ja sama domeeni tulemus tuleb 10 minutit vahemälust, nii et keegi ei saa sinu Workeri päevaseid päringuid ära kulutada. Saladusi ega võtmeid pole vaja.

## Testid

```bash
npm test
```

Testid ei kasuta võrku: DNS-i vastused on testis kirjas.

## English

Reads a domain's public e-mail records and says in plain words whether its mail reaches inboxes and whether a stranger can send mail in its name: the mail server (MX), SPF, DKIM, DMARC and MTA-STS. Every finding comes with a fix, often a ready DNS record to copy. It only asks public DNS over HTTPS (Cloudflare, then Google), never connects to the mail servers and never sends mail. It needs nothing but `fetch`, so it runs in Node 18+, Cloudflare Workers, Deno and Bun, with no dependencies.

- **MX**: a mail server and whose it is (Google Workspace, Microsoft 365, Zone, Zoho, Proton and more); a null MX is right for a domain that takes no mail.
- **SPF**: exactly one record, ending in `~all` or `-all`; every `include` and `redirect` is followed and DNS lookups are counted the way receivers count them (over 10 breaks SPF); the services allowed to send are named, and a missing record gets the one your mail service documents.
- **DKIM**: keys under the usual selectors (`google`, `selector1`, `selector2`, `zone`, `default`, `k1`, `s1` and more). A key under another name cannot be seen from outside; a sent message names it (`DKIM-Signature: s=…`), and `dkimSelectors` adds it. 1024-bit and revoked keys are reported.
- **DMARC**: one record with a valid `p=`; `p=none` is a warning with a ready `p=quarantine` record that keeps your other tags; a subdomain falls back to its organisation's record; no `rua=` is reported.
- **MTA-STS** and TLS reporting, for domains that receive mail.

```bash
npx github:novuwebsolutions/email-domain-check firma.ee --lang en
```

```js
import { checkEmailDomain } from 'email-domain-check';
const report = await checkEmailDomain('info@firma.ee', { lang: 'en' });
```

Options: `lang` (`'et'` or `'en'`), `dkimSelectors`, `fetch`, `doh`. It throws a `CheckError` (with a stable `code`) when the input is not a domain, the domain does not exist or DNS does not answer. `worker.mjs` with `wrangler.example.jsonc` is a ready Cloudflare Worker (`GET /?domain=firma.ee`) with a per-IP rate limit and a ten-minute cache. Tests run offline: `npm test`.

Made by [Novu Web Solutions](https://novu.ee), a web studio in Viljandi, Estonia. Try it in the browser at [novu.ee/tooriistad](https://novu.ee/tooriistad/). MIT licence.
