#!/usr/bin/env node
/* Servidor del simulador de walkie-talkie. Sin dependencias: funciona con Node.js 10 o superior.
   Uso:  node server.js            (HTTPS con certificado autofirmado, sin openssl)
         HTTP=1 node server.js     (fuerza HTTP; el micrófono solo funcionará en localhost)
         PORT=9000 node server.js  (otro puerto)
         CODE=1234 node server.js  (exige un código de sala para entrar)           */
'use strict';
const NODE_MAJOR = parseInt(process.versions.node, 10);
if (NODE_MAJOR < 10) {
  console.error('\n  Su version de Node.js (' + process.versions.node + ') es demasiado antigua. Se necesita Node 10 o superior (recomendado 18 o 20 LTS).');
  console.error('  Ubuntu/Debian:  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs');
  console.error('  Alternativa sin sudo:  instale nvm (https://github.com/nvm-sh/nvm) y ejecute  nvm install 20\n');
  process.exit(1);
}
const fs = require('fs'), path = require('path'), os = require('os'), http = require('http'), https = require('https');
const crypto = require('crypto'), net = require('net');

const FORCE_HTTP = process.env.HTTP === '1';
const CODE = (process.env.CODE || '').slice(0, 32);
const MAX_CH = 16, MAX_USERS = 32, TOT_MS = 45000, MAX_PAYLOAD = 64 * 1024;
const dir = __dirname, certDir = path.join(dir, 'certs');
let tlsOpts = null;

function lanIPs() { const o = [], n = os.networkInterfaces(); for (const k of Object.keys(n)) for (const i of n[k] || []) if ((i.family === 'IPv4' || i.family === 4) && !i.internal) o.push(i.address); return o; }
/* Certificado autofirmado generado en JavaScript puro (no necesita openssl) */
const der = (tag, ...c) => { const b = Buffer.concat(c), l = b.length;
  return Buffer.concat([l < 128 ? Buffer.from([tag, l]) : l < 256 ? Buffer.from([tag, 0x81, l]) : Buffer.from([tag, 0x82, l >> 8, l & 255]), b]); };
const oid = s => { const p = s.split('.').map(Number), b = [p[0] * 40 + p[1]];
  for (const n of p.slice(2)) { const t = [n & 127]; let x = n >> 7; while (x) { t.unshift((x & 127) | 128); x >>= 7; } b.push(...t); } return der(6, Buffer.from(b)); };
const dint = b => der(2, b[0] & 128 ? Buffer.concat([Buffer.from([0]), b]) : b);
const utc = d => der(23, Buffer.from(d.toISOString().replace(/[-:T]/g, '').slice(2, 14) + 'Z'));
function makeCert(ips) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const alg = der(0x30, oid('1.2.840.113549.1.1.11'), der(5, Buffer.alloc(0)));
  const name = der(0x30, der(0x31, der(0x30, oid('2.5.4.3'), der(12, Buffer.from('walkie-local')))));
  const sans = [der(0x82, Buffer.from('localhost')), der(0x87, Buffer.from([127, 0, 0, 1]))];
  for (const ip of ips) sans.push(der(0x87, Buffer.from(ip.split('.').map(Number))));
  const san = der(0x30, oid('2.5.29.17'), der(4, der(0x30, ...sans)));
  const eku = der(0x30, oid('2.5.29.37'), der(4, der(0x30, oid('1.3.6.1.5.5.7.3.1'))));
  const serial = crypto.randomBytes(8); serial[0] &= 0x7f;
  const now = Date.now(), tbs = der(0x30, der(0xA0, dint(Buffer.from([2]))), dint(serial), alg, name,
    der(0x30, utc(new Date(now - 864e5)), utc(new Date(now + 365 * 864e5))), name, publicKey.export({ type: 'spki', format: 'der' }), der(0xA3, der(0x30, san, eku)));
  const sig = crypto.createSign('RSA-SHA256').update(tbs).sign(privateKey), cert = der(0x30, tbs, alg, der(3, Buffer.concat([Buffer.from([0]), sig])));
  const pem = cert.toString('base64').match(/.{1,64}/g).join('\n');
  return { key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: '-----BEGIN CERTIFICATE-----\n' + pem + '\n-----END CERTIFICATE-----\n' };
}
function opensslCert(key, crt) {
  try {
    fs.mkdirSync(certDir, { recursive: true });
    require('child_process').execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', crt, '-days', '365', '-subj', '/CN=walkie-local'], { stdio: 'ignore' });
    return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
  } catch (e) { console.error('  No se pudo crear el certificado HTTPS; se usara HTTP.'); return null; }
}
function ensureCert() {
  const ips = lanIPs().sort();
  const key = path.join(certDir, 'key.pem'), crt = path.join(certDir, 'cert.pem'), tag = path.join(certDir, 'ips.txt');
  try {
    if (!(fs.existsSync(key) && fs.existsSync(crt) && fs.existsSync(tag) && fs.readFileSync(tag, 'utf8') === ips.join(','))) {
      const c = makeCert(ips); fs.mkdirSync(certDir, { recursive: true });
      fs.writeFileSync(key, c.key, { mode: 0o600 }); fs.writeFileSync(crt, c.cert); fs.writeFileSync(tag, ips.join(','));
    }
    return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
  } catch (e) { try { const c = makeCert(ips); return { key: c.key, cert: c.cert }; } catch (e2) { return opensslCert(key, crt); } }
}
if (!FORCE_HTTP) tlsOpts = ensureCert();
const PORT = parseInt(process.env.PORT, 10) || (tlsOpts ? 8443 : 8080);

/* Copia incrustada de index.html: se usa si no hay un index.html junto a este archivo. */
const EMBEDDED_HTML_B64 = [
  'PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVzIj4KPGhlYWQ+CjxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KPG1ldGEgbmFtZT0i',
  'dmlld3BvcnQiIGNvbnRlbnQ9IndpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLCB2aWV3cG9ydC1maXQ9Y292ZXIi',
  'Pgo8dGl0bGU+V2Fsa2llLXRhbGtpZSDCtyBzaW11bGFkb3IgZW4gcmVkIGxvY2FsPC90aXRsZT4KPHN0eWxlPgo6cm9vdHstLWJn',
  'OiMwZDEwMTM7LS1wYW5lbDojMTYxYjIwOy0tZWRnZTojMmEzMjNhOy0tdHh0OiNkYmUzZWE7LS1tdXQ6Izg0OTNhMDstLWFjYzoj',
  'ZjBhMjNhOy0tb2s6IzVmZDM4ZDstLWJhZDojZmY1ZDRkOy0tbGNkOiNiOGYyYTA7LS1sY2QtYmc6IzBiMWEwZDsKLS1zYW5zOiJB',
  'dmVuaXIgTmV4dCIsIlNlZ29lIFVJIiwiSGVsdmV0aWNhIE5ldWUiLEFyaWFsLHNhbnMtc2VyaWY7LS1tb25vOnVpLW1vbm9zcGFj',
  'ZSwiU0YgTW9ubyIsTWVubG8sQ29uc29sYXMsbW9ub3NwYWNlfQoqe2JveC1zaXppbmc6Ym9yZGVyLWJveH1baGlkZGVuXXtkaXNw',
  'bGF5Om5vbmUhaW1wb3J0YW50fQpodG1sLGJvZHl7bWFyZ2luOjA7bWluLWhlaWdodDoxMDAlfQpib2R5e2JhY2tncm91bmQ6cmFk',
  'aWFsLWdyYWRpZW50KDkwMHB4IDUwMHB4IGF0IDUwJSAtMTAlLCMxYzI0MmMsdmFyKC0tYmcpKTtjb2xvcjp2YXIoLS10eHQpO2Zv',
  'bnQ6MTVweC8xLjQ1IHZhcigtLXNhbnMpO3BhZGRpbmc6ZW52KHNhZmUtYXJlYS1pbnNldC10b3ApIDEycHggZW52KHNhZmUtYXJl',
  'YS1pbnNldC1ib3R0b20pOy13ZWJraXQtdGFwLWhpZ2hsaWdodC1jb2xvcjp0cmFuc3BhcmVudH0KaDF7Zm9udC1zaXplOjE4cHg7',
  'bWFyZ2luOjA7bGV0dGVyLXNwYWNpbmc6LjA0ZW19Ci53cmFwe21heC13aWR0aDo5MDBweDttYXJnaW46MCBhdXRvO3BhZGRpbmc6',
  'MTZweCAwIDI4cHh9Ci50b3B7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6MTJweDtmbGV4LXdyYXA6d3JhcDtt',
  'YXJnaW4tYm90dG9tOjE0cHh9LnRvcCAuc3B7ZmxleDoxfQouY29ubntmb250OjEycHggdmFyKC0tbW9ubyk7cGFkZGluZzo0cHgg',
  'MTBweDtib3JkZXItcmFkaXVzOjk5OXB4O2JvcmRlcjoxcHggc29saWQgdmFyKC0tZWRnZSk7Y29sb3I6dmFyKC0tbXV0KX0uY29u',
  'bi5va3tjb2xvcjp2YXIoLS1vayk7Ym9yZGVyLWNvbG9yOiMyZDZiNGF9LmNvbm4uYmFke2NvbG9yOnZhcigtLWJhZCk7Ym9yZGVy',
  'LWNvbG9yOiM3YTJhMjJ9Ci5jYXJke2JhY2tncm91bmQ6dmFyKC0tcGFuZWwpO2JvcmRlcjoxcHggc29saWQgdmFyKC0tZWRnZSk7',
  'Ym9yZGVyLXJhZGl1czoxMnB4O3BhZGRpbmc6MTZweH0KLmxvZ2lue21heC13aWR0aDo0MjBweDttYXJnaW46MzBweCBhdXRvfS5s',
  'b2dpbiBsYWJlbHtkaXNwbGF5OmJsb2NrO21hcmdpbjoxMnB4IDAgNHB4O2ZvbnQtc2l6ZToxM3B4O2NvbG9yOnZhcigtLW11dCl9',
  'CmlucHV0LHNlbGVjdHt3aWR0aDoxMDAlO2JhY2tncm91bmQ6IzBjMTAxNDtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWVkZ2UpO2Jv',
  'cmRlci1yYWRpdXM6OHB4O3BhZGRpbmc6MTBweCAxMnB4O2NvbG9yOnZhcigtLXR4dCk7Zm9udDppbmhlcml0fQppbnB1dDpmb2N1',
  'cy12aXNpYmxlLHNlbGVjdDpmb2N1cy12aXNpYmxlLGJ1dHRvbjpmb2N1cy12aXNpYmxle291dGxpbmU6MnB4IHNvbGlkIHZhcigt',
  'LWFjYyk7b3V0bGluZS1vZmZzZXQ6MnB4fQouYnRue2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KCMyZDM1M2QsIzFlMjUyYik7',
  'Ym9yZGVyOjFweCBzb2xpZCAjMGIwZTEwO2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOnZhcigtLXR4dCk7cGFkZGluZzoxMHB4IDE0',
  'cHg7Zm9udDppbmhlcml0O2N1cnNvcjpwb2ludGVyfS5idG46aG92ZXJ7Ym9yZGVyLWNvbG9yOnZhcigtLWFjYyl9Ci5idG4ubWFp',
  'bntiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgjZjBhMjNhLCNjOTdhMTQpO2NvbG9yOiMxYTEyMDU7Zm9udC13ZWlnaHQ6NzAw',
  'O3dpZHRoOjEwMCU7bWFyZ2luLXRvcDoxOHB4O2JvcmRlcjpub25lfQoubm90ZXtmb250LXNpemU6MTIuNXB4O2NvbG9yOnZhcigt',
  'LW11dCk7bWFyZ2luLXRvcDoxMnB4fS53YXJue2NvbG9yOiNmZmQyN2E7YmFja2dyb3VuZDojMmEyMTBjO2JvcmRlcjoxcHggc29s',
  'aWQgIzZiNTIxNztib3JkZXItcmFkaXVzOjhweDtwYWRkaW5nOjhweCAxMHB4O21hcmdpbi10b3A6MTJweDtmb250LXNpemU6MTNw',
  'eH0KLm1haW57ZGlzcGxheTpncmlkO2dyaWQtdGVtcGxhdGUtY29sdW1uczptaW5tYXgoMzAwcHgsMzgwcHgpIDFmcjtnYXA6MThw',
  'eDthbGlnbi1pdGVtczpzdGFydH0KLnJhZGlve3Bvc2l0aW9uOnJlbGF0aXZlO21hcmdpbjozNHB4IGF1dG8gMDt3aWR0aDoxMDAl',
  'O21heC13aWR0aDozODBweDtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgxNjBkZWcsIzJiMzMzYiwjMTcxYzIxIDU1JSwjMTAx',
  'NDE4KTtib3JkZXI6MXB4IHNvbGlkICMzYTQ0NGQ7Ym9yZGVyLXJhZGl1czoyNnB4IDI2cHggMzRweCAzNHB4O3BhZGRpbmc6MjJw',
  'eCAyMHB4IDI0cHg7Ym94LXNoYWRvdzowIDE4cHggNDBweCAjMDAwYixpbnNldCAwIDFweCAwICNmZmZmZmYxOH0KLnJhZGlvOjpi',
  'ZWZvcmV7Y29udGVudDoiIjtwb3NpdGlvbjphYnNvbHV0ZTt0b3A6LTQ0cHg7cmlnaHQ6NDZweDt3aWR0aDoxNnB4O2hlaWdodDo0',
  'OHB4O2JvcmRlci1yYWRpdXM6OHB4IDhweCAzcHggM3B4O2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KDkwZGVnLCMxNTE5MWQs',
  'IzM4NDI0YiwjMTUxOTFkKX0KLnJhZGlvOjphZnRlcntjb250ZW50OiIiO3Bvc2l0aW9uOmFic29sdXRlO3RvcDotMThweDtsZWZ0',
  'OjM4cHg7d2lkdGg6MzRweDtoZWlnaHQ6MjBweDtib3JkZXItcmFkaXVzOjZweCA2cHggMCAwO2JhY2tncm91bmQ6bGluZWFyLWdy',
  'YWRpZW50KCMzMjNiNDMsIzFiMjEyNyl9Ci5sZWRze2Rpc3BsYXk6ZmxleDtnYXA6MTRweDtmb250OjExcHggdmFyKC0tbW9ubyk7',
  'Y29sb3I6dmFyKC0tbXV0KTttYXJnaW4tYm90dG9tOjEwcHh9LmxlZCBpe2Rpc3BsYXk6aW5saW5lLWJsb2NrO3dpZHRoOjEwcHg7',
  'aGVpZ2h0OjEwcHg7Ym9yZGVyLXJhZGl1czo1MCU7YmFja2dyb3VuZDojMjYyYjMwO21hcmdpbi1yaWdodDo1cHg7dmVydGljYWwt',
  'YWxpZ246LTFweH0KLmxlZC5yeC5vbiBpe2JhY2tncm91bmQ6dmFyKC0tb2spO2JveC1zaGFkb3c6MCAwIDEwcHggdmFyKC0tb2sp',
  'fS5sZWQudHgub24gaXtiYWNrZ3JvdW5kOnZhcigtLWJhZCk7Ym94LXNoYWRvdzowIDAgMTBweCB2YXIoLS1iYWQpfS5sZWQuYnou',
  'b24gaXtiYWNrZ3JvdW5kOnZhcigtLWFjYyk7Ym94LXNoYWRvdzowIDAgMTBweCB2YXIoLS1hY2MpfQoubGNke2JhY2tncm91bmQ6',
  'bGluZWFyLWdyYWRpZW50KCMwZTIyMTIsdmFyKC0tbGNkLWJnKSk7Ym9yZGVyOjNweCBzb2xpZCAjMDUwNjA3O2JvcmRlci1yYWRp',
  'dXM6OHB4O3BhZGRpbmc6MTBweCAxMnB4O2NvbG9yOnZhcigtLWxjZCk7Zm9udC1mYW1pbHk6dmFyKC0tbW9ubyk7Ym94LXNoYWRv',
  'dzppbnNldCAwIDAgMjJweCAjMDAwO3Bvc2l0aW9uOnJlbGF0aXZlO292ZXJmbG93OmhpZGRlbn0KLmxjZDo6YWZ0ZXJ7Y29udGVu',
  'dDoiIjtwb3NpdGlvbjphYnNvbHV0ZTtpbnNldDowO2JhY2tncm91bmQ6cmVwZWF0aW5nLWxpbmVhci1ncmFkaWVudCgwZGVnLCMw',
  'MDAwIDAgMnB4LCMwMDAwMDAxYSAycHggM3B4KTtwb2ludGVyLWV2ZW50czpub25lfQoubGNkIC5yMXtkaXNwbGF5OmZsZXg7anVz',
  'dGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW47YWxpZ24taXRlbXM6YmFzZWxpbmV9LmxjZCAuY2h7Zm9udC1zaXplOjM4cHg7Zm9u',
  'dC13ZWlnaHQ6NzAwO3RleHQtc2hhZG93OjAgMCAxMHB4IHZhcigtLWxjZCk7bGV0dGVyLXNwYWNpbmc6LjA1ZW19Ci5sY2QgLnN0',
  'e2ZvbnQtc2l6ZToxM3B4O21pbi1oZWlnaHQ6MTlweH0ubGNkIC5ubXtmb250LXNpemU6MTJweDtvcGFjaXR5Oi43NX0ubGNkIGNh',
  'bnZhc3t3aWR0aDoxMDAlO2hlaWdodDoyNnB4O2Rpc3BsYXk6YmxvY2s7bWFyZ2luLXRvcDo0cHh9Ci5ncmlsbGV7aGVpZ2h0OjQ2',
  'cHg7bWFyZ2luOjE2cHggMDtib3JkZXItcmFkaXVzOjhweDtiYWNrZ3JvdW5kOnJlcGVhdGluZy1saW5lYXItZ3JhZGllbnQoOTBk',
  'ZWcsIzBhMGQxMCAwIDRweCwjMjMyYTMxIDRweCA4cHgpO2JveC1zaGFkb3c6aW5zZXQgMCAycHggOHB4ICMwMDB9Ci5yb3d7ZGlz',
  'cGxheTpmbGV4O2dhcDoxMHB4O2FsaWduLWl0ZW1zOmNlbnRlcjtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2Vlbn0KLnNidG57',
  'ZmxleDoxO2JhY2tncm91bmQ6bGluZWFyLWdyYWRpZW50KCMzMjNiNDMsIzFmMjUyYSk7Ym9yZGVyOjFweCBzb2xpZCAjMDkwYjBk',
  'O2JvcmRlci1yYWRpdXM6OHB4O2NvbG9yOiNkNGRjZTM7cGFkZGluZzoxMHB4IDRweDtmb250OjYwMCAxMnB4IHZhcigtLXNhbnMp',
  'O2N1cnNvcjpwb2ludGVyO2JveC1zaGFkb3c6MCAzcHggMCAjMGEwYzBlO3VzZXItc2VsZWN0Om5vbmU7dG91Y2gtYWN0aW9uOm1h',
  'bmlwdWxhdGlvbn0KLnNidG46YWN0aXZle3RyYW5zZm9ybTp0cmFuc2xhdGVZKDJweCk7Ym94LXNoYWRvdzowIDFweCAwICMwYTBj',
  'MGV9LnNidG4ub257Y29sb3I6IzFhMTIwNTtiYWNrZ3JvdW5kOmxpbmVhci1ncmFkaWVudCgjZjBhMjNhLCNjOTdhMTQpfQoudm9s',
  'e21hcmdpbjoxNHB4IDAgMnB4fS52b2wgbGFiZWx7Zm9udC1zaXplOjExcHg7Y29sb3I6dmFyKC0tbXV0KTtkaXNwbGF5OmZsZXg7',
  'anVzdGlmeS1jb250ZW50OnNwYWNlLWJldHdlZW59LnZvbCBpbnB1dHtwYWRkaW5nOjA7YWNjZW50LWNvbG9yOnZhcigtLWFjYyl9',
  'Ci5wdHR7ZGlzcGxheTpibG9jazt3aWR0aDoxMDAlO21hcmdpbi10b3A6MTZweDtoZWlnaHQ6MTEycHg7Ym9yZGVyLXJhZGl1czo1',
  'NnB4O2JvcmRlcjpub25lO2N1cnNvcjpwb2ludGVyO3RvdWNoLWFjdGlvbjpub25lO3VzZXItc2VsZWN0Om5vbmU7LXdlYmtpdC11',
  'c2VyLXNlbGVjdDpub25lOwogYmFja2dyb3VuZDpyYWRpYWwtZ3JhZGllbnQoY2lyY2xlIGF0IDUwJSAzMCUsI2ZmN2E1YywjYzQy',
  'ODFhIDcwJSk7Y29sb3I6I2ZmZjtmb250OjgwMCAyMHB4IHZhcigtLXNhbnMpO2xldHRlci1zcGFjaW5nOi4xZW07Ym94LXNoYWRv',
  'dzowIDhweCAwICM2ZTE0MGMsMCAxNHB4IDI0cHggIzAwMGF9Ci5wdHQgc21hbGx7ZGlzcGxheTpibG9jaztmb250OjUwMCAxMXB4',
  'IHZhcigtLXNhbnMpO2xldHRlci1zcGFjaW5nOi4wNGVtO29wYWNpdHk6Ljg1O21hcmdpbi10b3A6NHB4fQoucHR0LmRvd257dHJh',
  'bnNmb3JtOnRyYW5zbGF0ZVkoNnB4KTtib3gtc2hhZG93OjAgMnB4IDAgIzZlMTQwYywwIDRweCAxMHB4ICMwMDBhO2JhY2tncm91',
  'bmQ6cmFkaWFsLWdyYWRpZW50KGNpcmNsZSBhdCA1MCUgMzAlLCNmZjllODUsI2UwMzExZiA3MCUpfQoucHR0OmRpc2FibGVke2Zp',
  'bHRlcjpncmF5c2NhbGUoMSkgYnJpZ2h0bmVzcyguNik7Y3Vyc29yOm5vdC1hbGxvd2VkfQouc2lkZSBoMntmb250LXNpemU6MTRw',
  'eDttYXJnaW46MCAwIDhweDtjb2xvcjp2YXIoLS1hY2MpfS51c2Vyc3tsaXN0LXN0eWxlOm5vbmU7bWFyZ2luOjA7cGFkZGluZzow',
  'O2Rpc3BsYXk6Z3JpZDtnYXA6NnB4fQoudXNlcnMgbGl7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6OHB4O2Jh',
  'Y2tncm91bmQ6IzEwMTUxYTtib3JkZXI6MXB4IHNvbGlkIHZhcigtLWVkZ2UpO2JvcmRlci1yYWRpdXM6OHB4O3BhZGRpbmc6OHB4',
  'IDEwcHh9Ci51c2VycyBsaS50YWxre2JvcmRlci1jb2xvcjp2YXIoLS1vayk7Ym94LXNoYWRvdzowIDAgMTJweCAjNWZkMzhkNDR9',
  'LnVzZXJzIGxpLm1le2JvcmRlci1jb2xvcjojNGE1YTY4fS51c2VycyAuZG90e3dpZHRoOjlweDtoZWlnaHQ6OXB4O2JvcmRlci1y',
  'YWRpdXM6NTAlO2JhY2tncm91bmQ6IzJjMzQzYn0udXNlcnMgbGkudGFsayAuZG90e2JhY2tncm91bmQ6dmFyKC0tb2spfQoudXNl',
  'cnMgLnRhZ3ttYXJnaW4tbGVmdDphdXRvO2ZvbnQ6MTFweCB2YXIoLS1tb25vKTtjb2xvcjp2YXIoLS1tdXQpfQoubG9ne2ZvbnQ6',
  'MTJweCB2YXIoLS1tb25vKTtjb2xvcjojYTliN2MzO21heC1oZWlnaHQ6MTUwcHg7b3ZlcmZsb3c6YXV0bztkaXNwbGF5OmdyaWQ7',
  'Z2FwOjNweH0uc2Vje21hcmdpbi10b3A6MTZweH0KLnNoYXJle2Rpc3BsYXk6ZmxleDtnYXA6OHB4fS5zaGFyZSBpbnB1dHtmb250',
  'OjEycHggdmFyKC0tbW9ubyl9LnNoYXJlIC5idG57d2lkdGg6YXV0bzt3aGl0ZS1zcGFjZTpub3dyYXB9Ci50b2FzdHtwb3NpdGlv',
  'bjpmaXhlZDtsZWZ0OjUwJTtib3R0b206Y2FsYygxOHB4ICsgZW52KHNhZmUtYXJlYS1pbnNldC1ib3R0b20pKTt0cmFuc2Zvcm06',
  'dHJhbnNsYXRlWCgtNTAlKTtiYWNrZ3JvdW5kOiMyMDI3MmQ7Ym9yZGVyOjFweCBzb2xpZCB2YXIoLS1hY2MpO3BhZGRpbmc6OXB4',
  'IDE2cHg7Ym9yZGVyLXJhZGl1czo4cHg7ei1pbmRleDo5O21heC13aWR0aDo5MnZ3fQoudG9hc3QuZXJye2JvcmRlci1jb2xvcjp2',
  'YXIoLS1iYWQpfQpAbWVkaWEgKG1heC13aWR0aDo3NjBweCl7Lm1haW57Z3JpZC10ZW1wbGF0ZS1jb2x1bW5zOjFmcn19CkBtZWRp',
  'YSAocHJlZmVycy1yZWR1Y2VkLW1vdGlvbjpyZWR1Y2Upeyp7dHJhbnNpdGlvbjpub25lIWltcG9ydGFudDthbmltYXRpb246bm9u',
  'ZSFpbXBvcnRhbnR9fQo8L3N0eWxlPgo8L2hlYWQ+Cjxib2R5Pgo8ZGl2IGNsYXNzPSJ3cmFwIj4KIDxkaXYgY2xhc3M9InRvcCI+',
  'PGgxPldBTEtJRS1UQUxLSUU8L2gxPjxzcGFuIGNsYXNzPSJjb25uIiBpZD0iY29ubiI+c2luIGNvbmV4acOzbjwvc3Bhbj48c3Bh',
  'biBjbGFzcz0ic3AiPjwvc3Bhbj48c3BhbiBjbGFzcz0ibm90ZSIgc3R5bGU9Im1hcmdpbjowIj5TaW11bGFkb3IgZWR1Y2F0aXZv',
  'IGVuIHJlZCBsb2NhbDwvc3Bhbj48L2Rpdj4KCiA8ZGl2IGlkPSJsb2dpbiIgY2xhc3M9ImNhcmQgbG9naW4iPgogIDxoMiBzdHls',
  'ZT0ibWFyZ2luOjAgMCA0cHg7Zm9udC1zaXplOjE2cHgiPkVudHJhciBhbCBjYW5hbDwvaDI+CiAgPHAgY2xhc3M9Im5vdGUiIHN0',
  'eWxlPSJtYXJnaW4tdG9wOjAiPlRvZG9zIGxvcyBxdWUgYWJyYW4gZXN0YSBtaXNtYSBkaXJlY2Npw7NuIChsYSBJUCBkZWwgZXF1',
  'aXBvIHF1ZSBlamVjdXRhIGVsIHNlcnZpZG9yKSB5IGVsaWphbiBlbCBtaXNtbyBjYW5hbCBwb2Ryw6FuIGhhYmxhciBlbnRyZSBz',
  'w60uPC9wPgogIDxsYWJlbCBmb3I9Im5hbWUiPlN1IG5vbWJyZSBvIGluZGljYXRpdm88L2xhYmVsPjxpbnB1dCBpZD0ibmFtZSIg',
  'bWF4bGVuZ3RoPSIxNiIgYXV0b2NvbXBsZXRlPSJuaWNrbmFtZSIgcGxhY2Vob2xkZXI9InAuIGVqLiBBbmEiPgogIDxsYWJlbCBm',
  'b3I9ImNoU2VsIj5DYW5hbDwvbGFiZWw+PHNlbGVjdCBpZD0iY2hTZWwiPjwvc2VsZWN0PgogIDxkaXYgaWQ9ImNvZGVCb3giIGhp',
  'ZGRlbj48bGFiZWwgZm9yPSJjb2RlIj5Dw7NkaWdvIGRlIHNhbGE8L2xhYmVsPjxpbnB1dCBpZD0iY29kZSIgdHlwZT0icGFzc3dv',
  'cmQiIGF1dG9jb21wbGV0ZT0ib2ZmIj48L2Rpdj4KICA8YnV0dG9uIGNsYXNzPSJidG4gbWFpbiIgaWQ9ImpvaW4iIHR5cGU9ImJ1',
  'dHRvbiI+RU5UUkFSPC9idXR0b24+CiAgPGRpdiBjbGFzcz0id2FybiIgaWQ9Indhcm5TZWN1cmUiIGhpZGRlbj48L2Rpdj48ZGl2',
  'IGNsYXNzPSJ3YXJuIiBpZD0id2FybkZpbGUiIGhpZGRlbj48L2Rpdj4KIDwvZGl2PgoKIDxkaXYgaWQ9ImFwcCIgY2xhc3M9Im1h',
  'aW4iIGhpZGRlbj4KICA8ZGl2PgogICA8ZGl2IGNsYXNzPSJyYWRpbyI+CiAgICA8ZGl2IGNsYXNzPSJsZWRzIj48c3BhbiBjbGFz',
  'cz0ibGVkIHJ4IiBpZD0ibGVkUngiPjxpPjwvaT5SWDwvc3Bhbj48c3BhbiBjbGFzcz0ibGVkIHR4IiBpZD0ibGVkVHgiPjxpPjwv',
  'aT5UWDwvc3Bhbj48c3BhbiBjbGFzcz0ibGVkIGJ6IiBpZD0ibGVkQnoiPjxpPjwvaT5PQ1VQQURPPC9zcGFuPjwvZGl2PgogICAg',
  'PGRpdiBjbGFzcz0ibGNkIj48ZGl2IGNsYXNzPSJyMSI+PHNwYW4gY2xhc3M9ImNoIiBpZD0ibGNkQ2giPkNIIDAxPC9zcGFuPjxz',
  'cGFuIGNsYXNzPSJubSIgaWQ9ImxjZFVzZXJzIj4xIHVzdWFyaW88L3NwYW4+PC9kaXY+PGRpdiBjbGFzcz0ic3QiIGlkPSJsY2RT',
  'dCI+TElCUkU8L2Rpdj48ZGl2IGNsYXNzPSJubSIgaWQ9ImxjZE1lIj48L2Rpdj48Y2FudmFzIGlkPSJtZXRlciI+PC9jYW52YXM+',
  'PC9kaXY+CiAgICA8ZGl2IGNsYXNzPSJncmlsbGUiIGFyaWEtaGlkZGVuPSJ0cnVlIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InJv',
  'dyI+PGJ1dHRvbiBjbGFzcz0ic2J0biIgaWQ9ImNoRG4iIHR5cGU9ImJ1dHRvbiIgYXJpYS1sYWJlbD0iQ2FuYWwgYW50ZXJpb3Ii',
  'PkNIIOKWvDwvYnV0dG9uPjxidXR0b24gY2xhc3M9InNidG4iIGlkPSJjYWxsQnRuIiB0eXBlPSJidXR0b24iPkxMQU1BREE8L2J1',
  'dHRvbj48YnV0dG9uIGNsYXNzPSJzYnRuIiBpZD0iY2hVcCIgdHlwZT0iYnV0dG9uIiBhcmlhLWxhYmVsPSJDYW5hbCBzaWd1aWVu',
  'dGUiPkNIIOKWsjwvYnV0dG9uPjwvZGl2PgogICAgPGRpdiBjbGFzcz0idm9sIj48bGFiZWwgZm9yPSJ2b2wiPjxzcGFuPlZPTFVN',
  'RU48L3NwYW4+PHNwYW4gaWQ9InZvbFYiPjgwJTwvc3Bhbj48L2xhYmVsPjxpbnB1dCBpZD0idm9sIiB0eXBlPSJyYW5nZSIgbWlu',
  'PSIwIiBtYXg9IjEwMCIgdmFsdWU9IjgwIj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InJvdyIgc3R5bGU9Im1hcmdpbi10b3A6MTBw',
  'eCI+PGJ1dHRvbiBjbGFzcz0ic2J0biBvbiIgaWQ9InRnUm9nZXIiIHR5cGU9ImJ1dHRvbiIgYXJpYS1wcmVzc2VkPSJ0cnVlIj5S',
  'T0dFUjwvYnV0dG9uPjxidXR0b24gY2xhc3M9InNidG4gb24iIGlkPSJ0Z1NxbCIgdHlwZT0iYnV0dG9uIiBhcmlhLXByZXNzZWQ9',
  'InRydWUiPlNRVUVMQ0g8L2J1dHRvbj48YnV0dG9uIGNsYXNzPSJzYnRuIiBpZD0idGdMYXRjaCIgdHlwZT0iYnV0dG9uIiBhcmlh',
  'LXByZXNzZWQ9ImZhbHNlIj5GSUpPPC9idXR0b24+PC9kaXY+CiAgICA8YnV0dG9uIGNsYXNzPSJwdHQiIGlkPSJwdHQiIHR5cGU9',
  'ImJ1dHRvbiIgYXJpYS1sYWJlbD0iUHVsc2FyIHBhcmEgaGFibGFyIj5QVUxTQVIgUEFSQSBIQUJMQVI8c21hbGw+bWFudGVuZ2Eg',
  'cHVsc2FkbyBvIHVzZSBsYSBiYXJyYSBlc3BhY2lhZG9yYTwvc21hbGw+PC9idXR0b24+CiAgIDwvZGl2PgogIDwvZGl2PgogIDxk',
  'aXYgY2xhc3M9InNpZGUiPgogICA8ZGl2IGNsYXNzPSJjYXJkIj48aDI+VXN1YXJpb3MgZW4gZWwgY2FuYWw8L2gyPjx1bCBjbGFz',
  'cz0idXNlcnMiIGlkPSJ1c2VycyI+PC91bD4KICAgIDxkaXYgY2xhc3M9InNlYyI+PGgyPkNvbXBhcnRpcjwvaDI+PGRpdiBjbGFz',
  'cz0ic2hhcmUiPjxpbnB1dCBpZD0ic2hhcmVVcmwiIHJlYWRvbmx5IGFyaWEtbGFiZWw9IkRpcmVjY2nDs24gcGFyYSBjb21wYXJ0',
  'aXIiPjxidXR0b24gY2xhc3M9ImJ0biIgaWQ9ImNvcHkiIHR5cGU9ImJ1dHRvbiI+Q29waWFyPC9idXR0b24+PC9kaXY+PHAgY2xh',
  'c3M9Im5vdGUiPkVudsOtZSBlc3RhIGRpcmVjY2nDs24gYSBxdWllbmVzIGVzdMOpbiBlbiBsYSBtaXNtYSByZWQuPC9wPjwvZGl2',
  'PgogICAgPGRpdiBjbGFzcz0ic2VjIj48aDI+QWN0aXZpZGFkPC9oMj48ZGl2IGNsYXNzPSJsb2ciIGlkPSJsb2ciIGFyaWEtbGl2',
  'ZT0icG9saXRlIj48L2Rpdj48L2Rpdj4KICAgIDxkaXYgY2xhc3M9InNlYyI+PGJ1dHRvbiBjbGFzcz0iYnRuIiBpZD0ibGVhdmUi',
  'IHR5cGU9ImJ1dHRvbiI+U2FsaXI8L2J1dHRvbj48L2Rpdj4KICAgPC9kaXY+CiAgPC9kaXY+CiA8L2Rpdj4KPC9kaXY+CjxkaXYg',
  'Y2xhc3M9InRvYXN0IiBpZD0idG9hc3QiIGhpZGRlbj48L2Rpdj4KPHNjcmlwdD4KKCgpPT57J3VzZSBzdHJpY3QnOwpjb25zdCAk',
  'PWlkPT5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChpZCksUkFURT0xNjAwMCxGUj0zMjAsc3Q9e3J4OjAsdHg6MH07d2luZG93Lndh',
  'bGtpZT17c3R9OwpsZXQgd3M9bnVsbCxjdHg9bnVsbCxpbnA9bnVsbCx2b2w9bnVsbCxhbmE9bnVsbCxub2lzZUJ1Zj1udWxsLG1p',
  'Y1RyYWNrPW51bGwsam9pbmVkPWZhbHNlLHdhbnRKb2luPW51bGwscmV0cnk9MTAwMCxyZWNvbm5UPTA7CmxldCBtZT17aWQ6MCxu',
  'YW1lOicnLGNoOjF9LHVzZXJzPVtdLHRhbGtlcj1udWxsLHBlbmRpbmc9ZmFsc2UsdHhPbj1mYWxzZSxwdHREb3duPWZhbHNlLGxp',
  'c3Rlbk9ubHk9ZmFsc2UsbGF0Y2g9ZmFsc2Uscm9nZXI9dHJ1ZSxzcWw9dHJ1ZTsKbGV0IHF1ZXVlPVtdLHBsYXlUPTAscnhTaW5j',
  'ZT0wLG1pY0xldmVsPTAscGg9MCxzdW09MCxjbnQ9MCxmcj1uZXcgSW50MTZBcnJheShGUiksZmk9MDsKY29uc3Qgc3RvcmU9KGss',
  'dik9Pnt0cnl7aWYodj09PXVuZGVmaW5lZClyZXR1cm4gbG9jYWxTdG9yYWdlLmdldEl0ZW0oayk7bG9jYWxTdG9yYWdlLnNldEl0',
  'ZW0oayx2KX1jYXRjaChlKXtyZXR1cm4gbnVsbH19OwpmdW5jdGlvbiB0b2FzdChtLGVycil7Y29uc3QgdD0kKCd0b2FzdCcpO3Qu',
  'dGV4dENvbnRlbnQ9bTt0LmNsYXNzTmFtZT0ndG9hc3QnKyhlcnI/JyBlcnInOicnKTt0LmhpZGRlbj1mYWxzZTtjbGVhclRpbWVv',
  'dXQodG9hc3QuaCk7dG9hc3QuaD1zZXRUaW1lb3V0KCgpPT57dC5oaWRkZW49dHJ1ZX0sMzUwMCl9CmZ1bmN0aW9uIGxvZyhtKXtj',
  'b25zdCBsPSQoJ2xvZycpLGQ9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyksbj1uZXcgRGF0ZSgpO2QudGV4dENvbnRlbnQ9',
  'bi50b1RpbWVTdHJpbmcoKS5zbGljZSgwLDgpKycgICcrbTtsLnByZXBlbmQoZCk7d2hpbGUobC5jaGlsZHJlbi5sZW5ndGg+NDAp',
  'bC5sYXN0Q2hpbGQucmVtb3ZlKCl9CmZ1bmN0aW9uIHNldENvbm4oYyx0KXtjb25zdCBlPSQoJ2Nvbm4nKTtlLmNsYXNzTmFtZT0n',
  'Y29ubiAnK2M7ZS50ZXh0Q29udGVudD10fQpjb25zdCBzZW5kPW89PntpZih3cyYmd3MucmVhZHlTdGF0ZT09PTEpd3Muc2VuZChK',
  'U09OLnN0cmluZ2lmeShvKSl9OwovKiA9PT09PSBhcnJhbnF1ZSBkZSBsYSBpbnRlcmZheiA9PT09PSAqLwpjb25zdCBzZWw9JCgn',
  'Y2hTZWwnKTtmb3IobGV0IGk9MTtpPD0xNjtpKyspe2NvbnN0IG89ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnb3B0aW9uJyk7by52',
  'YWx1ZT1pO28udGV4dENvbnRlbnQ9J0NhbmFsICcrU3RyaW5nKGkpLnBhZFN0YXJ0KDIsJzAnKTtzZWwuYXBwZW5kQ2hpbGQobyl9',
  'CnNlbC52YWx1ZT1zdG9yZSgnd2tfY2gnKXx8JzEnOyQoJ25hbWUnKS52YWx1ZT1zdG9yZSgnd2tfbmFtZScpfHwnJzsKaWYobG9j',
  'YXRpb24ucHJvdG9jb2w9PT0nZmlsZTonKXtjb25zdCB3PSQoJ3dhcm5GaWxlJyk7dy5oaWRkZW49ZmFsc2U7dy50ZXh0Q29udGVu',
  'dD0nRXN0YSBww6FnaW5hIGRlYmUgYWJyaXJzZSBkZXNkZSBlbCBzZXJ2aWRvciAobm9kZSBzZXJ2ZXIuanMpIHkgbm8gY29tbyBh',
  'cmNoaXZvIGxvY2FsLic7JCgnam9pbicpLmRpc2FibGVkPXRydWV9CmVsc2UgaWYoIXdpbmRvdy5pc1NlY3VyZUNvbnRleHQpe2Nv',
  'bnN0IHc9JCgnd2FyblNlY3VyZScpO3cuaGlkZGVuPWZhbHNlO3cudGV4dENvbnRlbnQ9J0VzdGEgZGlyZWNjacOzbiBubyBlcyBz',
  'ZWd1cmEgKEhUVFApOiBlbCBuYXZlZ2Fkb3IgYmxvcXVlYXLDoSBlbCBtaWNyw7Nmb25vLiBQb2Ryw6EgZXNjdWNoYXIsIHBlcm8g',
  'bm8gaGFibGFyLiBBYnJhIGxhIGRpcmVjY2nDs24gaHR0cHM6Ly8gZGVsIHNlcnZpZG9yIHkgYWNlcHRlIGVsIGNlcnRpZmljYWRv',
  'Lid9CmZldGNoKCcvaW5mbycpLnRoZW4ocj0+ci5qc29uKCkpLnRoZW4oaT0+e2lmKGkuY29kZSkkKCdjb2RlQm94JykuaGlkZGVu',
  'PWZhbHNlfSkuY2F0Y2goKCk9Pnt9KTsKJCgnc2hhcmVVcmwnKS52YWx1ZT1sb2NhdGlvbi5vcmlnaW4rJy8nOwovKiA9PT09PSBh',
  'dWRpbyA9PT09PSAqLwpmdW5jdGlvbiB0b25lcygpe2NvbnN0IHdoZW49MDtyZXR1cm4gd2hlbn0KYXN5bmMgZnVuY3Rpb24gaW5p',
  'dEF1ZGlvKCl7aWYoY3R4KXJldHVybjtjb25zdCBBQz13aW5kb3cuQXVkaW9Db250ZXh0fHx3aW5kb3cud2Via2l0QXVkaW9Db250',
  'ZXh0O2lmKCFBQyl7bGlzdGVuT25seT10cnVlO3RvYXN0KCdFc3RlIG5hdmVnYWRvciBubyBhZG1pdGUgYXVkaW8gd2ViJywxKTty',
  'ZXR1cm59CiBjdHg9bmV3IEFDKCk7dHJ5e2F3YWl0IGN0eC5yZXN1bWUoKX1jYXRjaChlKXt9CiBjb25zdCBocD1jdHguY3JlYXRl',
  'QmlxdWFkRmlsdGVyKCk7aHAudHlwZT0naGlnaHBhc3MnO2hwLmZyZXF1ZW5jeS52YWx1ZT0zNDA7Y29uc3QgbHA9Y3R4LmNyZWF0',
  'ZUJpcXVhZEZpbHRlcigpO2xwLnR5cGU9J2xvd3Bhc3MnO2xwLmZyZXF1ZW5jeS52YWx1ZT0zMTAwOwogY29uc3Qgc2g9Y3R4LmNy',
  'ZWF0ZVdhdmVTaGFwZXIoKSxjdj1uZXcgRmxvYXQzMkFycmF5KDI1Nik7Zm9yKGxldCBpPTA7aTwyNTY7aSsrKXtjb25zdCB4PWkv',
  'MTI3LjUtMTtjdltpXT1NYXRoLnRhbmgoeCoxLjgpL01hdGgudGFuaCgxLjgpfXNoLmN1cnZlPWN2OwogY29uc3QgY3A9Y3R4LmNy',
  'ZWF0ZUR5bmFtaWNzQ29tcHJlc3NvcigpO2lucD1jdHguY3JlYXRlR2FpbigpO3ZvbD1jdHguY3JlYXRlR2FpbigpO2FuYT1jdHgu',
  'Y3JlYXRlQW5hbHlzZXIoKTthbmEuZmZ0U2l6ZT0yNTY7CiBpbnAuY29ubmVjdChocCk7aHAuY29ubmVjdChscCk7bHAuY29ubmVj',
  'dChzaCk7c2guY29ubmVjdChjcCk7Y3AuY29ubmVjdCh2b2wpO3ZvbC5jb25uZWN0KGFuYSk7YW5hLmNvbm5lY3QoY3R4LmRlc3Rp',
  'bmF0aW9uKTtzZXRWb2woKTsKIG5vaXNlQnVmPWN0eC5jcmVhdGVCdWZmZXIoMSxjdHguc2FtcGxlUmF0ZSxjdHguc2FtcGxlUmF0',
  'ZSk7Y29uc3QgbmQ9bm9pc2VCdWYuZ2V0Q2hhbm5lbERhdGEoMCk7Zm9yKGxldCBpPTA7aTxuZC5sZW5ndGg7aSsrKW5kW2ldPU1h',
  'dGgucmFuZG9tKCkqMi0xOwogaWYod2luZG93LmlzU2VjdXJlQ29udGV4dCYmbmF2aWdhdG9yLm1lZGlhRGV2aWNlcyYmbmF2aWdh',
  'dG9yLm1lZGlhRGV2aWNlcy5nZXRVc2VyTWVkaWEpewogIHRyeXtjb25zdCBzPWF3YWl0IG5hdmlnYXRvci5tZWRpYURldmljZXMu',
  'Z2V0VXNlck1lZGlhKHthdWRpbzp7ZWNob0NhbmNlbGxhdGlvbjp0cnVlLG5vaXNlU3VwcHJlc3Npb246dHJ1ZSxhdXRvR2FpbkNv',
  'bnRyb2w6dHJ1ZX19KTttaWNUcmFjaz1zLmdldEF1ZGlvVHJhY2tzKClbMF07bWljVHJhY2suZW5hYmxlZD1mYWxzZTthd2FpdCBz',
  'ZXR1cE1pYyhzKX0KICBjYXRjaChlKXtsaXN0ZW5Pbmx5PXRydWU7dG9hc3QoJ1NpbiBtaWNyw7Nmb25vICgnKygoZSYmZS5uYW1l',
  'KXx8J2Vycm9yJykrJyk6IHNvbG8gcG9kcsOhIGVzY3VjaGFyJywxKX19CiBlbHNlIGxpc3Rlbk9ubHk9dHJ1ZX0KYXN5bmMgZnVu',
  'Y3Rpb24gc2V0dXBNaWMoc3RyZWFtKXtjb25zdCBzcmM9Y3R4LmNyZWF0ZU1lZGlhU3RyZWFtU291cmNlKHN0cmVhbSksbXV0ZT1j',
  'dHguY3JlYXRlR2FpbigpO211dGUuZ2Fpbi52YWx1ZT0wO211dGUuY29ubmVjdChjdHguZGVzdGluYXRpb24pO2xldCBvaz1mYWxz',
  'ZTsKIHRyeXtpZihjdHguYXVkaW9Xb3JrbGV0KXtjb25zdCBjb2RlPSJjbGFzcyBQIGV4dGVuZHMgQXVkaW9Xb3JrbGV0UHJvY2Vz',
  'c29ye3Byb2Nlc3MoaSl7Y29uc3QgYz1pWzBdWzBdO2lmKGMpdGhpcy5wb3J0LnBvc3RNZXNzYWdlKGMuc2xpY2UoKSk7cmV0dXJu',
  'IHRydWV9fXJlZ2lzdGVyUHJvY2Vzc29yKCdtaWMtcHJvYycsUCkiOwogICBhd2FpdCBjdHguYXVkaW9Xb3JrbGV0LmFkZE1vZHVs',
  'ZShVUkwuY3JlYXRlT2JqZWN0VVJMKG5ldyBCbG9iKFtjb2RlXSx7dHlwZTonYXBwbGljYXRpb24vamF2YXNjcmlwdCd9KSkpO2Nv',
  'bnN0IG49bmV3IEF1ZGlvV29ya2xldE5vZGUoY3R4LCdtaWMtcHJvYycpO24ucG9ydC5vbm1lc3NhZ2U9ZT0+b25NaWMoZS5kYXRh',
  'KTtzcmMuY29ubmVjdChuKTtuLmNvbm5lY3QobXV0ZSk7b2s9dHJ1ZX19Y2F0Y2goZSl7fQogaWYoIW9rKXtjb25zdCBzcD1jdHgu',
  'Y3JlYXRlU2NyaXB0UHJvY2Vzc29yKDIwNDgsMSwxKTtzcC5vbmF1ZGlvcHJvY2Vzcz1lPT5vbk1pYyhlLmlucHV0QnVmZmVyLmdl',
  'dENoYW5uZWxEYXRhKDApKTtzcmMuY29ubmVjdChzcCk7c3AuY29ubmVjdChtdXRlKX19CmZ1bmN0aW9uIG9uTWljKGYpe2lmKCF0',
  'eE9uJiYhcGVuZGluZylyZXR1cm47Y29uc3QgcmF0aW89Y3R4LnNhbXBsZVJhdGUvUkFURTtsZXQgZT0wOwogZm9yKGxldCBpPTA7',
  'aTxmLmxlbmd0aDtpKyspe2UrPWZbaV0qZltpXTtzdW0rPWZbaV07Y250Kys7cGgrPTE7CiAgaWYocGg+PXJhdGlvKXtwaC09cmF0',
  'aW87bGV0IHY9c3VtL2NudDtzdW09MDtjbnQ9MDt2PXY+MT8xOnY8LTE/LTE6djtmcltmaSsrXT12PDA/diozMjc2ODp2KjMyNzY3',
  'O2lmKGZpPT09RlIpe2VtaXQoZnIuc2xpY2UoKS5idWZmZXIpO2ZpPTB9fX0KIG1pY0xldmVsPU1hdGgubWF4KG1pY0xldmVsKi44',
  'LE1hdGguc3FydChlL2YubGVuZ3RoKSo0KX0KZnVuY3Rpb24gZW1pdChiKXtpZih0eE9uJiZ3cyYmd3MucmVhZHlTdGF0ZT09PTEp',
  'e3dzLnNlbmQoYik7c3QudHgrK31lbHNlIGlmKHBlbmRpbmcpe3F1ZXVlLnB1c2goYik7aWYocXVldWUubGVuZ3RoPjI1KXF1ZXVl',
  'LnNoaWZ0KCl9fQpmdW5jdGlvbiBzZXRWb2woKXtpZih2b2wpdm9sLmdhaW4udmFsdWU9KCQoJ3ZvbCcpLnZhbHVlLzEwMCkqMS41',
  'OyQoJ3ZvbFYnKS50ZXh0Q29udGVudD0kKCd2b2wnKS52YWx1ZSsnJSd9CmZ1bmN0aW9uIGJlZXAoZixkLHYsd2hlbix0eXBlKXtp',
  'ZighY3R4KXJldHVybjtjb25zdCB0PWN0eC5jdXJyZW50VGltZSsod2hlbnx8MCksbz1jdHguY3JlYXRlT3NjaWxsYXRvcigpLGc9',
  'Y3R4LmNyZWF0ZUdhaW4oKTtvLnR5cGU9dHlwZXx8J3NpbmUnO28uZnJlcXVlbmN5LnZhbHVlPWY7CiBnLmdhaW4uc2V0VmFsdWVB',
  'dFRpbWUoMCx0KTtnLmdhaW4ubGluZWFyUmFtcFRvVmFsdWVBdFRpbWUodix0Ky4wMSk7Zy5nYWluLnNldFZhbHVlQXRUaW1lKHYs',
  'dCtkLS4wMik7Zy5nYWluLmxpbmVhclJhbXBUb1ZhbHVlQXRUaW1lKDAsdCtkKTtvLmNvbm5lY3QoZyk7Zy5jb25uZWN0KHZvbCk7',
  'by5zdGFydCh0KTtvLnN0b3AodCtkKy4wMil9CmZ1bmN0aW9uIG5vaXNlKGQsdix3aGVuKXtpZighY3R4fHwhc3FsKXJldHVybjtj',
  'b25zdCB0PWN0eC5jdXJyZW50VGltZSsod2hlbnx8MCkscz1jdHguY3JlYXRlQnVmZmVyU291cmNlKCksYnA9Y3R4LmNyZWF0ZUJp',
  'cXVhZEZpbHRlcigpLGc9Y3R4LmNyZWF0ZUdhaW4oKTtzLmJ1ZmZlcj1ub2lzZUJ1ZjticC50eXBlPSdiYW5kcGFzcyc7YnAuZnJl',
  'cXVlbmN5LnZhbHVlPTIyMDA7YnAuUS52YWx1ZT0uNjsKIGcuZ2Fpbi5zZXRWYWx1ZUF0VGltZSh2LHQpO2cuZ2Fpbi5leHBvbmVu',
  'dGlhbFJhbXBUb1ZhbHVlQXRUaW1lKC4wMDEsdCtkKTtzLmNvbm5lY3QoYnApO2JwLmNvbm5lY3QoZyk7Zy5jb25uZWN0KHZvbCk7',
  'cy5zdGFydCh0KTtzLnN0b3AodCtkKy4wMil9CmNvbnN0IGJ1c3lUb25lPSgpPT57YmVlcCg0MjAsLjE0LC4yNSwwLCdzcXVhcmUn',
  'KTtiZWVwKDQyMCwuMTQsLjI1LC4yLCdzcXVhcmUnKX0sY2FsbFRvbmU9KCk9Pntmb3IobGV0IGk9MDtpPDM7aSsrKXtiZWVwKDEw',
  'MDAsLjEyLC4zLGkqLjMpO2JlZXAoMTQwMCwuMTIsLjMsaSouMysuMTQpfX07Ci8qID09PT09IHJlY2VwY2nDs24gZGUgYXVkaW8g',
  'PT09PT0gKi8KZnVuY3Rpb24gcGxheUNodW5rKGJ1Zil7aWYoIWN0eHx8KHRhbGtlciYmdGFsa2VyLmlkPT09bWUuaWQpfHxidWYu',
  'Ynl0ZUxlbmd0aDwyfHxidWYuYnl0ZUxlbmd0aCYxKXJldHVybjtjb25zdCBpMTY9bmV3IEludDE2QXJyYXkoYnVmKSxhYj1jdHgu',
  'Y3JlYXRlQnVmZmVyKDEsaTE2Lmxlbmd0aCxSQVRFKSxkPWFiLmdldENoYW5uZWxEYXRhKDApOwogZm9yKGxldCBpPTA7aTxpMTYu',
  'bGVuZ3RoO2krKylkW2ldPWkxNltpXS8zMjc2ODtjb25zdCBzPWN0eC5jcmVhdGVCdWZmZXJTb3VyY2UoKTtzLmJ1ZmZlcj1hYjtz',
  'LmNvbm5lY3QoaW5wKTtjb25zdCBub3c9Y3R4LmN1cnJlbnRUaW1lOwogaWYocGxheVQ8bm93Ky4wMnx8cGxheVQ+bm93Ky45KXBs',
  'YXlUPW5vdysuMTQ7cy5zdGFydChwbGF5VCk7cGxheVQrPWFiLmR1cmF0aW9uO3N0LnJ4Kyt9CmZ1bmN0aW9uIHJ4U3RhcnQoKXtw',
  'bGF5VD0wO3J4U2luY2U9RGF0ZS5ub3coKTtub2lzZSguMDksLjQ1KX0KZnVuY3Rpb24gcnhFbmQod2FzKXtjb25zdCBhdD1NYXRo',
  'Lm1heCgwLHBsYXlULWN0eC5jdXJyZW50VGltZSkrLjAzO2lmKHJvZ2VyKWJlZXAoMTUwMCwuMSwuMjIsYXQpO25vaXNlKC4yLC40',
  'LGF0Kyhyb2dlcj8uMTowKSk7bG9nKHdhcy5uYW1lKycgaGFibMOzICcrTWF0aC5tYXgoMSxNYXRoLnJvdW5kKChEYXRlLm5vdygp',
  'LXJ4U2luY2UpLzEwMDApKSsnIHMnKX0KLyogPT09PT0gUFRUID09PT09ICovCmZ1bmN0aW9uIHB0dFN0YXJ0KCl7aWYoIWpvaW5l',
  'ZHx8cHR0RG93bilyZXR1cm47cHR0RG93bj10cnVlOwogaWYobGlzdGVuT25seSl7dG9hc3QoJ1NpbiBtaWNyw7Nmb25vOiBzb2xv',
  'IHB1ZWRlIGVzY3VjaGFyJywxKTtyZXR1cm59CiBpZih0YWxrZXImJnRhbGtlci5pZCE9PW1lLmlkKXtidXN5VG9uZSgpO2xvZygn',
  'Q2FuYWwgb2N1cGFkbzogaGFibGEgJyt0YWxrZXIubmFtZSk7cmV0dXJufQogcGVuZGluZz10cnVlO3F1ZXVlPVtdO2ZpPTA7cGg9',
  'MDtzdW09MDtjbnQ9MDtpZihtaWNUcmFjayltaWNUcmFjay5lbmFibGVkPXRydWU7c2VuZCh7dDoncHR0J30pO3JlbmRlcigpfQpm',
  'dW5jdGlvbiBwdHRFbmQoKXtjb25zdCB3YXM9cGVuZGluZ3x8dHhPbjtwdHREb3duPWZhbHNlO2lmKCF3YXMpe3JlbmRlcigpO3Jl',
  'dHVybn1zZW5kKHt0OidyZWwnfSk7cGVuZGluZz1mYWxzZTt0eE9uPWZhbHNlO3F1ZXVlPVtdO2ZpPTA7aWYobWljVHJhY2spbWlj',
  'VHJhY2suZW5hYmxlZD1mYWxzZTtiZWVwKDcwMCwuMDQsLjE1KTtyZW5kZXIoKX0KZnVuY3Rpb24gZ3JhbnQoKXtpZighcGVuZGlu',
  'ZylyZXR1cm47cGVuZGluZz1mYWxzZTt0eE9uPXRydWU7Zm9yKGNvbnN0IGIgb2YgcXVldWUpe2lmKHdzLnJlYWR5U3RhdGU9PT0x',
  'KXt3cy5zZW5kKGIpO3N0LnR4Kyt9fXF1ZXVlPVtdO2lmKHJvZ2VyKWJlZXAoOTAwLC4wNSwuMTgpO3JlbmRlcigpfQpjb25zdCBw',
  'dHQ9JCgncHR0Jyk7CnB0dC5hZGRFdmVudExpc3RlbmVyKCdwb2ludGVyZG93bicsZT0+e2UucHJldmVudERlZmF1bHQoKTtwdHQu',
  'c2V0UG9pbnRlckNhcHR1cmUoZS5wb2ludGVySWQpO2lmKGxhdGNoKXtpZihwZW5kaW5nfHx0eE9ufHxwdHREb3duKXB0dEVuZCgp',
  'O2Vsc2UgcHR0U3RhcnQoKX1lbHNlIHB0dFN0YXJ0KCl9KTsKY29uc3QgdXA9KCk9PntpZighbGF0Y2gpcHR0RW5kKCl9O3B0dC5h',
  'ZGRFdmVudExpc3RlbmVyKCdwb2ludGVydXAnLHVwKTtwdHQuYWRkRXZlbnRMaXN0ZW5lcigncG9pbnRlcmNhbmNlbCcsdXApO3B0',
  'dC5hZGRFdmVudExpc3RlbmVyKCdjb250ZXh0bWVudScsZT0+ZS5wcmV2ZW50RGVmYXVsdCgpKTsKZG9jdW1lbnQuYWRkRXZlbnRM',
  'aXN0ZW5lcigna2V5ZG93bicsZT0+e2lmKGUuY29kZSE9PSdTcGFjZSd8fGUucmVwZWF0fHwham9pbmVkfHwvSU5QVVR8U0VMRUNU',
  'fFRFWFRBUkVBLy50ZXN0KGUudGFyZ2V0LnRhZ05hbWUpKXJldHVybjtlLnByZXZlbnREZWZhdWx0KCk7aWYobGF0Y2gpe2lmKHBl',
  'bmRpbmd8fHR4T24pcHR0RW5kKCk7ZWxzZSBwdHRTdGFydCgpfWVsc2UgcHR0U3RhcnQoKX0pOwpkb2N1bWVudC5hZGRFdmVudExp',
  'c3RlbmVyKCdrZXl1cCcsZT0+e2lmKGUuY29kZT09PSdTcGFjZScmJmpvaW5lZCYmIWxhdGNoJiYhL0lOUFVUfFNFTEVDVHxURVhU',
  'QVJFQS8udGVzdChlLnRhcmdldC50YWdOYW1lKSlwdHRFbmQoKX0pOwp3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignYmx1cicsKCk9',
  'PntpZighbGF0Y2gpcHR0RW5kKCl9KTsKLyogPT09PT0gcmVkID09PT09ICovCmZ1bmN0aW9uIGNvbm5lY3QoKXtjbGVhclRpbWVv',
  'dXQocmVjb25uVCk7d3M9bmV3IFdlYlNvY2tldCgobG9jYXRpb24ucHJvdG9jb2w9PT0naHR0cHM6Jz8nd3NzOic6J3dzOicpKycv',
  'LycrbG9jYXRpb24uaG9zdCk7d3MuYmluYXJ5VHlwZT0nYXJyYXlidWZmZXInO3NldENvbm4oJycsJ2NvbmVjdGFuZG/igKYnKTsK',
  'IHdzLm9ub3Blbj0oKT0+e3JldHJ5PTEwMDA7c2V0Q29ubignb2snLCdjb25lY3RhZG8nKTtpZih3YW50Sm9pbilzZW5kKHt0Oidq',
  'b2luJyxuYW1lOndhbnRKb2luLm5hbWUsY29kZTp3YW50Sm9pbi5jb2RlLGNoOm1lLmNofSl9Owogd3Mub25tZXNzYWdlPW9uTXNn',
  'Owogd3Mub25jbG9zZT0oKT0+e3NldENvbm4oJ2JhZCcsd2FudEpvaW4/J3JlY29uZWN0YW5kb+KApic6J3NpbiBjb25leGnDs24n',
  'KTtwZW5kaW5nPWZhbHNlO3R4T249ZmFsc2U7aWYobWljVHJhY2spbWljVHJhY2suZW5hYmxlZD1mYWxzZTt0YWxrZXI9bnVsbDtp',
  'Zih3YW50Sm9pbil7cmVjb25uVD1zZXRUaW1lb3V0KGNvbm5lY3QscmV0cnkpO3JldHJ5PU1hdGgubWluKHJldHJ5KjEuNyw4MDAw',
  'KX1yZW5kZXIoKX07CiB3cy5vbmVycm9yPSgpPT57fX0KZnVuY3Rpb24gb25Nc2coZSl7aWYoZS5kYXRhIGluc3RhbmNlb2YgQXJy',
  'YXlCdWZmZXIpe3BsYXlDaHVuayhlLmRhdGEpO3JldHVybn1sZXQgbzt0cnl7bz1KU09OLnBhcnNlKGUuZGF0YSl9Y2F0Y2goXyl7',
  'cmV0dXJufQogc3dpdGNoKG8udCl7CiAgY2FzZSAnd2VsY29tZSc6am9pbmVkPXRydWU7bWU9e2lkOm8uaWQsbmFtZTpvLm5hbWUs',
  'Y2g6by5jaH07dXNlcnM9by51c2Vyczt0YWxrZXI9by50YWxrZXI7c3RvcmUoJ3drX2NoJyxvLmNoKTskKCdsb2dpbicpLmhpZGRl',
  'bj10cnVlOyQoJ2FwcCcpLmhpZGRlbj1mYWxzZTtsb2coJ0NhbmFsICcrU3RyaW5nKG8uY2gpLnBhZFN0YXJ0KDIsJzAnKSsnIMK3',
  'ICcrdXNlcnMubGVuZ3RoKycgdXN1YXJpbyhzKScpO3JlbmRlcigpO2JyZWFrOwogIGNhc2UgJ3VzZXJzJzp7Y29uc3QgcHJldj1u',
  'ZXcgU2V0KHVzZXJzLm1hcCh1PT51LmlkKSk7Zm9yKGNvbnN0IHUgb2Ygby51c2VycylpZighcHJldi5oYXModS5pZCkmJnUuaWQh',
  'PT1tZS5pZClsb2codS5uYW1lKycgZW50csOzJyk7Y29uc3Qgbm93PW5ldyBTZXQoby51c2Vycy5tYXAodT0+dS5pZCkpO2Zvcihj',
  'b25zdCB1IG9mIHVzZXJzKWlmKCFub3cuaGFzKHUuaWQpKWxvZyh1Lm5hbWUrJyBzYWxpw7MnKTt1c2Vycz1vLnVzZXJzO3JlbmRl',
  'cigpO2JyZWFrfQogIGNhc2UgJ3R4Jzp0YWxrZXI9e2lkOm8uaWQsbmFtZTpvLm5hbWV9O2lmKG8uaWQ9PT1tZS5pZClncmFudCgp',
  'O2Vsc2UgcnhTdGFydCgpO3JlbmRlcigpO2JyZWFrOwogIGNhc2UgJ3R4ZW5kJzppZih0YWxrZXImJnRhbGtlci5pZD09PW8uaWQp',
  'e2NvbnN0IHdhcz10YWxrZXI7dGFsa2VyPW51bGw7aWYod2FzLmlkIT09bWUuaWQpcnhFbmQod2FzKX1yZW5kZXIoKTticmVhazsK',
  'ICBjYXNlICdidXN5JzpwZW5kaW5nPWZhbHNlO3R4T249ZmFsc2U7aWYobWljVHJhY2spbWljVHJhY2suZW5hYmxlZD1mYWxzZTti',
  'dXN5VG9uZSgpO2xvZygnQ2FuYWwgb2N1cGFkbzogaGFibGEgJytvLm5hbWUpO3JlbmRlcigpO2JyZWFrOwogIGNhc2UgJ3RvdCc6',
  'dG9hc3QoJ1RpZW1wbyBtw6F4aW1vIGRlIHRyYW5zbWlzacOzbiAoNDUgcykuIFN1ZWx0ZSB5IHZ1ZWx2YSBhIHB1bHNhci4nLDEp',
  'O3BlbmRpbmc9ZmFsc2U7dHhPbj1mYWxzZTtpZihtaWNUcmFjayltaWNUcmFjay5lbmFibGVkPWZhbHNlO3JlbmRlcigpO2JyZWFr',
  'OwogIGNhc2UgJ2NhbGwnOmNhbGxUb25lKCk7bG9nKCdMbGFtYWRhIGRlICcrby5uYW1lKTt0b2FzdCgnTGxhbWFkYSBkZSAnK28u',
  'bmFtZSk7YnJlYWs7CiAgY2FzZSAnZXJyb3InOnRvYXN0KG8ubXNnLDEpO2lmKCFqb2luZWQpe3dhbnRKb2luPW51bGx9YnJlYWt9',
  'fQovKiA9PT09PSBpbnRlcmZheiA9PT09PSAqLwpmdW5jdGlvbiByZW5kZXIoKXtjb25zdCBtaW5lPXRhbGtlciYmdGFsa2VyLmlk',
  'PT09bWUuaWQsb3RoZXI9dGFsa2VyJiYhbWluZTsKICQoJ2xjZENoJykudGV4dENvbnRlbnQ9J0NIICcrU3RyaW5nKG1lLmNoKS5w',
  'YWRTdGFydCgyLCcwJyk7JCgnbGNkVXNlcnMnKS50ZXh0Q29udGVudD11c2Vycy5sZW5ndGgrKHVzZXJzLmxlbmd0aD09PTE/JyB1',
  'c3VhcmlvJzonIHVzdWFyaW9zJyk7JCgnbGNkTWUnKS50ZXh0Q29udGVudD1tZS5uYW1lPydVc3RlZDogJyttZS5uYW1lOicnOwog',
  'JCgnbGNkU3QnKS50ZXh0Q29udGVudD1wZW5kaW5nPydTT0xJQ0lUQU5ET+KApic6bWluZXx8dHhPbj8nVFJBTlNNSVRJRU5ETyc6',
  'b3RoZXI/J1JYIMK3ICcrdGFsa2VyLm5hbWU6d3MmJndzLnJlYWR5U3RhdGU9PT0xPydMSUJSRSc6J1NJTiBDT05FWEnDk04nOwog',
  'JCgnbGVkUngnKS5jbGFzc0xpc3QudG9nZ2xlKCdvbicsISFvdGhlcik7JCgnbGVkVHgnKS5jbGFzc0xpc3QudG9nZ2xlKCdvbics',
  'dHhPbnx8cGVuZGluZyk7JCgnbGVkQnonKS5jbGFzc0xpc3QudG9nZ2xlKCdvbicsISFvdGhlcik7CiBwdHQuY2xhc3NMaXN0LnRv',
  'Z2dsZSgnZG93bicsdHhPbnx8cGVuZGluZyk7cHR0LnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVzc2VkJyxTdHJpbmcodHhPbnx8cGVu',
  'ZGluZykpOwogcHR0LmZpcnN0Q2hpbGQudGV4dENvbnRlbnQ9dHhPbnx8cGVuZGluZz8nSEFCTEFORE/igKYnOm90aGVyPydDQU5B',
  'TCBPQ1VQQURPJzonUFVMU0FSIFBBUkEgSEFCTEFSJzsKIGNvbnN0IHVsPSQoJ3VzZXJzJyk7dWwudGV4dENvbnRlbnQ9Jyc7Zm9y',
  'KGNvbnN0IHUgb2YgdXNlcnMpe2NvbnN0IGxpPWRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2xpJyksZD1kb2N1bWVudC5jcmVhdGVF',
  'bGVtZW50KCdzcGFuJyksbj1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdzcGFuJyksdD1kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdz',
  'cGFuJyk7ZC5jbGFzc05hbWU9J2RvdCc7bi50ZXh0Q29udGVudD11Lm5hbWU7dC5jbGFzc05hbWU9J3RhZyc7CiAgdC50ZXh0Q29u',
  'dGVudD10YWxrZXImJnUuaWQ9PT10YWxrZXIuaWQ/J0hBQkxBTkRPJzp1LmlkPT09bWUuaWQ/J1TDmic6Jyc7bGkuY2xhc3NOYW1l',
  'PSh0YWxrZXImJnUuaWQ9PT10YWxrZXIuaWQ/J3RhbGsgJzonJykrKHUuaWQ9PT1tZS5pZD8nbWUnOicnKTtsaS5hcHBlbmQoZCxu',
  'LHQpO3VsLmFwcGVuZENoaWxkKGxpKX19CmZ1bmN0aW9uIHRvZ2dsZShpZCxnZXQsc2V0KXtjb25zdCBiPSQoaWQpO2Iub25jbGlj',
  'az0oKT0+e3NldCghZ2V0KCkpO2IuY2xhc3NMaXN0LnRvZ2dsZSgnb24nLGdldCgpKTtiLnNldEF0dHJpYnV0ZSgnYXJpYS1wcmVz',
  'c2VkJyxTdHJpbmcoZ2V0KCkpKX19CnRvZ2dsZSgndGdSb2dlcicsKCk9PnJvZ2VyLHY9Pntyb2dlcj12fSk7dG9nZ2xlKCd0Z1Nx',
  'bCcsKCk9PnNxbCx2PT57c3FsPXZ9KTt0b2dnbGUoJ3RnTGF0Y2gnLCgpPT5sYXRjaCx2PT57aWYoIXYmJih0eE9ufHxwZW5kaW5n',
  'KSlwdHRFbmQoKTtsYXRjaD12O3RvYXN0KHY/J01vZG8gZmlqbzogcHVsc2UgdW5hIHZleiBwYXJhIGhhYmxhciB5IG90cmEgcGFy',
  'YSBzb2x0YXInOidNb2RvIG5vcm1hbDogbWFudGVuZ2EgcHVsc2FkbycpfSk7CiQoJ3ZvbCcpLm9uaW5wdXQ9c2V0Vm9sOwpmdW5j',
  'dGlvbiBjaGFuZ2VDaChkKXtpZigham9pbmVkKXJldHVybjtpZih0eE9ufHxwZW5kaW5nKXB0dEVuZCgpO2NvbnN0IG49KChtZS5j',
  'aC0xK2QrMTYpJTE2KSsxO3NlbmQoe3Q6J2NoJyxjaDpufSl9CiQoJ2NoVXAnKS5vbmNsaWNrPSgpPT5jaGFuZ2VDaCgxKTskKCdj',
  'aERuJykub25jbGljaz0oKT0+Y2hhbmdlQ2goLTEpOwokKCdjYWxsQnRuJykub25jbGljaz0oKT0+e2lmKCFqb2luZWQpcmV0dXJu',
  'O3NlbmQoe3Q6J2NhbGwnfSk7YmVlcCgxMDAwLC4xMiwuMjUpO3RvYXN0KCdMbGFtYWRhIGVudmlhZGEgYWwgY2FuYWwnKX07CiQo',
  'J2NvcHknKS5vbmNsaWNrPWFzeW5jKCk9Pnt0cnl7YXdhaXQgbmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQoJCgnc2hhcmVV',
  'cmwnKS52YWx1ZSk7dG9hc3QoJ0RpcmVjY2nDs24gY29waWFkYScpfWNhdGNoKGUpeyQoJ3NoYXJlVXJsJykuc2VsZWN0KCk7dG9h',
  'c3QoJ1NlbGVjY2lvbmUgeSBjb3BpZSBsYSBkaXJlY2Npw7NuJyl9fTsKJCgnbGVhdmUnKS5vbmNsaWNrPSgpPT57d2FudEpvaW49',
  'bnVsbDtqb2luZWQ9ZmFsc2U7aWYodHhPbnx8cGVuZGluZylwdHRFbmQoKTtpZih3cyl3cy5jbG9zZSgpO3VzZXJzPVtdO3RhbGtl',
  'cj1udWxsOyQoJ2FwcCcpLmhpZGRlbj10cnVlOyQoJ2xvZ2luJykuaGlkZGVuPWZhbHNlO3NldENvbm4oJycsJ3NpbiBjb25leGnD',
  's24nKX07CiQoJ2pvaW4nKS5vbmNsaWNrPWFzeW5jKCk9Pntjb25zdCBuYW1lPSQoJ25hbWUnKS52YWx1ZS50cmltKCk7aWYoIW5h',
  'bWUpe3RvYXN0KCdFc2NyaWJhIHVuIG5vbWJyZScsMSk7JCgnbmFtZScpLmZvY3VzKCk7cmV0dXJufQogJCgnam9pbicpLmRpc2Fi',
  'bGVkPXRydWU7dHJ5e2F3YWl0IGluaXRBdWRpbygpfWZpbmFsbHl7JCgnam9pbicpLmRpc2FibGVkPWZhbHNlfQogc3RvcmUoJ3dr',
  'X25hbWUnLG5hbWUpO3N0b3JlKCd3a19jaCcsc2VsLnZhbHVlKTttZS5jaD1wYXJzZUludChzZWwudmFsdWUsMTApO3dhbnRKb2lu',
  'PXtuYW1lLGNvZGU6JCgnY29kZScpLnZhbHVlfTtjb25uZWN0KCl9OwokKCduYW1lJykuYWRkRXZlbnRMaXN0ZW5lcigna2V5ZG93',
  'bicsZT0+e2lmKGUua2V5PT09J0VudGVyJykkKCdqb2luJykuY2xpY2soKX0pOwovKiBtZWRpZG9yICovCmNvbnN0IG1jPSQoJ21l',
  'dGVyJyksbXg9bWMuZ2V0Q29udGV4dCgnMmQnKSxidWY9bmV3IFVpbnQ4QXJyYXkoMTI4KTsKZnVuY3Rpb24gZHJhdygpe2NvbnN0',
  'IHc9bWMuY2xpZW50V2lkdGgsaD1tYy5jbGllbnRIZWlnaHQsZD13aW5kb3cuZGV2aWNlUGl4ZWxSYXRpb3x8MTtpZihtYy53aWR0',
  'aCE9PU1hdGgucm91bmQodypkKSl7bWMud2lkdGg9TWF0aC5yb3VuZCh3KmQpO21jLmhlaWdodD1NYXRoLnJvdW5kKGgqZCl9CiBt',
  'eC5zZXRUcmFuc2Zvcm0oZCwwLDAsZCwwLDApO214LmNsZWFyUmVjdCgwLDAsdyxoKTtsZXQgbHY9MDsKIGlmKHRhbGtlciYmKCF0',
  'eE9uKSYmYW5hJiZ0YWxrZXIuaWQhPT1tZS5pZCl7YW5hLmdldEJ5dGVUaW1lRG9tYWluRGF0YShidWYpO2xldCBlPTA7Zm9yKGxl',
  'dCBpPTA7aTwxMjg7aSsrKXtjb25zdCB2PShidWZbaV0tMTI4KS8xMjg7ZSs9dip2fWx2PU1hdGgubWluKDEsTWF0aC5zcXJ0KGUv',
  'MTI4KSo1KX0KIGVsc2UgaWYodHhPbil7bHY9TWF0aC5taW4oMSxtaWNMZXZlbCk7bWljTGV2ZWwqPS45fQogY29uc3Qgbj0yNCxi',
  'dz13L247Zm9yKGxldCBpPTA7aTxuO2krKyl7Y29uc3Qgb249aS9uPGx2O214Lmdsb2JhbEFscGhhPW9uPzE6LjE1O214LmZpbGxT',
  'dHlsZT1pPm4qLjg/JyNmZjdhNWMnOicjYjhmMmEwJztteC5maWxsUmVjdChpKmJ3KzEsMyxidy0yLGgtNil9bXguZ2xvYmFsQWxw',
  'aGE9MTtyZXF1ZXN0QW5pbWF0aW9uRnJhbWUoZHJhdyl9CnJlcXVlc3RBbmltYXRpb25GcmFtZShkcmF3KTtyZW5kZXIoKTsKfSko',
  'KTsKPC9zY3JpcHQ+CjwvYm9keT4KPC9odG1sPgo='
].join('');
function loadPage(cb) {
  // 1) index.html junto a server.js, 2) en la carpeta actual, 3) copia incrustada
  const tryFiles = [path.join(dir, 'index.html'), path.join(process.cwd(), 'index.html')];
  (function next(i) {
    if (i >= tryFiles.length) return cb(Buffer.from(EMBEDDED_HTML_B64, 'base64'));
    fs.readFile(tryFiles[i], (err, data) => err ? next(i + 1) : cb(data));
  })(0);
}
function handler(req, res) {
  const url = (req.url || '/').split('?')[0];
  if (url === '/' || url === '/index.html') {
    loadPage(data => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
      res.end(data);
    });
  } else if (url === '/info') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ code: !!CODE, maxCh: MAX_CH }));
  } else { res.writeHead(404); res.end('No encontrado'); }
}
const server = tlsOpts ? https.createServer(tlsOpts, handler) : http.createServer(handler);
/* Un solo puerto para HTTPS y HTTP: si alguien escribe http:// se le redirige a https:// */
const redirect = http.createServer((req, res) => { const h = (req.headers.host || 'localhost').replace(/:\d+$/, ''); res.writeHead(301, { Location: 'https://' + h + ':' + PORT + (req.url || '/') }); res.end(); });
const front = tlsOpts ? net.createServer(sock => { sock.on('error', () => {}); sock.once('data', b => { sock.pause(); sock.unshift(b); (b[0] === 0x16 ? server : redirect).emit('connection', sock); process.nextTick(() => sock.resume()); }); }) : server;

/* ===== WebSocket mínimo (RFC 6455) ===== */
function wsFrame(op, payload) {
  const n = payload.length; let h;
  if (n < 126) h = Buffer.from([0x80 | op, n]);
  else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeUInt32BE(0, 2); h.writeUInt32BE(n, 6); }
  return Buffer.concat([h, payload]);
}
const channels = new Map(); // n -> { users:Set, talker:Client|null, timer }
let nextId = 1;
function chan(n) { if (!channels.has(n)) channels.set(n, { users: new Set(), talker: null, timer: null }); return channels.get(n); }

class Client {
  constructor(socket) {
    this.s = socket; this.buf = Buffer.alloc(0); this.id = nextId++; this.name = ''; this.ch = 0; this.alive = true;
    this.frag = []; this.fragOp = 0; this.msgs = 0; this.t0 = Date.now();
    socket.on('data', d => this.onData(d));
    socket.on('close', () => this.close()); socket.on('error', () => this.close());
  }
  send(o) { if (!this.s.destroyed) this.s.write(wsFrame(1, Buffer.from(JSON.stringify(o)))); }
  sendBin(b) { if (!this.s.destroyed && this.s.writableLength < 256 * 1024) this.s.write(wsFrame(2, b)); }
  onData(d) {
    this.buf = Buffer.concat([this.buf, d]);
    while (this.buf.length >= 2) {
      const b0 = this.buf[0], b1 = this.buf[1], fin = !!(b0 & 0x80), op = b0 & 15, masked = !!(b1 & 0x80);
      let len = b1 & 127, off = 2;
      if (!masked) return this.kill(1002);
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; const hi = this.buf.readUInt32BE(2), lo = this.buf.readUInt32BE(6); if (hi > 0 || lo > MAX_PAYLOAD) return this.kill(1009); len = lo; off = 10; }
      if (len > MAX_PAYLOAD) return this.kill(1009);
      if (this.buf.length < off + 4 + len) return;
      const mask = this.buf.subarray(off, off + 4), p = Buffer.from(this.buf.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < p.length; i++) p[i] ^= mask[i & 3];
      this.buf = this.buf.subarray(off + 4 + len);
      if (op === 8) return this.kill(1000);
      if (op === 9) { this.s.write(wsFrame(10, p)); continue; }
      if (op === 10) { this.alive = true; continue; }
      if (op === 1 || op === 2) { this.fragOp = op; this.frag = [p]; } else if (op === 0) this.frag.push(p); else return this.kill(1002);
      if (fin) { const m = Buffer.concat(this.frag); this.frag = []; this.onMessage(this.fragOp, m); }
    }
  }
  kill(code) { try { const b = Buffer.alloc(2); b.writeUInt16BE(code); this.s.write(wsFrame(8, b)); this.s.end(); } catch (e) {} this.close(); }
  onMessage(op, m) {
    if (op === 2) { // audio del que tiene el turno
      const c = channels.get(this.ch);
      if (c && c.talker === this && m.length <= 4096) for (const u of c.users) if (u !== this) u.sendBin(m);
      return;
    }
    let o; try { o = JSON.parse(m.toString('utf8')); } catch (e) { return; }
    if (!o || typeof o.t !== 'string') return;
    if (++this.msgs > 200 && Date.now() - this.t0 < 10000) return this.kill(1008);
    switch (o.t) {
      case 'join': return this.join(o);
      case 'ch': return this.ch ? this.switchCh(o.ch) : null;
      case 'ptt': return this.ptt();
      case 'rel': return this.release();
      case 'call': { const c = channels.get(this.ch); if (c) for (const u of c.users) if (u !== this) u.send({ t: 'call', name: this.name }); return; }
    }
  }
  join(o) {
    if (this.ch) return;
    if (CODE && o.code !== CODE) { this.send({ t: 'error', msg: 'Código de sala incorrecto' }); return this.kill(1008); }
    const name = String(o.name || '').replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, 16);
    if (!name) { this.send({ t: 'error', msg: 'Indique un nombre' }); return; }
    this.name = name; this.switchCh(o.ch);
  }
  switchCh(n) {
    n = parseInt(n, 10); if (!(n >= 1 && n <= MAX_CH)) return this.send({ t: 'error', msg: 'Canal no válido (1-' + MAX_CH + ')' });
    const dst = chan(n); if (dst.users.size >= MAX_USERS && this.ch !== n) return this.send({ t: 'error', msg: 'Canal lleno' });
    this.leave(); this.ch = n; dst.users.add(this);
    this.send({ t: 'welcome', id: this.id, ch: n, name: this.name, users: roster(dst), talker: dst.talker ? { id: dst.talker.id, name: dst.talker.name } : null });
    broadcastUsers(dst);
  }
  leave() {
    const c = channels.get(this.ch); if (!c) return;
    if (c.talker === this) this.release();
    c.users.delete(this); broadcastUsers(c); if (!c.users.size) channels.delete(this.ch);
    this.ch = 0;
  }
  ptt() {
    const c = channels.get(this.ch); if (!c) return;
    if (c.talker && c.talker !== this) return this.send({ t: 'busy', name: c.talker.name });
    if (c.talker === this) return;
    c.talker = this; for (const u of c.users) u.send({ t: 'tx', id: this.id, name: this.name });
    clearTimeout(c.timer);
    c.timer = setTimeout(() => { if (c.talker) { const t = c.talker; t.send({ t: 'tot' }); t.release(); } }, TOT_MS);
  }
  release() {
    const c = channels.get(this.ch); if (!c || c.talker !== this) return;
    clearTimeout(c.timer); c.talker = null; for (const u of c.users) u.send({ t: 'txend', id: this.id });
  }
  close() { if (this.closed) return; this.closed = true; this.leave(); try { this.s.destroy(); } catch (e) {} clients.delete(this); }
}
const clients = new Set();
const roster = c => [...c.users].map(u => ({ id: u.id, name: u.name, talking: c.talker === u }));
function broadcastUsers(c) { const r = roster(c); for (const u of c.users) u.send({ t: 'users', users: r }); }

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if ((req.headers.upgrade || '').toLowerCase() !== 'websocket' || !key || clients.size >= 500) return socket.destroy();
  const acc = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  socket.setNoDelay(true); clients.add(new Client(socket));
});
setInterval(() => { for (const c of clients) { if (!c.alive) { c.kill(1001); continue; } c.alive = false; try { c.s.write(wsFrame(9, Buffer.alloc(0))); } catch (e) {} } }, 25000).unref();

front.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error('\n  El puerto ' + PORT + ' ya esta en uso. Pruebe otro:  PORT=9000 node server.js\n');
  else if (e.code === 'EACCES') console.error('\n  Sin permiso para usar el puerto ' + PORT + '. Use un puerto superior a 1024.\n');
  else console.error('\n  Error del servidor: ' + e.message + '\n');
  process.exit(1);
});
front.listen(PORT, '0.0.0.0', () => {
  const proto = tlsOpts ? 'https' : 'http';
  console.log('\n  WALKIE-TALKIE · servidor activo (' + proto.toUpperCase() + ', puerto ' + PORT + ')\n');
  console.log('  En este equipo:   ' + proto + '://localhost:' + PORT);
  for (const ip of lanIPs()) console.log('  Para la red local: ' + proto + '://' + ip + ':' + PORT);
  if (CODE) console.log('\n  Código de sala exigido: ' + CODE);
  if (tlsOpts) console.log('\n  Certificado autofirmado: el navegador avisará la primera vez; acepte la excepción (necesario para usar el micrófono en la red).');
  else console.log('\n  AVISO: sin HTTPS (HTTP=1 o fallo al crear el certificado). Abra las direcciones http:// de arriba; el micrófono solo funcionará en localhost.');
  console.log('  Pulse Ctrl+C para detenerlo.\n');
});
