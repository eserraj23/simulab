#!/usr/bin/env node
/* Servidor del simulador de walkie-talkie. Sin dependencias: solo Node.js 16 o superior.
   Uso:  node server.js            (HTTPS con certificado autofirmado, sin openssl)
         HTTP=1 node server.js     (fuerza HTTP; el micrófono solo funcionará en localhost)
         PORT=9000 node server.js  (otro puerto)
         CODE=1234 node server.js  (exige un código de sala para entrar)           */
'use strict';
const fs = require('fs'), path = require('path'), os = require('os'), http = require('http'), https = require('https');
const crypto = require('crypto'), net = require('net');

const FORCE_HTTP = process.env.HTTP === '1';
const CODE = (process.env.CODE || '').slice(0, 32);
const MAX_CH = 16, MAX_USERS = 32, TOT_MS = 45000, MAX_PAYLOAD = 64 * 1024;
const dir = __dirname, certDir = path.join(dir, 'certs');
let tlsOpts = null;

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
  const sig = crypto.sign('sha256', tbs, privateKey), cert = der(0x30, tbs, alg, der(3, Buffer.concat([Buffer.from([0]), sig])));
  const pem = cert.toString('base64').match(/.{1,64}/g).join('\n');
  return { key: privateKey.export({ type: 'pkcs8', format: 'pem' }), cert: '-----BEGIN CERTIFICATE-----\n' + pem + '\n-----END CERTIFICATE-----\n' };
}
function ensureCert() {
  const ips = Object.values(os.networkInterfaces()).flat().filter(i => i && i.family === 'IPv4' && !i.internal).map(i => i.address).sort();
  const key = path.join(certDir, 'key.pem'), crt = path.join(certDir, 'cert.pem'), tag = path.join(certDir, 'ips.txt');
  try {
    if (!(fs.existsSync(key) && fs.existsSync(crt) && fs.existsSync(tag) && fs.readFileSync(tag, 'utf8') === ips.join(','))) {
      const c = makeCert(ips); fs.mkdirSync(certDir, { recursive: true });
      fs.writeFileSync(key, c.key, { mode: 0o600 }); fs.writeFileSync(crt, c.cert); fs.writeFileSync(tag, ips.join(','));
    }
    return { key: fs.readFileSync(key), cert: fs.readFileSync(crt) };
  } catch (e) { try { const c = makeCert(ips); return { key: c.key, cert: c.cert }; } catch (e2) { console.error('No se pudo crear el certificado:', e2.message); return null; } }
}
if (!FORCE_HTTP) tlsOpts = ensureCert();
const PORT = parseInt(process.env.PORT, 10) || (tlsOpts ? 8443 : 8080);

function handler(req, res) {
  const url = (req.url || '/').split('?')[0];
  if (url === '/' || url === '/index.html') {
    fs.readFile(path.join(dir, 'index.html'), (err, data) => {
      if (err) { res.writeHead(500); return res.end('No se encuentra index.html junto a server.js'); }
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
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
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
      else if (len === 127) { if (this.buf.length < 10) return; const big = this.buf.readBigUInt64BE(2); if (big > BigInt(MAX_PAYLOAD)) return this.kill(1009); len = Number(big); off = 10; }
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

front.listen(PORT, '0.0.0.0', () => {
  const proto = tlsOpts ? 'https' : 'http';
  console.log('\n  WALKIE-TALKIE · servidor activo (' + proto.toUpperCase() + ', puerto ' + PORT + ')\n');
  console.log('  En este equipo:   ' + proto + '://localhost:' + PORT);
  for (const list of Object.values(os.networkInterfaces())) for (const i of list || []) if (i.family === 'IPv4' && !i.internal) console.log('  Para la red local: ' + proto + '://' + i.address + ':' + PORT);
  if (CODE) console.log('\n  Código de sala exigido: ' + CODE);
  if (tlsOpts) console.log('\n  Certificado autofirmado: el navegador avisará la primera vez; acepte la excepción (necesario para usar el micrófono en la red).');
  else console.log('\n  AVISO: sin HTTPS (HTTP=1 o fallo al crear el certificado). Abra las direcciones http:// de arriba; el micrófono solo funcionará en localhost.');
  console.log('  Pulse Ctrl+C para detenerlo.\n');
});
