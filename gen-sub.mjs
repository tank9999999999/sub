// gen-sub.mjs — 生成可托管的 v2rayN 订阅文件 (Node 18+)
// 用法: node gen-sub.mjs
//
// 产物:
//   sub.txt    -> Base64 订阅内容 (上传到对象存储/COS 设公开读, v2rayNG 订阅 URL 指向它)
//   links.txt  -> 明文分享链接 (一行一条, 用于手动导入/排查)

import crypto from 'crypto';
import { writeFileSync } from 'fs';

const API = 'https://appamfusion.azurewebsites.net/api/data';
const SEED = Buffer.from('7b48b0ed8b051f290123e27815e8b110', 'hex');
// APK signing certificate SHA-256 (atom-fusion / amf.apk)
const CERT_HASH = Buffer.from(
  '62112ed134d52cec16705abfa40a44c3d4d744240360c976d6b2db3638048da8',
  'hex'
);
const TYPE = 1;

// v2rayN FmtHandler share schemes (ServiceLib)
const SHARE_RE =
  /^(?:hy2|hysteria2|ss|ssr|vmess|vless|trojan|tuic|wireguard|anytls|hysteria|juicity|brook|socks|http|https):\/\//i;

async function deriveKey() {
  const ikm = await crypto.subtle.importKey('raw', SEED, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: CERT_HASH, info: new Uint8Array([TYPE]) },
    ikm,
    128
  );
  return Buffer.from(bits);
}

async function decryptPayload(b64) {
  const blob = Buffer.from(String(b64).trim(), 'base64');
  if (blob.length < 28) throw new Error(`payload too short: ${blob.length}`);
  const nonce = blob.subarray(0, 12);
  const data = blob.subarray(12);
  const key = await deriveKey();
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, cryptoKey, data);
  return Buffer.from(pt).toString('utf8');
}

/** Extract share links; v2rayN subscription = links joined by \n then Base64. */
function toV2rayNSubscription(plain) {
  const links = plain
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter((s) => SHARE_RE.test(s));
  if (!links.length) throw new Error('no hy2:// / ss:// (etc.) share links found');
  const body = links.join('\n') + '\n';
  return { b64: Buffer.from(body, 'utf8').toString('base64'), links };
}

const res = await fetch(API);
if (!res.ok) throw new Error(`HTTP ${res.status}`);
const { b64, links } = toV2rayNSubscription(await decryptPayload(await res.text()));

writeFileSync('sub.txt', b64);
writeFileSync('links.txt', links.join('\n') + '\n');

console.log(`OK  节点数: ${links.length}`);
console.log(`已写入 sub.txt   (Base64 订阅, 用于托管 -> 订阅 URL)`);
console.log(`已写入 links.txt (明文链接, 用于手动导入)`);
console.log(`首条示例: ${links[0]?.slice(0, 64)}...`);
