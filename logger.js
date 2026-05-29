// logger.js
import { request } from 'node:https';
import { URL } from 'node:url';

// 環境変数読み込み
const WEBHOOK_URL = process.env.WEBHOOK_URL;     // 🌐 アクセスURL通知用
const WEBHOOK_LOG = process.env.WEBHOOK_LOG;     // 📝 システムログ用
const NOTIFY_KEYWORDS = (process.env.NOTIFY_KEYWORDS || '')
  .split(',').map(k => k.trim().toLowerCase()).filter(Boolean);

// 除外ファイル拡張子
const SKIP_EXTENSIONS = /\.(jpg|jpeg|png|gif|webp|svg|mp4|webm|mp3|wav|zip|rar|exe|pdf|ico|css|js|woff2?|ttf)$/i;

// 共通Webhook送信関数
function sendWebhook(webhookUrl, payload) {
  if (!webhookUrl) return Promise.resolve(false);
  return new Promise((resolve) => {
    try {
      const url = new URL(webhookUrl);
      const data = JSON.stringify(payload);
      const req = request({
        hostname: url.hostname,
        port: url.protocol === 'https:' ? 443 : 80,
        path: url.pathname + url.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
        timeout: 3000
      }, (res) => { res.resume(); resolve(res.statusCode >= 200 && res.statusCode < 300); });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.write(data);
      req.end();
    } catch { resolve(false); }
  });
}

// 🌐 アクセスログ送信（ファイル除外）
export async function logAccess(req, metadata = {}) {
  if (!WEBHOOK_URL) return;
  const rawUrl = req.url || '';
  if (SKIP_EXTENSIONS.test(rawUrl)) return;
  const [path, query] = rawUrl.split('?');
  const keyword = NOTIFY_KEYWORDS.find(k => rawUrl.toLowerCase().includes(k)) || null;
  
  await sendWebhook(WEBHOOK_URL, {
    type: 'url_access',
    timestamp: new Date().toISOString(),
    method: req.method,
    path: path || '/',
    query: query || null,
    headers: {
      'user-agent': req.headers['user-agent'] || null,
      'ip': req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || null
    },
    bareRoute: rawUrl.startsWith('/bare/'),
    alertKeyword: keyword,
    ...metadata
  });
}

// 📝 システムログ送信
export async function logSystem(event, data = {}) {
  if (!WEBHOOK_LOG) return;
  await sendWebhook(WEBHOOK_LOG, {
    type: 'system_log',
    event,
    timestamp: new Date().toISOString(),
    ...data
  });
}

// ミドルウェア用ラッパー
export async function handleWebhooks(req, metadata = {}) {
  await logAccess(req, metadata);
}
