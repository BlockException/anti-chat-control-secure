const path = require('path');
const fs = require('fs/promises');
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const compression = require('compression');
const helmet = require('helmet');
const speakeasy = require('speakeasy');
const WebSocket = require('ws');

const DATA_DIR = path.resolve(__dirname, 'data');
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const QUEUE_FILE = path.join(DATA_DIR, 'queue.json');
const MESSAGE_WINDOW_MS = 5 * 60 * 1000;
const MAX_QUEUE_ITEMS = 2000;
const MAX_REPLAY_CACHE = 5000;

const clients = new Map();
const sessions = new Map();
const replayCache = new Set();
const replayOrder = [];
let accounts = new Map();
let offlineQueue = [];

async function ensureDataDirectory() {
  await fs.mkdir(DATA_DIR, { recursive: true });
}

async function loadJson(filePath, fallback) {
  try {
    const content = await fs.readFile(filePath, 'utf8');
    return JSON.parse(content);
  } catch (error) {
    if (error.code === 'ENOENT') {
      return fallback;
    }
    throw error;
  }
}

async function saveJson(filePath, value) {
  await fs.writeFile(filePath, JSON.stringify(value, null, 2), 'utf8');
}

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 180000, 32, 'sha256').toString('base64');
}

function createSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function getAccountByUsername(username) {
  return accounts.get(username) || null;
}

function getAccountByUserId(userId) {
  return Array.from(accounts.values()).find((account) => account.userId === userId) || null;
}

function createAccount(username, password) {
  const salt = crypto.randomBytes(16).toString('base64');
  const passwordHash = hashPassword(password, salt);
  const mfaSecret = speakeasy.generateSecret({ length: 20, name: `SecureChat:${username}` }).base32;
  const userId = crypto.randomUUID();
  const account = {
    username,
    userId,
    salt,
    passwordHash,
    mfaSecret,
    mfaEnabled: false,
    publicKey: null,
    signingPublicKey: null,
  };
  accounts.set(username, account);
  return account;
}

function verifyPassword(account, password) {
  const hash = hashPassword(password, account.salt);
  if (hash.length !== account.passwordHash.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(hash, 'base64'), Buffer.from(account.passwordHash, 'base64'));
}

function getMfaProvisioningUri(account) {
  return speakeasy.otpauthURL({
    secret: account.mfaSecret,
    label: `Secure Chat:${account.username}`,
    issuer: 'Secure Chat',
    encoding: 'base32',
  });
}

function pruneReplayCache() {
  while (replayOrder.length > MAX_REPLAY_CACHE) {
    const oldId = replayOrder.shift();
    replayCache.delete(oldId);
  }
}

function isValidMessage(message) {
  return (
    message
    && typeof message.from === 'string'
    && typeof message.to === 'string'
    && typeof message.messageId === 'string'
    && typeof message.timestamp === 'number'
    && typeof message.ciphertext === 'string'
    && typeof message.iv === 'string'
    && typeof message.ephemeralKey === 'string'
    && typeof message.signature === 'string'
  );
}

async function persistAccounts() {
  await saveJson(ACCOUNTS_FILE, [...accounts.values()]);
}

async function persistQueue() {
  await saveJson(QUEUE_FILE, offlineQueue);
}

function broadcastParticipants() {
  const participants = [...clients.values()].map((client) => ({
    userId: client.userId,
    username: client.username,
    publicKey: client.publicKey,
    signingPublicKey: client.signingPublicKey,
  }));

  clients.forEach((client) => {
    if (client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify({ type: 'participants', participants }));
    }
  });
}

async function deliverQueuedMessages(userId) {
  const recipient = clients.get(userId);
  if (!recipient || recipient.ws.readyState !== WebSocket.OPEN) {
    return;
  }

  const queueForRecipient = offlineQueue.filter((item) => item.to === userId);
  offlineQueue = offlineQueue.filter((item) => item.to !== userId);
  await persistQueue();

  queueForRecipient.forEach((queuedMessage) => {
    recipient.ws.send(JSON.stringify({ type: 'message', ...queuedMessage }));
  });
}

function pruneQueue() {
  if (offlineQueue.length > MAX_QUEUE_ITEMS) {
    offlineQueue = offlineQueue.slice(-MAX_QUEUE_ITEMS);
  }
}

async function loadState() {
  await ensureDataDirectory();
  const storedAccounts = await loadJson(ACCOUNTS_FILE, []);
  accounts = new Map(storedAccounts.map((account) => [account.username, account]));
  offlineQueue = await loadJson(QUEUE_FILE, []);
}

function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use(helmet());
  app.use(compression());
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  app.post('/api/auth', async (req, res) => {
    const { username, password, otp } = req.body;
    if (typeof username !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    let account = getAccountByUsername(username);
    if (!account) {
      account = createAccount(username, password);
      await persistAccounts();
    } else if (!verifyPassword(account, password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (account.mfaEnabled) {
      if (typeof otp !== 'string') {
        return res.status(403).json({ status: 'mfa_required' });
      }
      const verified = speakeasy.totp.verify({
        secret: account.mfaSecret,
        encoding: 'base32',
        token: otp,
        window: 1,
      });
      if (!verified) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    } else if (typeof otp === 'string') {
      const verified = speakeasy.totp.verify({
        secret: account.mfaSecret,
        encoding: 'base32',
        token: otp,
        window: 1,
      });
      if (verified) {
        account.mfaEnabled = true;
        await persistAccounts();
      }
    }

    const sessionToken = createSessionToken();
    sessions.set(sessionToken, account.userId);
    return res.json({
      status: 'ok',
      userId: account.userId,
      sessionToken,
      mfaEnabled: account.mfaEnabled,
      mfaProvisioningUri: account.mfaEnabled ? null : getMfaProvisioningUri(account),
    });
  });

  app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
  });

  app.use(express.static(path.join(__dirname, 'public')));

  app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
  });

  app.use((err, req, res, _next) => {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

function createServer() {
  const app = createApp();
  const server = http.createServer(app);
  const wss = new WebSocket.Server({ server });

  wss.on('connection', (ws) => {
    let connectedUserId = null;

    ws.on('message', async (raw) => {
      let message;
      try {
        message = JSON.parse(raw.toString());
      } catch {
        return;
      }

      if (message.type === 'register' && typeof message.sessionToken === 'string') {
        const userId = sessions.get(message.sessionToken);
        if (!userId) {
          ws.send(JSON.stringify({ type: 'error', error: 'Invalid session' }));
          return;
        }

        const account = getAccountByUserId(userId);
        if (!account) {
          ws.send(JSON.stringify({ type: 'error', error: 'Account not found' }));
          return;
        }

        connectedUserId = userId;
        if (typeof message.publicKey === 'string') {
          account.publicKey = message.publicKey;
        }
        if (typeof message.signingPublicKey === 'string') {
          account.signingPublicKey = message.signingPublicKey;
        }
        await persistAccounts();

        clients.set(userId, {
          ws,
          userId,
          username: account.username,
          publicKey: account.publicKey,
          signingPublicKey: account.signingPublicKey,
        });

        ws.send(JSON.stringify({ type: 'registered', userId }));
        broadcastParticipants();
        await deliverQueuedMessages(userId);
        return;
      }

      if (message.type === 'message' && isValidMessage(message)) {
        if (replayCache.has(message.messageId)) {
          return;
        }

        const isTooOld = Date.now() - message.timestamp > MESSAGE_WINDOW_MS;
        const isFromFuture = message.timestamp - Date.now() > 60 * 1000;

        if (isTooOld || isFromFuture) {
          return;
        }

        replayCache.add(message.messageId);
        replayOrder.push(message.messageId);
        pruneReplayCache();

        const recipient = clients.get(message.to);
        if (recipient && recipient.ws.readyState === WebSocket.OPEN) {
          const outgoing = JSON.stringify({ type: 'message', ...message });
          recipient.ws.send(outgoing);
        } else {
          offlineQueue.push(message);
          pruneQueue();
          await persistQueue();
        }
      }
    });

    ws.on('close', () => {
      if (connectedUserId) {
        clients.delete(connectedUserId);
        broadcastParticipants();
      }
    });
  });

  return server;
}

async function start() {
  await loadState();
  const server = createServer();
  const port = process.env.PORT || 3000;
  await new Promise((resolve, reject) => {
    server.listen(port, (error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  // eslint-disable-next-line no-console
  console.log('Secure relay server listening on port', port);
  return server;
}

if (require.main === module) {
  start().catch((error) => {
    // eslint-disable-next-line no-console
    console.error('Failed to start server:', error);
    process.exit(1);
  });
}

module.exports = { createApp, createServer, start };
