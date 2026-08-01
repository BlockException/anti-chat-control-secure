const loginPanel = document.getElementById('login-panel');
const participantsPanel = document.getElementById('participants-panel');
const participantsList = document.getElementById('participants-list');
const loginBtn = document.getElementById('login-btn');
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const chatArea = document.getElementById('chat-area');
const chatTitle = document.getElementById('chat-title');
const chatSubtitle = document.getElementById('chat-subtitle');
const messagesEl = document.getElementById('messages');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const updateBanner = document.getElementById('update-banner');

const APP_VERSION = '1.0.0';
let socket;
let userId;
let username;
let keyPair;
let publicKeyBase64;
const participants = new Map();
let selectedUserId = null;
let seenMessageIds = new Set();

async function deriveAuthToken(password) {
  const salt = new TextEncoder().encode('anti-chat-control-auth');
  const passBytes = new TextEncoder().encode(password);
  const baseKey = await crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 150000,
    },
    baseKey,
    256,
  );
  return arrayBufferToBase64(derived);
}

async function generateKeys() {
  keyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );

  const rawPublicKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  publicKeyBase64 = arrayBufferToBase64(rawPublicKey);
}

async function importPublicKey(raw) {
  return crypto.subtle.importKey(
    'raw',
    raw,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  );
}

async function deriveSharedKey(publicKeyRaw, privateKey) {
  const otherPublicKey = await importPublicKey(publicKeyRaw);
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: otherPublicKey },
    privateKey,
    256,
  );

  const hkdfKey = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(16),
      info: new TextEncoder().encode('secure-chat-message'),
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

async function generateEphemeralKey() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  );
}

async function encryptMessage(text, recipientPublicKey) {
  const ephemeral = await generateEphemeralKey();
  const rawEphemeralPublic = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
  const key = await deriveSharedKey(recipientPublicKey, ephemeral.privateKey);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return {
    ciphertext: arrayBufferToBase64(ciphertext),
    iv: arrayBufferToBase64(iv),
    ephemeralKey: arrayBufferToBase64(rawEphemeralPublic),
  };
}

async function decryptMessage(ciphertextBase64, ivBase64, senderPublicKey, ephemeralKeyBase64) {
  const key = await deriveSharedKey(base64ToArrayBuffer(ephemeralKeyBase64), keyPair.privateKey);
  const ciphertext = base64ToArrayBuffer(ciphertextBase64);
  const iv = base64ToArrayBuffer(ivBase64);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function makeUuid() {
  return crypto.randomUUID();
}

function showUpdateBanner(version) {
  updateBanner.textContent = `Neue App-Version verfügbar: ${version}. Bitte Seite neu laden.`;
  updateBanner.classList.remove('hidden');
}

async function checkAppVersion() {
  try {
    const response = await fetch('/version.json', { cache: 'no-cache' });
    if (!response.ok) return;
    const data = await response.json();
    if (data.version && data.version !== APP_VERSION) {
      showUpdateBanner(data.version);
    }
  } catch (error) {
    console.warn('Versionsprüfung fehlgeschlagen', error);
  }
}

function connectWebSocket(authToken) {
  const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  socket = new WebSocket(`${scheme}//${window.location.host}`);

  socket.addEventListener('open', () => {
    socket.send(JSON.stringify({
      type: 'register',
      username,
      authToken,
      publicKey: publicKeyBase64,
    }));
  });

  socket.addEventListener('message', async (event) => {
    const message = JSON.parse(event.data);

    if (message.type === 'registered' && typeof message.userId === 'string') {
      userId = message.userId;
      return;
    }

    if (message.type === 'participants') {
      updateParticipants(message.participants);
      return;
    }

    if (message.type === 'message' && message.to === userId) {
      if (seenMessageIds.has(message.messageId)) {
        return;
      }
      seenMessageIds.add(message.messageId);
      if (seenMessageIds.size > 5000) {
        seenMessageIds = new Set(Array.from(seenMessageIds).slice(-4000));
      }

      const sender = participants.get(message.from);
      if (!sender) {
        return;
      }
      try {
        const text = await decryptMessage(
          message.ciphertext,
          message.iv,
          base64ToArrayBuffer(sender.publicKey),
          message.ephemeralKey,
        );
        appendMessage(text, 'incoming', sender.username);
      } catch (error) {
        console.error('Decrypt error', error);
      }
    }
  });
}

function updateParticipants(list) {
  participants.clear();
  participantsList.innerHTML = '';
  const filtered = list.filter((participant) => participant.userId !== userId);

  filtered.forEach((participant) => {
    participants.set(participant.userId, participant);
    const item = document.createElement('div');
    item.className = 'participant';
    item.textContent = participant.username;
    item.dataset.id = participant.userId;
    item.addEventListener('click', () => selectParticipant(participant.userId));
    participantsList.appendChild(item);
  });

  if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.textContent = 'Keine anderen Teilnehmer online.';
    empty.style.color = '#94a3b8';
    participantsList.appendChild(empty);
    chatTitle.textContent = 'Warte auf andere Teilnehmer';
    chatSubtitle.textContent = 'Privatsphäre durch direkte Verschlüsselung.';
    selectedUserId = null;
    document.querySelectorAll('.participant').forEach((entry) => entry.classList.remove('selected'));
  }
}

function selectParticipant(id) {
  selectedUserId = id;
  const participant = participants.get(id);
  chatTitle.textContent = participant ? `Chat mit ${participant.username}` : 'Wähle einen Kontakt';
  chatSubtitle.textContent = participant
    ? 'Nachrichten werden lokal verschlüsselt übertragen.'
    : 'Privatsphäre durch direkte Verschlüsselung.';
  document.querySelectorAll('.participant').forEach((entry) => {
    entry.classList.toggle('selected', entry.dataset.id === id);
  });
  messagesEl.innerHTML = '';
}

function appendMessage(text, direction, author) {
  const message = document.createElement('div');
  message.className = `message ${direction}`;
  message.innerHTML = `<div>${escapeHtml(text)}</div><div class="meta">${direction === 'outgoing' ? 'Du' : escapeHtml(author)} · ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>`;
  messagesEl.appendChild(message);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function escapeHtml(text) {
  return text.replace(/[&<>'"]/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  })[char]);
}

loginBtn.addEventListener('click', async () => {
  username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username) {
    usernameInput.focus();
    return;
  }
  if (!password) {
    passwordInput.focus();
    return;
  }

  loginPanel.classList.add('hidden');
  participantsPanel.classList.remove('hidden');
  chatArea.classList.remove('hidden');

  await generateKeys();
  const authToken = await deriveAuthToken(password);
  connectWebSocket(authToken);
});

messageForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const text = messageInput.value.trim();
  if (!text || !selectedUserId) {
    return;
  }
  const recipient = participants.get(selectedUserId);
  if (!recipient) {
    return;
  }

  const recipientPublicKey = base64ToArrayBuffer(recipient.publicKey);
  const encrypted = await encryptMessage(text, recipientPublicKey);
  const messageId = makeUuid();
  const timestamp = Date.now();

  socket.send(JSON.stringify({
    type: 'message',
    from: userId,
    to: selectedUserId,
    ciphertext: encrypted.ciphertext,
    iv: encrypted.iv,
    ephemeralKey: encrypted.ephemeralKey,
    messageId,
    timestamp,
  }));

  appendMessage(text, 'outgoing', 'Du');
  messageInput.value = '';
});

checkAppVersion();
