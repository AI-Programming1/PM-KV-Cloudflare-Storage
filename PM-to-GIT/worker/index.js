addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

/* ======== BASIC HELPERS ======== */
function genRandomID(len = 16) {
  const arr = crypto.getRandomValues(new Uint8Array(len));
  let s = btoa(String.fromCharCode(...arr));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function genSessionToken(len = 24) {
  const arr = crypto.getRandomValues(new Uint8Array(len));
  let s = btoa(String.fromCharCode(...arr));
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}
async function kvGet(key) { const v = await USER_KV.get(key); return v ? JSON.parse(v) : null; }
async function kvPut(key, obj) { await USER_KV.put(key, JSON.stringify(obj)); }
async function kvDel(key) { await USER_KV.delete(key); }

async function isRevokedPmId(pmId) {
  if (!pmId) return false;
  const v = await USER_KV.get(`revoked:${pmId}`);
  return !!v;
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };
}
function corsWrap(resp) {
  if (resp instanceof Response) {
    for (const k in corsHeaders()) resp.headers.set(k, corsHeaders()[k]);
    return resp;
  }
  return (async () => {
    const r = await resp;
    for (const k in corsHeaders()) r.headers.set(k, corsHeaders()[k]);
    return r;
  })();
}

/* ======== BUFFER / BASE64 UTIL ======== */
function bufToBase64(buf) {
  let b = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) b += String.fromCharCode(bytes[i]);
  return btoa(b);
}
function base64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bytes.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function strToBuf(str) { return new TextEncoder().encode(str); }
function genSalt(len = 16) { const a = crypto.getRandomValues(new Uint8Array(len)); return bufToBase64(a.buffer); }

/* ======== USERNAME HASH (for KV key) ======== */
async function hashUsername(uname) {
  const normalized = uname.trim().toLowerCase();
  const data = new TextEncoder().encode(normalized);
  const digest = await crypto.subtle.digest("SHA-256", data);
  let b64 = bufToBase64(digest);
  // base64url encoding
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* ======== PBKDF2 PASSWORD HASHING (accounts) ======== */
async function derivePBKDF2(id, saltB64, iters = 100000, len = 32) {
  const saltBuf = base64ToBuf(saltB64);
  const keyMat = await crypto.subtle.importKey('raw', strToBuf(id), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new Uint8Array(saltBuf), iterations: iters, hash: 'SHA-256' },
    keyMat,
    len * 8
  );
  return bits;
}
async function makePasswordHash(id, saltB64 = null, iters = 100000) {
  const salt = saltB64 || genSalt(16);
  const derived = await derivePBKDF2(id, salt, iters, 32);
  const hash = bufToBase64(derived);
  return { hash, salt, iterations: iters };
}
async function verifyPassword(id, storedHash, salt, iters = 100000) {
  const derived = await derivePBKDF2(id, salt, iters, 32);
  const h = bufToBase64(derived);
  return h === storedHash;
}

/* ======== AES-GCM ENCRYPTION FOR TEXT MESSAGES ======== */
async function deriveKeyFromId(id) {
  const hash = await crypto.subtle.digest('SHA-256', strToBuf(id));
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function encryptMessage(id, text) {
  const key = await deriveKeyFromId(id);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, strToBuf(text || ""));
  return { iv: bufToBase64(iv), data: bufToBase64(enc) };
}
async function decryptMessage(id, obj) {
  try {
    if (typeof obj === "string") return obj;
    if (!obj || !obj.iv || !obj.data) return "[Invalid format]";
    const key = await deriveKeyFromId(id);
    const iv = base64ToBuf(obj.iv);
    const data = base64ToBuf(obj.data);
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, data);
    return new TextDecoder().decode(dec);
  } catch {
    return typeof obj === "string" ? obj : "[Decryption failed]";
  }
}

/* ======== ACCOUNT-FIELD ENCRYPTION (Option B) ======== */
/* Uses per-user passwordHash (already stored) to derive an AES key
   and encrypt sensitive account fields like pmId and username. */

async function deriveAccountKeyFromHash(passwordHashB64) {
  const hashBuf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(passwordHashB64)
  );
  return crypto.subtle.importKey("raw", hashBuf, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

async function encryptAccountField(passwordHashB64, plaintext) {
  const key = await deriveAccountKeyFromHash(passwordHashB64);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(plaintext || "")
  );
  return {
    iv: bufToBase64(iv.buffer),
    data: bufToBase64(enc),
  };
}

async function decryptAccountField(passwordHashB64, encObj) {
  if (!encObj || !encObj.iv || !encObj.data) return null;
  try {
    const key = await deriveAccountKeyFromHash(passwordHashB64);
    const ivBuf = base64ToBuf(encObj.iv);
    const dataBuf = base64ToBuf(encObj.data);
    const dec = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: new Uint8Array(ivBuf) },
      key,
      dataBuf
    );
    return new TextDecoder().decode(dec);
  } catch (e) {
    console.error("decryptAccountField failed:", e);
    return null;
  }
}

/* Helper: load & migrate user record (add pmIdEnc/usernameEnc & hashed-key) */
async function getUserRecord(uname) {
  const normalized = uname.trim().toLowerCase();
  const unameHash = await hashUsername(normalized);
  const hashedKey = `user:${unameHash}`;

  // Try hashed key (new format) first
  let raw = await USER_KV.get(hashedKey);
  if (raw) {
    let user = JSON.parse(raw);

    // Ensure pmIdEnc & usernameEnc exist if passwordHash present
    let changed = false;
    if (user.passwordHash) {
      if (!user.usernameEnc) {
        user.usernameEnc = await encryptAccountField(user.passwordHash, normalized);
        changed = true;
      }
      if (user.pmId && !user.pmIdEnc) {
        user.pmIdEnc = await encryptAccountField(user.passwordHash, user.pmId);
        delete user.pmId;
        changed = true;
      }
    }
    if (changed) {
      await USER_KV.put(hashedKey, JSON.stringify(user));
    }
    return user;
  }

  // Fallback: old key user:<username>, migrate it
  const oldKey = `user:${normalized}`;
  raw = await USER_KV.get(oldKey);
  if (!raw) return null;

  let user = JSON.parse(raw);
  if (user.passwordHash) {
    if (!user.pmIdEnc && user.pmId) {
      user.pmIdEnc = await encryptAccountField(user.passwordHash, user.pmId);
      delete user.pmId;
    }
    if (!user.usernameEnc) {
      user.usernameEnc = await encryptAccountField(user.passwordHash, normalized);
    }
  }

  await USER_KV.put(hashedKey, JSON.stringify(user));
  await USER_KV.delete(oldKey);

  return user;
}

/* ======== AES-GCM ENCRYPTION FOR MEDIA BLOBS (server-side at-rest) ======== */
/* CHANGE THIS to a long random secret before deploying */
const MEDIA_MASTER = "CHANGE_THIS_MEDIA_MASTER_KEY_TO_A_LONG_RANDOM_STRING";

async function deriveMediaKey() {
  const hash = await crypto.subtle.digest('SHA-256', strToBuf(MEDIA_MASTER));
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function encryptMediaBase64(b64Str) {
  const key = await deriveMediaKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, strToBuf(b64Str));
  return { iv: bufToBase64(iv), data: bufToBase64(enc) };
}
async function decryptMediaBase64(encObj) {
  if (!encObj || !encObj.iv || !encObj.data) throw new Error("Invalid media cipher");
  const key = await deriveMediaKey();
  const iv = base64ToBuf(encObj.iv);
  const data = base64ToBuf(encObj.data);
  const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, data);
  return new TextDecoder().decode(dec); // original base64 string
}

/* ======== SESSION HELPERS ======== */
async function getUserBySessionToken(token) {
  if (!token) return null;
  const list = await USER_KV.list({ prefix: 'user:' });
  for (const k of list.keys) {
    const raw = await USER_KV.get(k.name);
    if (!raw) continue;
    const u = JSON.parse(raw);
    if (u.sessionToken === token) {
      let uname = null;
      if (u.usernameEnc && u.passwordHash) {
        uname = await decryptAccountField(u.passwordHash, u.usernameEnc);
      }
      if (!uname) {
        // fallback: legacy key
        uname = k.name.replace(/^user:/, '');
      }
      return { username: (uname || ''), user: u };
    }
  }
  return null;
}

/* ======== MEDIA ID EXTRACTOR (from URL) ======== */
function extractMediaIdFromUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    const parts = u.pathname.split("/media/");
    if (parts.length < 2) return null;
    return decodeURIComponent(parts[1]);
  } catch {
    return null;
  }
}

/* ======== ROUTER ======== */
async function handleRequest(req) {
  const url = new URL(req.url);
  const path = url.pathname;
  try {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

    if (path === '/createAccount' && req.method === 'POST') return corsWrap(await handleCreateAccount(req));
    if (path === '/login' && req.method === 'POST') return corsWrap(await handleLogin(req));
    if (path === '/logout' && req.method === 'POST') return corsWrap(await handleLogout(req));
    if (path === '/sendPM' && req.method === 'POST') return corsWrap(await handleSendPM(req));
    if (path === '/inbox' && req.method === 'GET') return corsWrap(await handleInbox(req));
    if (path === '/deleteMessage' && req.method === 'POST') return corsWrap(await handleDeleteMessage(req));
    if (path === '/deleteAll' && req.method === 'POST') return corsWrap(await handleDeleteAll(req));
    if (path === '/deleteAccount' && req.method === 'POST') return corsWrap(await handleDeleteAccount(req));
    if (path === '/regeneratePmId' && req.method === 'POST') return corsWrap(await handleRegeneratePmId(req));

    if (path === '/uploadMedia' && req.method === 'POST') return corsWrap(await handleUploadMedia(req));
    if (path.startsWith('/media/') && req.method === 'GET') return await handleGetMedia(req);

    return new Response('Not found', { status: 404, headers: corsHeaders() });
  } catch (e) {
    console.error("Worker error:", e);
    return new Response(JSON.stringify({ ok: false, error: e.message || String(e) }), {
      status: 500,
      headers: { "Content-Type": "application/json", ...corsHeaders() }
    });
  }
}

/* ======== API IMPLEMENTATIONS ======== */

// CREATE ACCOUNT (now uses hashed username key)
async function handleCreateAccount(req) {
  const { username } = await req.json();
  if (!username) return jsonResponse({ ok: false, error: 'Missing username' }, 400);
  const uname = username.trim().toLowerCase();
  const unameHash = await hashUsername(uname);
  const hashedKey = `user:${unameHash}`;

  // Check both new hashed key and old legacy key to avoid dupes
  if (await USER_KV.get(hashedKey) || await USER_KV.get(`user:${uname}`)) {
    return jsonResponse({ ok: false, error: 'Username taken' }, 409);
  }

  const rawId = genRandomID(18);
  const { hash, salt, iterations } = await makePasswordHash(rawId);
  const pmId = genRandomID(18);
  const createdAt = new Date().toISOString();

  // Encrypt pmId and username at rest using per-user passwordHash
  const pmIdEnc = await encryptAccountField(hash, pmId);
  const usernameEnc = await encryptAccountField(hash, uname);

  const record = {
    passwordHash: hash,
    salt,
    iterations,
    pmIdEnc,
    usernameEnc,
    createdAt
  };

  await USER_KV.put(hashedKey, JSON.stringify(record));
  await kvPut(`pm:${pmId}`, []);
  return jsonResponse({ ok: true, username: uname, id: rawId, pmId });
}

// LOGIN (decrypt pmIdEnc to return pmId)
async function handleLogin(req) {
  const { username, id } = await req.json();
  if (!username || !id) return jsonResponse({ ok: false, error: 'Missing fields' }, 400);
  const uname = username.trim().toLowerCase();
  const data = await getUserRecord(uname); // may migrate old record
  if (!data) return jsonResponse({ ok: false, error: 'User not found' }, 404);
  const ok = await verifyPassword(id, data.passwordHash, data.salt, data.iterations);
  if (!ok) return jsonResponse({ ok: false, error: 'Invalid credentials' }, 403);

  const token = genSessionToken(24);
  data.sessionToken = token;

  // Decrypt pmId from pmIdEnc for this session
  const pmId = data.pmIdEnc
    ? await decryptAccountField(data.passwordHash, data.pmIdEnc)
    : data.pmId; // fallback for any not-yet-migrated case

  if (!pmId) {
    console.error("Failed to derive pmId for user:", uname);
    return jsonResponse({ ok: false, error: "Account data corrupt" }, 500);
  }

  // Persist back under hashed key
  const unameHash = await hashUsername(uname);
  await USER_KV.put(`user:${unameHash}`, JSON.stringify(data));

  return jsonResponse({ ok: true, username: uname, pmId, sessionToken: token });
}

// LOGOUT
async function handleLogout(req) {
  const { username, sessionToken } = await req.json();
  if (!username || !sessionToken) return jsonResponse({ ok: false, error: 'Missing fields' }, 400);
  const uname = username.trim().toLowerCase();
  const u = await getUserRecord(uname);
  if (!u) return jsonResponse({ ok: false, error: 'User not found' }, 404);
  if (u.sessionToken === sessionToken) delete u.sessionToken;
  const unameHash = await hashUsername(uname);
  await USER_KV.put(`user:${unameHash}`, JSON.stringify(u));
  return jsonResponse({ ok: true });
}

// SEND PM
async function handleSendPM(req) {
  const body = await req.json();
  const { sessionToken, toUsername, subject, body: msgBody, mediaUrl, mediaType } = body || {};
  if (!sessionToken || !toUsername || !msgBody) return jsonResponse({ ok: false, error: 'Missing fields' }, 400);

  const sender = await getUserBySessionToken(sessionToken);
  if (!sender) return jsonResponse({ ok: false, error: 'Invalid session' }, 403);
  const senderName = sender.username;

  const recRaw = await getUserRecord(toUsername.trim().toLowerCase());
  if (!recRaw) return jsonResponse({ ok: false, error: 'Recipient not found' }, 404);

  const recPmId = recRaw.pmIdEnc
    ? await decryptAccountField(recRaw.passwordHash, recRaw.pmIdEnc)
    : recRaw.pmId;

  if (!recPmId) return jsonResponse({ ok: false, error: 'Recipient inbox missing' }, 500);
  if (await isRevokedPmId(recPmId)) return jsonResponse({ ok: false, error: 'Recipient PM revoked' }, 403);

  const encryptedSubject = await encryptMessage(recRaw.passwordHash, subject || "");
  const encryptedBody = await encryptMessage(recRaw.passwordHash, msgBody || "");

  const msg = {
    id: genRandomID(12),
    senderUsername: senderName,
    subject: encryptedSubject,
    body: encryptedBody,
    ts: new Date().toISOString(),
    mediaUrl: mediaUrl || null,
    mediaType: mediaType || null
  };
  const inboxKey = `pm:${recPmId}`;
  const currentRaw = await USER_KV.get(inboxKey);
  let arr = currentRaw ? JSON.parse(currentRaw) : [];
  arr.push(msg);
  await USER_KV.put(inboxKey, JSON.stringify(arr));
  return jsonResponse({ ok: true, delivered: true });
}

// INBOX
async function handleInbox(req) {
  const url = new URL(req.url);
  const pmId = url.searchParams.get('id');
  const token = url.searchParams.get('token');
  if (!pmId) return jsonResponse({ ok: false, error: 'Missing id' }, 400);
  if (await isRevokedPmId(pmId)) return jsonResponse({ ok: false, error: 'PM revoked' }, 403);

  const userList = await USER_KV.list({ prefix: 'user:' });
  let owner = null;
  let ownerUsername = null;
  for (const k of userList.keys) {
    const raw = await USER_KV.get(k.name);
    if (!raw) continue;
    const u = JSON.parse(raw);
    // Support both new (pmIdEnc) and old (pmId) formats
    let userPmId = u.pmId;
    if (!userPmId && u.pmIdEnc) {
      userPmId = await decryptAccountField(u.passwordHash, u.pmIdEnc);
    }
    if (userPmId === pmId) {
      owner = u;
      if (u.usernameEnc && u.passwordHash) {
        ownerUsername = await decryptAccountField(u.passwordHash, u.usernameEnc);
      } else {
        ownerUsername = k.name.replace(/^user:/, '');
      }
      break;
    }
  }
  if (!owner) return jsonResponse({ ok: false, error: 'Invalid PM ID' }, 403);
  if (!token || token !== owner.sessionToken) return jsonResponse({ ok: false, error: 'Not authenticated' }, 403);

  const pmRaw = await USER_KV.get(`pm:${pmId}`);
  let arr = pmRaw ? JSON.parse(pmRaw) : [];
  for (const m of arr) {
    m.subject = await decryptMessage(owner.passwordHash, m.subject);
    m.body = await decryptMessage(owner.passwordHash, m.body);
  }
  return jsonResponse({ ok: true, messages: arr });
}

/* ======== MESSAGE MANAGEMENT + MEDIA CLEANUP ======== */

// DELETE SINGLE MESSAGE
async function handleDeleteMessage(request) {
  const body = await request.json();
  const { sessionToken, pmId, msgId } = body || {};
  if (!sessionToken || !pmId || !msgId) return jsonResponse({ ok: false, error: 'Missing fields' }, 400);

  const owner = await getUserBySessionToken(sessionToken);
  if (!owner) return jsonResponse({ ok: false, error: 'Not authorized' }, 403);

  // Check that this pmId actually belongs to the session owner
  let ownerPmId = owner.user.pmId;
  if (!ownerPmId && owner.user.pmIdEnc) {
    ownerPmId = await decryptAccountField(owner.user.passwordHash, owner.user.pmIdEnc);
  }
  if (ownerPmId !== pmId) return jsonResponse({ ok: false, error: 'Not authorized' }, 403);

  const inboxKey = `pm:${pmId}`;
  const currentRaw = await USER_KV.get(inboxKey);
  if (!currentRaw) return jsonResponse({ ok: false, error: 'Inbox not found' }, 404);
  let arr = JSON.parse(currentRaw);

  const msgToDelete = arr.find(m => m.id === msgId);
  const newArr = arr.filter(m => m.id !== msgId);
  await USER_KV.put(inboxKey, JSON.stringify(newArr));

  // delete associated media blob if exists
  if (msgToDelete && msgToDelete.mediaUrl) {
    const mediaId = extractMediaIdFromUrl(msgToDelete.mediaUrl);
    if (mediaId) {
      await USER_KV.delete(`media:${mediaId}`);
    }
  }

  return jsonResponse({ ok: true });
}

// DELETE ALL MESSAGES IN INBOX + media
async function handleDeleteAll(request) {
  const body = await request.json();
  const { sessionToken, pmId } = body || {};
  if (!sessionToken || !pmId) return jsonResponse({ ok: false, error: 'Missing fields' }, 400);

  const owner = await getUserBySessionToken(sessionToken);
  if (!owner) return jsonResponse({ ok: false, error: 'Not authorized' }, 403);

  let ownerPmId = owner.user.pmId;
  if (!ownerPmId && owner.user.pmIdEnc) {
    ownerPmId = await decryptAccountField(owner.user.passwordHash, owner.user.pmIdEnc);
  }
  if (ownerPmId !== pmId) return jsonResponse({ ok: false, error: 'Not authorized' }, 403);

  const inboxKey = `pm:${pmId}`;
  const currentRaw = await USER_KV.get(inboxKey);
  let arr = currentRaw ? JSON.parse(currentRaw) : [];

  // delete all media blobs for this inbox
  for (const m of arr) {
    if (m.mediaUrl) {
      const mediaId = extractMediaIdFromUrl(m.mediaUrl);
      if (mediaId) {
        await USER_KV.delete(`media:${mediaId}`);
      }
    }
  }

  await USER_KV.put(inboxKey, JSON.stringify([]));
  return jsonResponse({ ok: true });
}

// DELETE ACCOUNT + revoke PM + remove messages + media
async function handleDeleteAccount(req) {
  try {
    const { username, sessionToken } = await req.json();
    if (!username || !sessionToken)
      return jsonResponse({ ok: false, error: "Missing fields" }, 400);

    const uname = username.trim().toLowerCase();
    const user = await getUserRecord(uname);
    if (!user)
      return jsonResponse({ ok: false, error: "User not found" }, 404);

    if (user.sessionToken !== sessionToken)
      return jsonResponse({ ok: false, error: "Invalid session" }, 403);

    // derive current pmId (may be encrypted)
    const userPmId = user.pmIdEnc
      ? await decryptAccountField(user.passwordHash, user.pmIdEnc)
      : user.pmId;

    // revoke PM link for a while
    if (userPmId) {
      await USER_KV.put(`revoked:${userPmId}`, "1", { expirationTtl: 86400 });
    }

    // delete own inbox + its media
    if (userPmId) {
      const inboxKey = `pm:${userPmId}`;
      const inboxRaw = await USER_KV.get(inboxKey);
      if (inboxRaw) {
        const msgs = JSON.parse(inboxRaw);
        for (const m of msgs) {
          if (m.mediaUrl) {
            const mediaId = extractMediaIdFromUrl(m.mediaUrl);
            if (mediaId) await USER_KV.delete(`media:${mediaId}`);
          }
        }
        await USER_KV.delete(inboxKey);
      }
    }

    // delete user record (hashed key + legacy key just in case)
    const unameHash = await hashUsername(uname);
    await USER_KV.delete(`user:${unameHash}`);
    await USER_KV.delete(`user:${uname}`);

    // remove messages they sent from all inboxes + media of those messages
    const list = await USER_KV.list({ prefix: "pm:" });
    for (const entry of list.keys) {
      const key = entry.name;
      const rawInbox = await USER_KV.get(key);
      if (!rawInbox) continue;
      const msgs = JSON.parse(rawInbox);
      const kept = [];
      for (const m of msgs) {
        if (m.senderUsername === uname) {
          if (m.mediaUrl) {
            const mediaId = extractMediaIdFromUrl(m.mediaUrl);
            if (mediaId) await USER_KV.delete(`media:${mediaId}`);
          }
        } else {
          kept.push(m);
        }
      }
      if (kept.length !== msgs.length) {
        await USER_KV.put(key, JSON.stringify(kept));
      }
    }

    return jsonResponse({ ok: true, message: "Account and sent messages deleted." }, 200);
  } catch (err) {
    console.error("Delete account error:", err);
    return jsonResponse({ ok: false, error: err.message }, 500);
  }
}

// REGENERATE PM LINK
async function handleRegeneratePmId(request) {
  const body = await request.json();
  const { sessionToken, username } = body || {};
  if (!sessionToken || !username) return jsonResponse({ ok: false, error: 'Missing fields' }, 400);

  const uname = username.trim().toLowerCase();
  const user = await getUserRecord(uname);
  if (!user) return jsonResponse({ ok: false, error: 'User not found' }, 404);
  if (user.sessionToken !== sessionToken)
    return jsonResponse({ ok: false, error: 'Not authorized' }, 403);

  const oldPmId = user.pmIdEnc
    ? await decryptAccountField(user.passwordHash, user.pmIdEnc)
    : user.pmId;

  const newPmId = genRandomID(18);

  if (oldPmId) {
    const oldInbox = await USER_KV.get(`pm:${oldPmId}`);
    if (oldInbox) await USER_KV.put(`pm:${newPmId}`, oldInbox);
    await USER_KV.put(`revoked:${oldPmId}`, "1");
  } else {
    // no old inbox, just create empty
    await USER_KV.put(`pm:${newPmId}`, JSON.stringify([]));
  }

  const newPmIdEnc = await encryptAccountField(user.passwordHash, newPmId);
  user.pmIdEnc = newPmIdEnc;
  delete user.pmId;

  const unameHash = await hashUsername(uname);
  await USER_KV.put(`user:${unameHash}`, JSON.stringify(user));

  return jsonResponse({ ok: true, newPmId });
}

/* ======== MEDIA UPLOAD (client compresses, Worker encrypts at rest) ======== */

// POST /uploadMedia  (multipart/form-data: file + sessionToken)
async function handleUploadMedia(req) {
  const contentType = req.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().startsWith("multipart/form-data")) {
    return jsonResponse({ ok: false, error: "Invalid content type" }, 400);
  }

  const form = await req.formData();
  const file = form.get("file");
  const sessionToken = form.get("sessionToken");

  if (!sessionToken) return jsonResponse({ ok: false, error: "Missing sessionToken" }, 400);
  if (!file) return jsonResponse({ ok: false, error: "No file provided" }, 400);

  const user = await getUserBySessionToken(sessionToken);
  if (!user) return jsonResponse({ ok: false, error: "Invalid session" }, 403);

  const MAX_MEDIA_BYTES = 1 * 1024 * 1024; // 1 MB
  if (file.size && file.size > MAX_MEDIA_BYTES) {
    return jsonResponse({ ok: false, error: "File too large (max ~1MB)" }, 400);
  }

  const arrayBuffer = await file.arrayBuffer();
  const base64 = bufToBase64(arrayBuffer);
  const mediaId = genRandomID(18);
  const type = file.type || "application/octet-stream";

  const cipher = await encryptMediaBase64(base64);

  await USER_KV.put(`media:${mediaId}`, JSON.stringify({
    c: cipher,
    type,
    uploadedBy: user.username,
    ts: new Date().toISOString()
  }));

  const url = new URL(req.url);
  const mediaUrl = `${url.origin}/media/${mediaId}`;

  return jsonResponse({ ok: true, url: mediaUrl, mediaType: type });
}

// GET /media/:id?token=SESSION_TOKEN
async function handleGetMedia(req) {
  const url = new URL(req.url);
  const id = url.pathname.slice("/media/".length);
  const token = url.searchParams.get("token");

  if (!id) return new Response("Not found", { status: 404, headers: corsHeaders() });

  // require logged-in user
  const user = await getUserBySessionToken(token);
  if (!user) {
    return new Response("Unauthorized", { status: 401, headers: corsHeaders() });
  }

  const raw = await USER_KV.get(`media:${id}`);
  if (!raw) return new Response("Not found", { status: 404, headers: corsHeaders() });

  const stored = JSON.parse(raw);
  if (!stored.c) return new Response("Corrupt media", { status: 500, headers: corsHeaders() });

  const base64 = await decryptMediaBase64(stored.c);
  const buf = base64ToBuf(base64);
  const bytes = new Uint8Array(buf);

  return new Response(bytes, {
    status: 200,
    headers: {
      "Content-Type": stored.type || "application/octet-stream",
      "Cache-Control": "private, max-age=0",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
