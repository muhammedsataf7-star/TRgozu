// TR-GOZU — istemci güvenlik yardımcıları (JWT başlığı, PBKDF2 şifre saklama)

const TRGOZU_JWT_KEY = 'trgozu_jwt';
const TRGOZU_ROLE_KEY = 'trgozu_role';

function getTrgozuAuthHeaders() {
    const t = sessionStorage.getItem(TRGOZU_JWT_KEY);
    if (!t) return {};
    return { Authorization: 'Bearer ' + t };
}

function setTrgozuSession(token, role) {
    if (token) sessionStorage.setItem(TRGOZU_JWT_KEY, token);
    else sessionStorage.removeItem(TRGOZU_JWT_KEY);
    if (role) sessionStorage.setItem(TRGOZU_ROLE_KEY, role);
    else sessionStorage.removeItem(TRGOZU_ROLE_KEY);
}

function clearTrgozuSession() {
    sessionStorage.removeItem(TRGOZU_JWT_KEY);
    sessionStorage.removeItem(TRGOZU_ROLE_KEY);
}

const PBKDF2_ITERATIONS = 100000;

function _bufToB64(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

function _b64ToBuf(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
}

async function derivePasswordHash(password) {
    const enc = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );
    return `pbkdf2$${PBKDF2_ITERATIONS}$${_bufToB64(salt)}$${_bufToB64(bits)}`;
}

async function verifyPasswordHash(password, stored) {
    if (stored == null || typeof stored !== 'string') return false;
    if (!stored.startsWith('pbkdf2$')) {
        return password === stored;
    }
    const parts = stored.split('$');
    if (parts.length !== 4) return false;
    const iter = parseInt(parts[1], 10);
    const salt = _b64ToBuf(parts[2]);
    const expected = _b64ToBuf(parts[3]);
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt,
            iterations: iter,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );
    const out = new Uint8Array(bits);
    if (out.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < out.length; i++) diff |= out[i] ^ expected[i];
    return diff === 0;
}
