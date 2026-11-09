// Alle cryptografie van de app. Dit draait enkel in de browser: de server ziet nooit een sleutel.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_';
const MOD = ALPHABET.length; // 37

// Kleine letters worden hoofdletters en een spatie wordt _.
// Andere tekens (zoals . of é) passen niet in het alfabet: die weigeren we,
// zodat een bericht nooit stilletjes verandert.
function clean(text) {
    const result = text.trim().toUpperCase().replaceAll(' ', '_');

    for (const char of result) {
        if (!ALPHABET.includes(char)) {
            throw new Error(`Het teken "${char}" is niet toegelaten. Gebruik enkel A-Z, 0-9 en spaties.`);
        }
    }
    return result;
}

// Telt (richting = 1) of trekt (richting = -1) de sleutel per teken af, modulo 37.
function combine(text, key, direction) {
    let result = '';

    for (let i = 0; i < text.length; i++) {
        const t = ALPHABET.indexOf(text[i]);
        const k = ALPHABET.indexOf(key[i]);
        // + MOD zorgt ervoor dat het resultaat nooit negatief wordt.
        result += ALPHABET[(t + direction * k + MOD) % MOD];
    }
    return result;
}

function checkLengths(text, key) {
    if (text.length === 0) {
        throw new Error('Het bericht is leeg.');
    }
    if (key.length < text.length) {
        throw new Error(`De sleutel (${key.length} tekens) is korter dan het bericht (${text.length} tekens).`);
    }
}

// Versleutelen: (bericht + sleutel) mod 37.
export function encrypt(message, key) {
    const text = clean(message);
    const cleanKey = clean(key);
    checkLengths(text, cleanKey);
    return combine(text, cleanKey, 1);
}

// Ontsleutelen: (ciphertext - sleutel) mod 37. Een _ tonen we weer als spatie.
export function decrypt(ciphertext, key) {
    const cleanKey = clean(key);
    checkLengths(ciphertext, cleanKey);
    return combine(ciphertext, cleanKey, -1).replaceAll('_', ' ');
}

// ------------------------------------------------------------------ HMAC SHA256

function importHmacKey(secret, usage) {
    // Web Crypto bestaat enkel in een veilige context.
    if (!crypto.subtle) {
        throw new Error('Web Crypto werkt enkel via HTTPS of op localhost.');
    }
    return crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret.trim()),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        [usage]
    );
}

// De MAC beschermt de ciphertext en het regelnummer, zodat ook een gewijzigd nummer opvalt.
function macInput(keyLine, ciphertext) {
    return new TextEncoder().encode(`${keyLine}:${ciphertext}`);
}

export async function computeMac(secret, keyLine, ciphertext) {
    const key = await importHmacKey(secret, 'sign');
    const signature = await crypto.subtle.sign('HMAC', key, macInput(keyLine, ciphertext));
    return [...new Uint8Array(signature)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

// We laten verify de controle doen: die vergelijkt in constante tijd,
// zodat de duur van de controle niets verraadt over de juiste MAC.
export async function verifyMac(secret, keyLine, ciphertext, mac) {
    const key = await importHmacKey(secret, 'verify');
    const bytes = (mac.match(/../g) || []).map(pair => parseInt(pair, 16));
    return crypto.subtle.verify('HMAC', key, new Uint8Array(bytes), macInput(keyLine, ciphertext));
}
