/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToByteString(bytes) {
    let byteStr = ''
    for (let i = 0; i < bytes.byteLength; i++) {
        byteStr += String.fromCharCode(bytes[i])
    }
    return byteStr
}

/**
 * @param {string} byteStr
 * @returns {Uint8Array}
 */
export function byteStringToBytes(byteStr) {
    let bytes = new Uint8Array(byteStr.length)
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i)
    }
    return bytes
}

/**
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
export function arrayBufferToBase64String(arrayBuffer) {
    return btoa(bytesToByteString(new Uint8Array(arrayBuffer)))
}

/**
 * @param {string} b64str
 * @returns {ArrayBuffer}
 */
export function base64StringToArrayBuffer(b64str) {
    return byteStringToBytes(atob(b64str)).buffer
}

/**
 * @param {string} str
 * @returns {ArrayBuffer}
 */
export function textToArrayBuffer(str) {
    return byteStringToBytes(decodeURI(encodeURIComponent(str)))
}

/**
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
export function arrayBufferToText(arrayBuffer) {
    return bytesToByteString(new Uint8Array(arrayBuffer))
}

/**
 * @param {ArrayBuffer} arrayBuffer
 * @returns {string}
 */
export function arrayBufferToBase64Url(arrayBuffer) {
    return arrayBufferToBase64String(arrayBuffer).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * @param {string} b64url
 * @returns {ArrayBuffer}
 */
export function base64UrlToArrayBuffer(b64url) {
    return base64StringToArrayBuffer(b64url.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
}

/**
 * @param {string} str
 * @returns {string}
 */
export function textToBase64Url(str) {
    const encoder = new TextEncoder();
    const charCodes = encoder.encode(str);
    const binaryStr = String.fromCharCode(...charCodes);
    return btoa(binaryStr).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * @param {string} pem
 * @returns {ArrayBuffer}
 */
export function pemToBinary(pem) {
    return base64StringToArrayBuffer(pem.replace(/-+(BEGIN|END).*/g, '').replace(/\s/g, ''))
}

/**
 * @typedef {'sign' | 'verify'} KeyUsages
 */

/**
 * @param {string} key
 * @param {import('@cloudflare/workers-types').SubtleCryptoImportKeyAlgorithm} algorithm
 * @param {KeyUsages[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
export async function importTextSecret(key, algorithm, keyUsages) {
    return await crypto.subtle.importKey("raw", textToArrayBuffer(key), algorithm, true, keyUsages)
}

/**
 * @param {JsonWebKey} key
 * @param {import('@cloudflare/workers-types').SubtleCryptoImportKeyAlgorithm} algorithm
 * @param {KeyUsages[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
export async function importJwk(key, algorithm, keyUsages) {
    return await crypto.subtle.importKey("jwk", key, algorithm, true, keyUsages)
}

/**
 * @param {string} key
 * @param {import('@cloudflare/workers-types').SubtleCryptoImportKeyAlgorithm} algorithm
 * @param {KeyUsages[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
export async function importPublicKey(key, algorithm, keyUsages) {
    return await crypto.subtle.importKey("spki", pemToBinary(key), algorithm, true, keyUsages)
}

/**
 * @param {string} key
 * @param {import('@cloudflare/workers-types').SubtleCryptoImportKeyAlgorithm} algorithm
 * @param {KeyUsages[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
export async function importPrivateKey(key, algorithm, keyUsages) {
    return await crypto.subtle.importKey("pkcs8", pemToBinary(key), algorithm, true, keyUsages)
}

/**
 * @param {string | JsonWebKey} key
 * @param {import('@cloudflare/workers-types').SubtleCryptoImportKeyAlgorithm} algorithm
 * @param {KeyUsages[]} keyUsages
 * @returns {Promise<CryptoKey>}
 */
export async function importKey(key, algorithm, keyUsages) {
    if (typeof key === 'object')
        return importJwk(key, algorithm, keyUsages)

    if (typeof key !== 'string')
        throw new Error('Unsupported key type!')

    if (key.includes('PUBLIC'))
        return importPublicKey(key, algorithm, keyUsages)

    if (key.includes('PRIVATE'))
        return importPrivateKey(key, algorithm, keyUsages)

    return importTextSecret(key, algorithm, keyUsages)
}

/**
 * @template [T = any]
 * @param {string} raw
 * @returns {T | undefined}
 */
export function decodePayload(raw) {
    try {
        const bytes = Array.from(atob(raw), char => char.charCodeAt(0));
        const decodedString = new TextDecoder('utf-8').decode(new Uint8Array(bytes));

        return JSON.parse(decodedString);
    } catch {
        return
    }
}