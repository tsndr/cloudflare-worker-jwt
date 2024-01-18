export function bytesToByteString(bytes: Uint8Array): string {
    let byteStr = ''
    for (let i = 0; i < bytes.byteLength; i++) {
        byteStr += String.fromCharCode(bytes[i])
    }
    return byteStr
}

export function byteStringToBytes(byteStr: string): Uint8Array {
    let bytes = new Uint8Array(byteStr.length)
    for (let i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i)
    }
    return bytes
}

export function arrayBufferToBase64String(arrayBuffer: ArrayBuffer): string {
    return btoa(bytesToByteString(new Uint8Array(arrayBuffer)))
}

export function base64StringToArrayBuffer(b64str: string): ArrayBuffer {
    return byteStringToBytes(atob(b64str)).buffer
}

export function textToArrayBuffer(str: string): ArrayBuffer {
    return byteStringToBytes(decodeURI(encodeURIComponent(str)))
}

export function arrayBufferToText(arrayBuffer: ArrayBuffer): string {
    return bytesToByteString(new Uint8Array(arrayBuffer))
}

export function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    return arrayBufferToBase64String(arrayBuffer).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function base64UrlToArrayBuffer(b64url: string): ArrayBuffer {
    return base64StringToArrayBuffer(b64url.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, ''))
}

export function textToBase64Url(str: string): string {
    const encoder = new TextEncoder();
    const charCodes = encoder.encode(str);
    const binaryStr = String.fromCharCode(...charCodes);
    return btoa(binaryStr).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function pemToBinary(pem: string): ArrayBuffer {
    return base64StringToArrayBuffer(pem.replace(/-+(BEGIN|END).*/g, '').replace(/\s/g, ''))
}

export async function importTextSecret(key: string, algorithm: SubtleCryptoImportKeyAlgorithm): Promise<CryptoKey> {
    return await crypto.subtle.importKey("raw", textToArrayBuffer(key), algorithm, true, ["verify", "sign"])
}

export async function importJwk(key: JsonWebKey, algorithm: SubtleCryptoImportKeyAlgorithm): Promise<CryptoKey> {
    return await crypto.subtle.importKey("jwk", key, algorithm, true, ["verify", "sign"])
}

export async function importPublicKey(key: string, algorithm: SubtleCryptoImportKeyAlgorithm): Promise<CryptoKey> {
    return await crypto.subtle.importKey("spki", pemToBinary(key), algorithm, true, ["verify"])
}

export async function importPrivateKey(key: string, algorithm: SubtleCryptoImportKeyAlgorithm): Promise<CryptoKey> {
    return await crypto.subtle.importKey("pkcs8", pemToBinary(key), algorithm, true, ["sign"])
}

export async function importKey(key: string | JsonWebKey, algorithm: SubtleCryptoImportKeyAlgorithm): Promise<CryptoKey> {
    if (typeof key === 'object')
        return importJwk(key, algorithm)

    if (typeof key !== 'string')
        throw new Error('Unsupported key type!')

    if (key.includes('PUBLIC'))
        return importPublicKey(key, algorithm)

    if (key.includes('PRIVATE'))
        return importPrivateKey(key, algorithm)

    return importTextSecret(key, algorithm)
}

export function decodePayload<T = any>(raw: string): T | undefined {
    try {
        const bytes = Array.from(atob(raw), char => char.charCodeAt(0));
        const decodedString = new TextDecoder('utf-8').decode(new Uint8Array(bytes));

        return JSON.parse(decodedString);
    } catch {
        return
    }
}