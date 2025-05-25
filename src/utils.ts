export type KeyUsages = "sign" | "verify"
export type x509Element = {
    byteLength: number,
    contents: Uint8Array,
    raw: Uint8Array
}


export function bytesToByteString(bytes: Uint8Array): string {
    let byteStr = ""
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

export function base64StringToUint8Array(b64str: string): Uint8Array {
    return byteStringToBytes(atob(b64str))
}

export function textToUint8Array(str: string): Uint8Array {
    return byteStringToBytes(str)
}

export function arrayBufferToText(arrayBuffer: ArrayBuffer): string {
    return bytesToByteString(new Uint8Array(arrayBuffer))
}

export function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    return arrayBufferToBase64String(arrayBuffer).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}

export function base64UrlToUint8Array(b64url: string): Uint8Array {
    return base64StringToUint8Array(b64url.replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""))
}

export function textToBase64Url(str: string): string {
    const encoder = new TextEncoder()
    const charCodes = encoder.encode(str)
    const binaryStr = String.fromCharCode(...charCodes)

    return btoa(binaryStr).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}

export function getElement(seq: Uint8Array): x509Element[] {
    const result = []
    let next = 0

    while (next < seq.length) {
        const nextPart = parseElement(seq.subarray(next))
        result.push(nextPart)
        next += nextPart.byteLength
    }
    return result
}

export function parseElement(bytes: Uint8Array): x509Element {
    let position = 0

    // tag
    let tag = bytes[0] & 0x1f
    position++
    if (tag === 0x1f) {
        tag = 0
        while (bytes[position] >= 0x80) {
            tag = tag * 128 + bytes[position] - 0x80
            position++
        }
        tag = tag * 128 + bytes[position] - 0x80
        position++
    }

    // length
    let length = 0
    if (bytes[position] < 0x80) {
        length = bytes[position]
        position++
    } else if (length === 0x80) {
        length = 0

        while (bytes[position + length] !== 0 || bytes[position + length + 1] !== 0) {
            if (length > bytes.byteLength) {
                throw new TypeError('invalid indefinite form length')
            }
            length++
        }

        const byteLength = position + length + 2
        return {
            byteLength,
            contents: bytes.subarray(position, position + length),
            raw: bytes.subarray(0, byteLength),
        }
    } else {
        const numberOfDigits = bytes[position] & 0x7f
        position++
        length = 0
        for (let i = 0; i < numberOfDigits; i++) {
            length = length * 256 + bytes[position]
            position++
        }
    }

    const byteLength = position + length
    return {
        byteLength,
        contents: bytes.subarray(position, byteLength),
        raw: bytes.subarray(0, byteLength),
    }
}

export function x509toSpki(buf: Uint8Array): Uint8Array {
    const tbsCertificate = getElement(getElement(parseElement(buf).contents)[0].contents)
    return tbsCertificate[tbsCertificate[0].raw[0] === 0xa0 ? 6 : 5].raw
}

export function pemToBinary(pem: string): Uint8Array {
    return base64StringToUint8Array(pem.replace(/-+(BEGIN|END).*/g, "").replace(/\s/g, ""))
}

export async function importTextSecret(key: string, algorithm: SubtleCryptoImportKeyAlgorithm, keyUsages: KeyUsages[]): Promise<CryptoKey> {
    return await crypto.subtle.importKey("raw", textToUint8Array(key), algorithm, true, keyUsages)
}

export async function importJwk(key: JsonWebKeyWithKid, algorithm: SubtleCryptoImportKeyAlgorithm, keyUsages: KeyUsages[]): Promise<CryptoKey> {
    return await crypto.subtle.importKey("jwk", key, algorithm, true, keyUsages)
}

export async function importPublicKey(key: string, algorithm: SubtleCryptoImportKeyAlgorithm, keyUsages: KeyUsages[]): Promise<CryptoKey> {
    return await crypto.subtle.importKey("spki", pemToBinary(key), algorithm, true, keyUsages)
}

export async function importPrivateKey(key: string, algorithm: SubtleCryptoImportKeyAlgorithm, keyUsages: KeyUsages[]): Promise<CryptoKey> {
    return await crypto.subtle.importKey("pkcs8", pemToBinary(key), algorithm, true, keyUsages)
}

export async function importX509PublicKey(key: string, algorithm: SubtleCryptoImportKeyAlgorithm, keyUsages: KeyUsages[]): Promise<CryptoKey> {
    return await crypto.subtle.importKey("spki", x509toSpki(pemToBinary(key)), algorithm, true, keyUsages)
}

export async function importKey(key: string | JsonWebKeyWithKid, algorithm: SubtleCryptoImportKeyAlgorithm, keyUsages: KeyUsages[]): Promise<CryptoKey> {
    if (typeof key === "object")
        return importJwk(key, algorithm, keyUsages)

    if (typeof key !== "string")
        throw new Error("Unsupported key type!")

    if (key.includes("PUBLIC"))
        return importPublicKey(key, algorithm, keyUsages)

    if (key.includes("PRIVATE"))
        return importPrivateKey(key, algorithm, keyUsages)

    if (key.includes("-----BEGIN CERTIFICATE-----"))
        return importX509PublicKey(key, algorithm, keyUsages)

    return importTextSecret(key, algorithm, keyUsages)
}

export function decodePayload<T = any>(raw: string): T | undefined {
    try {
        const bytes = Array.from(atob(raw), char => char.charCodeAt(0));
        const decodedString = new TextDecoder("utf-8").decode(new Uint8Array(bytes));

        return JSON.parse(decodedString);
    } catch {
        return
    }
}