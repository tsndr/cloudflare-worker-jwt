import {
    textToArrayBuffer,
    arrayBufferToBase64Url,
    base64UrlToArrayBuffer,
    textToBase64Url,
    importKey,
    decodePayload
} from "./utils"

if (typeof crypto === 'undefined' || !crypto.subtle)
    throw new Error('SubtleCrypto not supported!')

/**
 * @typedef JwtAlgorithm
 * @type {'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512'}
 */
export type JwtAlgorithm = 'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512'

/**
 * @typedef JwtAlgorithms
 */
export type JwtAlgorithms = {
    [key: string]: SubtleCryptoImportKeyAlgorithm
}

/**
 * @typedef JwtHeader
 * @prop {string} [typ] Type
 */
export type JwtHeader<T = {}> = {
    /**
     * Type (default: `"JWT"`)
     *
     * @default "JWT"
     */
    typ?: string

    /**
     * Algorithm (default: `"HS256"`)
     *
     * @default "HS256"
     */
    alg?: JwtAlgorithm
} & T

/**
 * @typedef JwtPayload
 * @prop {string} [iss] Issuer
 * @prop {string} [sub] Subject
 * @prop {string | string[]} [aud] Audience
 * @prop {string} [exp] Expiration Time
 * @prop {string} [nbf] Not Before
 * @prop {string} [iat] Issued At
 * @prop {string} [jti] JWT ID
 */
export type JwtPayload<T = { [key: string]: any }> = {
    /** Issuer */
    iss?: string

    /** Subject */
    sub?: string

    /** Audience */
    aud?: string | string[]

    /** Expiration Time */
    exp?: number

    /** Not Before */
    nbf?: number

    /** Issued At */
    iat?: number

    /** JWT ID */
    jti?: string
} & T

/**
 * @typedef JwtOptions
 * @prop {JwtAlgorithm | string} algorithm
 */
export type JwtOptions = {
    algorithm?: JwtAlgorithm | string
}

/**
 * @typedef JwtSignOptions
 * @extends JwtOptions
 * @prop {JwtHeader} [header]
 */
export type JwtSignOptions<T> = {
    header?: JwtHeader<T>
} & JwtOptions

/**
 * @typedef JwtVerifyOptions
 * @extends JwtOptions
 * @prop {boolean} [throwError=false] If `true` throw error if checks fail. (default: `false`)
 */
export type JwtVerifyOptions = {
    /**
    * Clock tolerance to help with slightly out of sync systems
    */
    clockTolerance?: number

    /**
     * If `true` throw error if checks fail. (default: `false`)
     *
     * @default false
    */
    throwError?: boolean
} & JwtOptions

/**
 * @typedef JwtData
 * @prop {JwtHeader} header
 * @prop {JwtPayload} payload
 */
export type JwtData<Payload = {}, Header = {}> = {
    header?: JwtHeader<Header>
    payload?: JwtPayload<Payload>
}

const algorithms: JwtAlgorithms = {
    ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
    ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } },
    ES512: { name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-512' } },
    HS256: { name: 'HMAC', hash: { name: 'SHA-256' } },
    HS384: { name: 'HMAC', hash: { name: 'SHA-384' } },
    HS512: { name: 'HMAC', hash: { name: 'SHA-512' } },
    RS256: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
    RS384: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } },
    RS512: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } }
}

/**
 * Signs a payload and returns the token
 *
 * @param {JwtPayload} payload The payload object. To use `nbf` (Not Before) and/or `exp` (Expiration Time) add `nbf` and/or `exp` to the payload.
 * @param {string | JsonWebKey | CryptoKey} secret A string which is used to sign the payload.
 * @param {JwtSignOptions | JwtAlgorithm | string} [options={ algorithm: 'HS256', header: { typ: 'JWT' } }] The options object or the algorithm.
 * @throws {Error} If there's a validation issue.
 * @returns {Promise<string>} Returns token as a `string`.
 */
export async function sign<Payload = {}, Header = {}>(payload: JwtPayload<Payload>, secret: string | JsonWebKey, options: JwtSignOptions<Header> | JwtAlgorithm = 'HS256'): Promise<string> {
    if (typeof options === 'string')
        options = { algorithm: options }

    options = { algorithm: 'HS256', header: { typ: 'JWT' } as JwtHeader<Header>, ...options }

    if (!payload || typeof payload !== 'object')
        throw new Error('payload must be an object')

    if (!secret || (typeof secret !== 'string' && typeof secret !== 'object'))
        throw new Error('secret must be a string, a JWK object or a CryptoKey object')

    if (typeof options.algorithm !== 'string')
        throw new Error('options.algorithm must be a string')

    const algorithm: SubtleCryptoImportKeyAlgorithm = algorithms[options.algorithm]

    if (!algorithm)
        throw new Error('algorithm not found')

    if (!payload.iat)
        payload.iat = Math.floor(Date.now() / 1000)

    const partialToken = `${textToBase64Url(JSON.stringify({ ...options.header, alg: options.algorithm }))}.${textToBase64Url(JSON.stringify(payload))}`

    const key = secret instanceof CryptoKey ? secret : await importKey(secret, algorithm, ['sign'])
    const signature = await crypto.subtle.sign(algorithm, key, textToArrayBuffer(partialToken))

    return `${partialToken}.${arrayBufferToBase64Url(signature)}`
}

/**
 * Verifies the integrity of the token and returns a boolean value.
 *
 * @param {string} token The token string generated by `jwt.sign()`.
 * @param {string | JsonWebKey | CryptoKey} secret The string which was used to sign the payload.
 * @param {JWTVerifyOptions | JWTAlgorithm} options The options object or the algorithm.
 * @throws {Error | string} Throws an error `string` if the token is invalid or an `Error-Object` if there's a validation issue.
 * @returns {Promise<boolean>} Returns `true` if signature, `nbf` (if set) and `exp` (if set) are valid, otherwise returns `false`.
 */
export async function verify(token: string, secret: string | JsonWebKey | CryptoKey, options: JwtVerifyOptions | JwtAlgorithm = 'HS256'): Promise<boolean> {
    if (typeof options === 'string')
        options = { algorithm: options }
    options = { algorithm: 'HS256', clockTolerance: 0, throwError: false, ...options }

    if (typeof token !== 'string')
        throw new Error('token must be a string')

    if (typeof secret !== 'string' && typeof secret !== 'object')
        throw new Error('secret must be a string, a JWK object or a CryptoKey object')

    if (typeof options.algorithm !== 'string')
        throw new Error('options.algorithm must be a string')

    const tokenParts = token.split('.')

    if (tokenParts.length !== 3)
        throw new Error('token must consist of 3 parts')

    const algorithm: SubtleCryptoImportKeyAlgorithm = algorithms[options.algorithm]

    if (!algorithm)
        throw new Error('algorithm not found')

    const { header, payload } = decode(token)

    if (header?.alg !== options.algorithm) {
        if (options.throwError)
            throw new Error('ALG_MISMATCH')
        return false
    }

    try {
        if (!payload)
            throw new Error('PARSE_ERROR')

        const now = Math.floor(Date.now() / 1000)

        if (payload.nbf && payload.nbf > now && Math.abs(payload.nbf - now) > (options.clockTolerance ?? 0))
            throw new Error('NOT_YET_VALID')

        if (payload.exp && payload.exp <= now && Math.abs(payload.exp - now) > (options.clockTolerance ?? 0))
            throw new Error('EXPIRED')

        const key = secret instanceof CryptoKey ? secret : await importKey(secret, algorithm, ['verify'])

        return await crypto.subtle.verify(algorithm, key, base64UrlToArrayBuffer(tokenParts[2]), textToArrayBuffer(`${tokenParts[0]}.${tokenParts[1]}`))
    } catch(err) {
        if (options.throwError)
            throw err
        return false
    }
}

/**
 * Returns the payload **without** verifying the integrity of the token. Please use `jwt.verify()` first to keep your application secure!
 *
 * @param {string} token The token string generated by `jwt.sign()`.
 * @returns {JwtData} Returns an `object` containing `header` and `payload`.
 */
export function decode<Payload = {}, Header = {}>(token: string): JwtData<Payload, Header> {
    return {
        header: decodePayload<JwtHeader<Header>>(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')),
        payload: decodePayload<JwtPayload<Payload>>(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
    }
}

export default {
    sign,
    verify,
    decode
}