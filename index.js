class Base64URL {
    static parse(s) {
        return new Uint8Array(Array.prototype.map.call(atob(s.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '')), c => c.charCodeAt(0)))
    }
    static stringify(a) {
        return btoa(String.fromCharCode.apply(0, a)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
    }
}

class JWT {
    constructor() {
        if (typeof crypto === 'undefined' || !crypto.subtle)
            throw new Error('Crypto not supported!')
        this.algorithms = {
            ES256: { name: 'ECDSA', namedCurve: 'P-256', hash: { name: 'SHA-256' } },
            ES384: { name: 'ECDSA', namedCurve: 'P-384', hash: { name: 'SHA-384' } },
            ES512: { name: 'ECDSA', namedCurve: 'P-521', hash: { name: 'SHA-512' } },
            HS256: { name: 'HMAC', hash: { name: 'SHA-256' } },
            HS384: { name: 'HMAC', hash: { name: 'SHA-384' } },
            HS512: { name: 'HMAC', hash: { name: 'SHA-512' } },
            RS256: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } },
            RS384: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } },
            RS512: { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } },
        }
    }
    _utf8ToUint8Array(str) {
        return Base64URL.parse(btoa(unescape(encodeURIComponent(str))))
    }
    _str2ab(str) {
        const buf = new ArrayBuffer(str.length);
        const bufView = new Uint8Array(buf);
        for (let i = 0, strLen = str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
        }
        return buf;
    }
    _decodePayload(raw) {
        switch (raw.length % 4) {
            case 0:
                break
            case 2:
                raw += '=='
                break
            case 3:
                raw += '='
                break
            default:
                throw new Error('Illegal base64url string!')
        }
        try {
            return JSON.parse(decodeURIComponent(escape(atob(raw))))
        } catch {
            return null
        }
    }
    async sign(payload, secret, options = { algorithm: 'HS256', header: { typ: 'JWT' } }) {
        if (typeof options === 'string')
            options = { algorithm: options, header: { typ: 'JWT' } }
        if (payload === null || typeof payload !== 'object')
            throw new Error('payload must be an object')
        if (typeof secret !== 'string')
            throw new Error('secret must be a string')
        if (typeof options.algorithm !== 'string')
            throw new Error('options.algorithm must be a string')
        const importAlgorithm = this.algorithms[options.algorithm]
        if (!importAlgorithm)
            throw new Error('algorithm not found')
        payload.iat = Math.floor(Date.now() / 1000)
        const payloadAsJSON = JSON.stringify(payload)
        const partialToken = `${Base64URL.stringify(this._utf8ToUint8Array(JSON.stringify({ ...options.header, alg: options.algorithm, kid: options.keyid })))}.${Base64URL.stringify(this._utf8ToUint8Array(payloadAsJSON))}`
        let keyFormat = 'raw'
        let keyData
        if (secret.startsWith('-----BEGIN')) {
            keyFormat = 'pkcs8'
            keyData = this._str2ab(atob(secret.replace(/-----BEGIN.*?-----/g, '').replace(/-----END.*?-----/g, '').replace(/\s/g, '')))
        } else
            keyData = this._utf8ToUint8Array(secret)
        const key = await crypto.subtle.importKey(keyFormat, keyData, importAlgorithm, false, ['sign'])
        const signature = await crypto.subtle.sign(importAlgorithm, key, this._utf8ToUint8Array(partialToken))
        return `${partialToken}.${Base64URL.stringify(new Uint8Array(signature))}`
    }
    async verify(token, secret, options = { algorithm: 'HS256', throwError: false }) {
        if (typeof options === 'string')
            options = { algorithm: options }
        if (typeof token !== 'string')
            throw new Error('token must be a string')
        if (typeof secret !== 'string')
            throw new Error('secret must be a string')
        if (typeof options.algorithm !== 'string')
            throw new Error('options.algorithm must be a string')
        const tokenParts = token.split('.')
        if (tokenParts.length !== 3)
            throw new Error('token must consist of 3 parts')
        const importAlgorithm = this.algorithms[options.algorithm]
        if (!importAlgorithm)
            throw new Error('algorithm not found')
        const payload = this.decode(token)
        if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000)) {
            if (options.throwError)
                throw 'NOT_YET_VALID'
            return false
        }
        if (payload.exp && payload.exp <= Math.floor(Date.now() / 1000)) {
            if (options.throwError)
                throw 'EXPIRED'
            return false
        }
        let keyFormat = 'raw'
        let keyData
        if (secret.startsWith('-----BEGIN')) {
            keyFormat = 'spki'
            keyData = this._str2ab(atob(secret.replace(/-----BEGIN.*?-----/g, '').replace(/-----END.*?-----/g, '').replace(/\s/g, '')))
        } else
            keyData = this._utf8ToUint8Array(secret)
        const key = await crypto.subtle.importKey(keyFormat, keyData, importAlgorithm, false, ['verify'])
        return await crypto.subtle.verify(importAlgorithm, key, Base64URL.parse(tokenParts[2]), this._utf8ToUint8Array(`${tokenParts[0]}.${tokenParts[1]}`))
    }
    decode(token) {
        return {
            header: this._decodePayload(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')),
            payload: this._decodePayload(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
        }
    }
}

module.exports = new JWT
