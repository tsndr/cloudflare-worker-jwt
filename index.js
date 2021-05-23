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
        if (!crypto || !crypto.subtle)
            throw new Error('Crypto not supported!')
        this.algorithms = {
            HS256: {
                name: 'HMAC',
                hash: {
                    name: 'SHA-256'
                }
            },
            HS512: {
                name: 'HMAC',
                hash: {
                    name: 'SHA-512'
                }
            }
        }
    }
    _utf8ToUint8Array(str) {
        return Base64URL.parse(btoa(unescape(encodeURIComponent(str))))
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
    async sign(payload, secret, algorithm = 'HS256') {
        if (payload === null || typeof payload !== 'object')
            throw new Error('payload must be an object')
        if (typeof secret !== 'string')
            throw new Error('secret must be a string')
        if (typeof algorithm !== 'string')
            throw new Error('algorithm must be a string')
        const importAlgorithm = this.algorithms[algorithm]
        if (!importAlgorithm)
            throw new Error('algorithm not found')
        payload.iat = Math.floor(Date.now() / 1000)
        const payloadAsJSON = JSON.stringify(payload)
        const partialToken = `${Base64URL.stringify(this._utf8ToUint8Array(JSON.stringify({ alg: algorithm, typ: 'JWT' })))}.${Base64URL.stringify(this._utf8ToUint8Array(payloadAsJSON))}`
        const key = await crypto.subtle.importKey('raw', this._utf8ToUint8Array(secret), importAlgorithm, false, ['sign'])
        const characters = payloadAsJSON.split('')
        const it = this._utf8ToUint8Array(payloadAsJSON).entries()
        let i = 0
        const result = []
        let current
        while (!(current = it.next()).done) {
            result.push([current.value[1], characters[i]])
            i++
        }
        const signature = await crypto.subtle.sign(importAlgorithm.name, key, this._utf8ToUint8Array(partialToken))
        return `${partialToken}.${Base64URL.stringify(new Uint8Array(signature))}`
    }
    async verify(token, secret, algorithm = 'HS256') {
        if (typeof token !== 'string')
            throw new Error('token must be a string')
        if (typeof secret !== 'string')
            throw new Error('secret must be a string')
        if (typeof algorithm !== 'string')
            throw new Error('algorithm must be a string')
        const tokenParts = token.split('.')
        if (tokenParts.length !== 3)
            throw new Error('token must have 3 parts')
        const importAlgorithm = this.algorithms[algorithm]
        if (!importAlgorithm)
            throw new Error('algorithm not found')
        const keyData = this._utf8ToUint8Array(secret)
        const key = await crypto.subtle.importKey('raw', keyData, importAlgorithm, false, ['sign'])
        const partialToken = tokenParts.slice(0, 2).join('.')
        const payload = this._decodePayload(tokenParts[1].replace(/-/g, '+').replace(/_/g, '/'))
        if (payload.nbf && payload.nbf >= Math.floor(Date.now() / 1000))
            return false
        if (payload.exp && payload.exp < Math.floor(Date.now() / 1000))
            return false
        const signaturePart = tokenParts[2]
        const messageAsUint8Array = this._utf8ToUint8Array(partialToken)
        const res = await crypto.subtle.sign(importAlgorithm.name, key, messageAsUint8Array)
        return Base64URL.stringify(new Uint8Array(res)) === signaturePart
    }
    decode(token) {
        return this._decodePayload(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))
    }
}

module.exports = new JWT
