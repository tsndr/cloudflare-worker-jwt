export type JwtAlgorithm = 'ES256' | 'ES384' | 'ES512' | 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512'

export type JwtAlgorithms = {
    [key: string]: SubtleCryptoImportKeyAlgorithm
}

export type JwtHeader<T = {}> = {
    /**
     * Type (default: `"JWT"`)
     *
     * @default "JWT"
     */
    typ?: string
} & T

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
} & T;

export type JwtOptions = {
    algorithm?: JwtAlgorithm | string
}

export type JwtSignOptions<T> = {
    header?: JwtHeader<T>
} & JwtOptions

export type JwtVerifyOptions = {
    /**
     * If `true` throw error if checks fail. (default: `false`)
     *
     * @default false
    */
    throwError?: boolean
} & JwtOptions

export type JwtData<Payload = {}, Header = {}> = {
    header?: JwtHeader<Header>
    payload?: JwtPayload<Payload>
}
