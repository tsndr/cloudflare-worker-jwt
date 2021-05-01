declare class JWT {
    sign(payload: object, secret: string, algorithm?: "HS256" | "HS512"): Promise<string>
    verify(token: string, secret: string, algorithm?: "HS256" | "HS512"): Promise<boolean>
    decode(token: string): object | null
}
declare const _exports: JWT
export = _exports