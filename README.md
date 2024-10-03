# Cloudflare Worker JWT

A lightweight JWT implementation with ZERO dependencies for Cloudflare Workers.


## Contents

- [Install](#install)
- [Examples](#examples)
- [Usage](#usage)
    - [Sign](#sign)
    - [Verify](#verify)
    - [Decode](#decode)


## Install

```bash
npm i @tsndr/cloudflare-worker-jwt
```


## Examples
### Basic Example

```typescript
async () => {
    import jwt from "@tsndr/cloudflare-worker-jwt"

    // Create a token
    const token = await sign({
        sub: "1234",
        name: "John Doe",
        email: "john.doe@gmail.com"
    }, "secret")

    // Verify token
    const verifiedToken = await verify(token, "secret")

    // Abort if token isn't valid
    if (!verifiedToken)
        return

    // Access token payload
    const { payload } = verifiedToken

    // { sub: "1234", name: "John Doe", email: "john.doe@gmail.com" }
}
```


### Restrict Timeframe

```typescript
async () => {
    import jwt from "@tsndr/cloudflare-worker-jwt"

    // Create a token
    const token = await sign({
        sub: "1234",
        name: "John Doe",
        email: "john.doe@gmail.com",
        nbf: Math.floor(Date.now() / 1000) + (60 * 60),      // Not before: Now + 1h
        exp: Math.floor(Date.now() / 1000) + (2 * (60 * 60)) // Expires: Now + 2h
    }, "secret")

    // Verify token
    const verifiedToken = await verify(token, "secret") // false

    // Abort if token isn't valid
    if (!verifiedToken)
        return

    // Access token payload
    const { payload } = verifiedToken

    // { sub: "1234", name: "John Doe", email: "john.doe@gmail.com", ... }
}
```

## Usage

- [Sign](#sign)
- [Verify](#verify)
- [Decode](#decode)

<hr>

### Sign
#### `sign(payload, secret, [options])`

Signs a payload and returns the token.


#### Arguments

Argument                 | Type                                | Status   | Default     | Description
------------------------ | ----------------------------------- | -------- | ----------- | -----------
`payload`                | `object`                            | required | -           | The payload object. To use `nbf` (Not Before) and/or `exp` (Expiration Time) add `nbf` and/or `exp` to the payload.
`secret`                 | `string`, `JsonWebKey`, `CryptoKey` | required | -           | A string which is used to sign the payload.
`options`                | `string`, `object`                  | optional | `HS256`     | Either the `algorithm` string or an object.
`options.algorithm`      | `string`                            | optional | `HS256`     | See [Available Algorithms](#available-algorithms)
`options.header`         | `object`                            | optional | `undefined` | Extend the header of the resulting JWT.


#### `return`

Returns token as a `string`.


<hr>


### Verify
#### `verify(token, secret, [options])`

Verifies the integrity of the token.

Argument                 | Type                                | Status   | Default | Description
------------------------ | ----------------------------------- | -------- | ------- | -----------
`token`                  | `string`                            | required | -       | The token string generated by `sign()`.
`secret`                 | `string`, `JsonWebKey`, `CryptoKey` | required | -       | The string which was used to sign the payload.
`options`                | `string`, `object`                  | optional | `HS256` | Either the `algorithm` string or an object.
`options.algorithm`      | `string`                            | optional | `HS256` | See [Available Algorithms](#available-algorithms)
`options.clockTolerance` | `number`                            | optional | `0`     | Clock tolerance in seconds, to help with slighly out of sync systems.
`options.throwError`     | `boolean`                           | optional | `false` | By default this we will only throw integration errors, only set this to `true` if you want verification errors to be thrown as well.


#### `throws`

Throws integration errors and if `options.throwError` is set to `true` also throws `ALG_MISMATCH`, `NOT_YET_VALID`, `EXPIRED` or `INVALID_SIGNATURE`.


#### `return`

Returns the decoded token or `undefined`.

```typescript
{
    header: {
        alg: "HS256",
        typ: "JWT"
    },
    payload: {
        name: "John Doe",
        email: "john.doe@gmail.com"
    }
}
```


<hr>


### Decode
#### `decode(token)`

Just returns the decoded token **without** verifying verifying it. Please use `verify()` if you intend to verify it as well.

Argument    | Type     | Status   | Default | Description
----------- | -------- | -------- | ------- | -----------
`token`     | `string` | required | -       | The token string generated by `sign()`.


#### `return`

Returns an `object` containing `header` and `payload`:

```typescript
{
    header: {
        alg: "HS256",
        typ: "JWT"
    },
    payload: {
        name: "John Doe",
        email: "john.doe@gmail.com"
    }
}
```


### Available Algorithms

 - `ES256`, `ES384`, `ES512`
 - `HS256`, `HS384`, `HS512`
 - `RS256`, `RS384`, `RS512`