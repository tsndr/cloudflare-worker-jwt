const { subtle } = require('crypto').webcrypto;
Object.defineProperty(global, 'crypto', {
    value: {subtle}
})

const JWT = require("./index.js")
const oneDay = (60 * 60 * 24)
const now = Date.now() / 1000
const staticPayload = {
    "name": "John Doe",
    "iat": 1516239022
}
const missingIatPayload = {
    "name": "John Doe"
}
const validPayload = {
    "name": "John Doe",
    "iat": Math.floor(now - (oneDay / 2)),
    "nbf": Math.floor(now - (oneDay / 4)),
    "exp": Math.floor(now + (oneDay / 2))
}
const expiredPayload = {
    "name": "John Doe",
    "iat": Math.floor(now - (oneDay / 2)),
    "nbf": Math.floor(now - (oneDay / 4)),
    "exp": Math.floor(now - (oneDay / 8))
}
const notBeforePayload = {
    "name": "John Doe",
    "iat": Math.floor(now),
    "nbf": Math.floor(now + (oneDay / 4)),
    "exp": Math.floor(now + oneDay)
}

test.each`
    algorithm  | secret          | expectedToken
    ${"HS256"} | ${"the-secret"} | ${"eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.MrkOa4BhYkyOvbIRktZN03OnEbxpe2N6wcBs9jbO6Uk"}
    ${"HS384"} | ${"the-secret"} | ${"eyJhbGciOiJIUzM4NCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.qpN-I6iV-la9Azfww8vqPqsKL2-o-TBXQCjXGkv2K1Nimnx5DqAomxS4Eh3cTqWR"}
    ${"HS512"} | ${"the-secret"} | ${"eyJhbGciOiJIUzUxMiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.8qcHh9YDvpcwr1WP6NX8UlwkPsCR4ZniOYzcxo0kbwTdJq_S1MhubLHW4Jtj2bcegbm9yOHQEN_Hk3Yi6x-ZPg"}
`("encode a jwt payload", async ({ algorithm, secret, expectedToken }) => {
    expect(await JWT.sign(staticPayload, secret, { algorithm })).toEqual(expectedToken)
})

test.each`
    token
    ${"eyJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.MrkOa4BhYkyOvbIRktZN03OnEbxpe2N6wcBs9jbO6Uk"}
    ${"eyJhbGciOiJIUzM4NCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.qpN-I6iV-la9Azfww8vqPqsKL2-o-TBXQCjXGkv2K1Nimnx5DqAomxS4Eh3cTqWR"}
    ${"eyJhbGciOiJIUzUxMiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.8qcHh9YDvpcwr1WP6NX8UlwkPsCR4ZniOYzcxo0kbwTdJq_S1MhubLHW4Jtj2bcegbm9yOHQEN_Hk3Yi6x-ZPg"}
`("decode a jwt payload", ({ token }) => {
    const payload = JWT.decode(token)
    expect(payload).toEqual(staticPayload)
})

test.each`
    algorithm  | secret          | payload
    ${"HS256"} | ${"the-secret"} | ${missingIatPayload}
    ${"HS384"} | ${"the-secret"} | ${missingIatPayload}
    ${"HS512"} | ${"the-secret"} | ${missingIatPayload}
`("add iat field when missing from payload", async ({ algorithm, secret, payload }) => {
    const testStart = Math.floor(Date.now() / 1000)
    const token = await JWT.sign(payload, secret, { algorithm })
    expect(JWT.decode(token)).toHaveProperty("iat")
})

test.each`
    algorithm  | secret          | payload
    ${"HS256"} | ${"the-secret"} | ${validPayload}
    ${"HS384"} | ${"the-secret"} | ${validPayload}
    ${"HS512"} | ${"the-secret"} | ${validPayload}
`("verify valid jwt", async ({ algorithm, secret, payload }) => {
    const token = await JWT.sign(payload, secret, { algorithm })
    expect(await JWT.verify(token, secret, { algorithm })).toBeTruthy()
})

test.each`
    algorithm  | secret          | payload
    ${"HS256"} | ${"the-secret"} | ${validPayload}
    ${"HS384"} | ${"the-secret"} | ${validPayload}
    ${"HS512"} | ${"the-secret"} | ${validPayload}
`("verify jwt has invalid signature", async ({ algorithm, secret, payload }) => {
    const token = await JWT.sign(payload, secret, { algorithm })
    expect(await JWT.verify(token + "failbear", secret, { algorithm })).toBeFalsy()
})

test.each`
    algorithm  | secret          | payload
    ${"HS256"} | ${"the-secret"} | ${expiredPayload}
    ${"HS384"} | ${"the-secret"} | ${expiredPayload}
    ${"HS512"} | ${"the-secret"} | ${expiredPayload}
`("verify jwt is expired", async ({ algorithm, secret, payload }) => {
    const token = await JWT.sign(payload, secret, { algorithm })
    expect(await JWT.verify(token, secret, { algorithm })).toBeFalsy()
    expect(await JWT.verify(token, secret, { algorithm, ignoreExpiration: true })).toBeTruthy()
})

test.each`
    algorithm  | secret          | payload
    ${"HS256"} | ${"the-secret"} | ${notBeforePayload}
    ${"HS384"} | ${"the-secret"} | ${notBeforePayload}
    ${"HS512"} | ${"the-secret"} | ${notBeforePayload}
`("verify jwt can't be used yet (nbf)", async ({ algorithm, secret, payload }) => {
    const token = await JWT.sign(payload, secret, { algorithm })
    expect(await JWT.verify(token, secret, { algorithm })).toBeFalsy()
    expect(await JWT.verify(token, secret, { algorithm, ignoreNotBefore: true })).toBeTruthy()
})
