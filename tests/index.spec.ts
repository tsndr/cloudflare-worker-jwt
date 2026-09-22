import { describe, expect, test } from "vitest"
import jwt from "../src/index"

describe("Verify", async () => {
    const secret = "super-secret"

    const now = Math.floor(Date.now() / 1000)
    const offset = 30 // 30 seconds

    const validToken = await jwt.sign({ sub: "me", nbf: now - offset }, secret)
    const notYetExpired = await jwt.sign({ sub: "me", exp: now + offset }, secret)

    const notYetValidToken = await jwt.sign({ sub: "me", nbf: now + offset }, secret)
    const expiredToken = await jwt.sign({ sub: "me", exp: now - offset }, secret)

    test("Valid", async () => {
        await expect(jwt.verify(validToken, secret, { throwError: true })).resolves.toBeTruthy()
    })

    test("Not yet expired", async () => {
        await expect(jwt.verify(notYetExpired, secret, { throwError: true })).resolves.toBeTruthy()
    })

    test("Not yet valid", async () => {
        await expect(jwt.verify(notYetValidToken, secret, { throwError: true })).rejects.toThrowError("NOT_YET_VALID")
    })

    test("Expired", async () => {
        await expect(jwt.verify(expiredToken, secret, { throwError: true })).rejects.toThrowError("EXPIRED")
    })

    test("Clock offset", async () => {
        await expect(jwt.verify(notYetValidToken, secret, { clockTolerance: offset, throwError: true })).resolves.toBeTruthy()
        await expect(jwt.verify(expiredToken, secret, { clockTolerance: offset + 1, throwError: true })).resolves.toBeTruthy()

        await expect(jwt.verify(notYetValidToken, secret, { clockTolerance: offset - 1, throwError: true })).rejects.toThrowError("NOT_YET_VALID")
        await expect(jwt.verify(expiredToken, secret, { clockTolerance: offset, throwError: true })).rejects.toThrowError("EXPIRED")
    })

    test("Expires exactly at exp", async () => {
        const nowToken = await jwt.sign({ sub: "me", exp: Math.floor(Date.now() / 1000) }, secret)
        await expect(jwt.verify(nowToken, secret, { throwError: true })).rejects.toThrowError("EXPIRED")
    })

    test("Non-ASCII secret is UTF-8 encoded", async () => {
        const utf8Secret = "密码-secret"
        const token = await jwt.sign({ sub: "me" }, utf8Secret)
        await expect(jwt.verify(token, utf8Secret, { throwError: true })).resolves.toBeTruthy()
        // Same low bytes as utf8Secret when truncated to 8 bits, so this must NOT verify.
        const collidingSecret = String.fromCharCode(0x1bc6, 0x1801) + "-secret"
        await expect(jwt.verify(token, collidingSecret, { throwError: true })).rejects.toThrowError("INVALID_SIGNATURE")
    })

    test("Large payload", async () => {
        const token = await jwt.sign({ sub: "me", data: "x".repeat(1_000_000) }, secret)
        await expect(jwt.verify(token, secret, { throwError: true })).resolves.toBeTruthy()
    })
})