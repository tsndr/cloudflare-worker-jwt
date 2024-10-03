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

    test("Valid", () => {
        expect(jwt.verify(validToken, secret, { throwError: true })).resolves.toBeTruthy()
    })

    test("Not yet expired", () => {
        expect(jwt.verify(notYetExpired, secret, { throwError: true })).resolves.toBeTruthy()
    })

    test("Not yet valid", () => {
        expect(jwt.verify(notYetValidToken, secret, { throwError: true })).rejects.toThrowError("NOT_YET_VALID")
    })

    test("Expired", () => {
        expect(jwt.verify(expiredToken, secret, { throwError: true })).rejects.toThrowError("EXPIRED")
    })

    test("Clock offset", () => {
        expect(jwt.verify(notYetValidToken, secret, { clockTolerance: offset, throwError: true })).resolves.toBeTruthy()
        expect(jwt.verify(expiredToken, secret, { clockTolerance: offset, throwError: true })).resolves.toBeTruthy()

        expect(jwt.verify(notYetValidToken, secret, { clockTolerance: offset - 1, throwError: true })).rejects.toThrowError("NOT_YET_VALID")
        expect(jwt.verify(expiredToken, secret, { clockTolerance: offset - 1, throwError: true })).rejects.toThrowError("EXPIRED")
    })
})