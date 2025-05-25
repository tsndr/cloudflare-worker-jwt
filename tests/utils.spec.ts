import { describe, expect, test } from "vitest"
import {
    bytesToByteString,
    byteStringToBytes,
    arrayBufferToBase64String,
    base64StringToUint8Array,
    textToUint8Array,
    arrayBufferToText,
    arrayBufferToBase64Url,
    base64UrlToUint8Array,
    textToBase64Url,
    pemToBinary,
    importTextSecret
} from "../src/utils"

describe("Converters", () => {
    const testString = "cloudflare-worker-jwt"
    const testByteArray = [ 99, 108, 111, 117, 100, 102, 108, 97, 114, 101, 45, 119, 111, 114, 107, 101, 114, 45, 106, 119, 116 ]
    const testUint8Array = new Uint8Array(testByteArray)
    const testBase64String = "Y2xvdWRmbGFyZS13b3JrZXItand0"
    const testArrayBuffer = testUint8Array

    test("bytesToByteString", () => {
        expect(bytesToByteString(testUint8Array)).toStrictEqual(testString)
    })

    test("byteStringToBytes", () => {
        expect(byteStringToBytes(testString)).toStrictEqual(testUint8Array)
    })

    test("arrayBufferToBase64String", () => {
        expect(arrayBufferToBase64String(testArrayBuffer)).toStrictEqual(testBase64String)
    })

    test("base64StringToArrayBuffer", () => {
        expect(base64StringToUint8Array(testBase64String)).toStrictEqual(testArrayBuffer)
    })

    test("textToArrayBuffer", () => {
        expect(textToUint8Array(testString)).toStrictEqual(testUint8Array)
    })

    test("arrayBufferToText", () => {
        expect(arrayBufferToText(testArrayBuffer)).toStrictEqual(testString)
    })

    test("arrayBufferToBase64Url", () => {
        expect(arrayBufferToBase64Url(testArrayBuffer)).toStrictEqual(testBase64String)
    })

    test("base64UrlToArrayBuffer", () => {
        expect(base64UrlToUint8Array(testBase64String)).toStrictEqual(testArrayBuffer)
    })

    test("textToBase64Url", () => {
        expect(textToBase64Url(testString)).toStrictEqual(testBase64String)
    })

    test("pemToBinary", () => {
        expect(pemToBinary(`-----BEGIN PUBLIC KEY-----\n${testBase64String}\n-----END PUBLIC KEY-----`)).toStrictEqual(testArrayBuffer)
    })
})

describe("Imports", () => {
    test("importTextSecret", async () => {
        const testKey = "cloudflare-worker-jwt"
        const testAlgorithm = { name: "HMAC", hash: { name: "SHA-256" } }
        const testCryptoKey = { type: "secret", extractable: true, algorithm: { ...testAlgorithm, length: 168 }, usages: ["verify", "sign"] }

        await expect(importTextSecret(testKey, testAlgorithm, ["verify", "sign"])).resolves.toMatchObject(testCryptoKey)
    })

    test.todo("importJwk")
    test.todo("importPublicKey")
    test.todo("importPrivateKey")
    test.todo("importKey")
})

describe.todo("Payload", () => {
    test.todo("decodePayload")
})