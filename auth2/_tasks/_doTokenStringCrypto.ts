import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";

/**
 * Encrypts a UTF-8 plaintext string using AES-256-GCM.
 *
 * Implementation details:
 * - Derives a 32-byte key by hashing the environment variable VET_CLIENT_SECRET with SHA-256.
 * - Generates a cryptographically secure random 12-byte IV (nonce) for GCM.
 * - Encrypts the plaintext with AES-256-GCM and includes the authentication tag.
 * - Returns a single string in the format "iv:ciphertext:tag", where each component is base64-encoded.
 *
 * Behavior:
 * - If VET_CLIENT_SECRET is not set or an error occurs during encryption, the function logs the error and returns false.
 * - The returned value contains the IV and auth tag necessary for decryption; the secret key is not included.
 *
 * @param plainText - The UTF-8 encoded string to encrypt.
 * @returns The encrypted payload as "base64(iv):base64(ciphertext):base64(tag)", or false if an error occurred.
 */
const encrypt = (plainText: string) => {
    try {
        const secret = process.env.VET_CLIENT_SECRET;
        if (!secret) {
            throw new Error("VET_CLIENT_SECRET not set");
        }

        // derive a 32-byte key from the secret
        const key = createHash("sha256").update(secret).digest();

        // generate a random 12-byte IV for GCM
        const iv = randomBytes(12);

        // encrypt using AES-256-GCM
        const cipher = createCipheriv("aes-256-gcm", key, iv);
        const ciphertext = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
        const authTag = cipher.getAuthTag();

        // return "iv:ciphertext:tag" (base64)
        return `${iv.toString("base64")}:${ciphertext.toString("base64")}:${authTag.toString("base64")}`;
    } catch (error) {
        console.error("Error encrypting token:", error);
        return false;
    }
}

/**
 * Decrypts a token string produced by a corresponding encryptor that encodes
 * the IV, ciphertext, and optionally an authentication tag as base64, joined by ":".
 *
 * The function derives a 32-byte AES key by hashing the environment variable
 * VET_CLIENT_SECRET with SHA-256. It expects tokenString to be in one of two formats:
 * - "iv:ciphertext:tag" (three parts): decrypted using AES-256-GCM with the provided auth tag
 * - "iv:ciphertext" (two parts): decrypted using AES-256-CBC as a fallback (no auth tag)
 *
 * The IV, ciphertext, and tag (when present) must be base64-encoded. The decrypted
 * plaintext is returned as a UTF-8 string on success.
 *
 * Notes:
 * - If process.env.VET_CLIENT_SECRET is not set, or the tokenString format is invalid,
 *   the function logs an error and returns false.
 * - Any runtime decryption errors are caught, logged to console.error, and result in
 *   a return value of false (the function does not throw).
 *
 * @param tokenString - The encrypted token string in the format "iv:ciphertext" or "iv:ciphertext:tag",
 *                      where each part is base64-encoded.
 * @returns The decrypted UTF-8 plaintext on success, or false on failure.
 *
 * @example
 * // AES-GCM token: "<base64 iv>:<base64 ciphertext>:<base64 tag>"
 * const plaintextOrFalse = decrypt(tokenString);
 */
const decrypt = (tokenString: string) => {
    try {
        const secret = process.env.VET_CLIENT_SECRET;
        if (!secret) {
            throw new Error("VET_CLIENT_SECRET not set");
        }

        // derive a 32-byte key from the secret
        const key = createHash("sha256").update(secret).digest();

        // expect "iv:ciphertext:tag" (base64). If only "iv:ciphertext" is present, try CBC fallback.
        const parts = tokenString.split(":");
        if (parts.length < 2) {
            throw new Error("Encrypted token has invalid format");
        }

        const iv = Buffer.from(parts[0], "base64");
        const ciphertext = Buffer.from(parts[1], "base64");
        let decrypted: string;

        if (parts.length === 3) {
            // AES-256-GCM with auth tag
            const authTag = Buffer.from(parts[2], "base64");
            const decipher = createDecipheriv("aes-256-gcm", key, iv);
            decipher.setAuthTag(authTag);
            decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
        } else {
            // fallback to AES-256-CBC (no auth tag)
            const decipher = createDecipheriv("aes-256-cbc", key, iv);
            decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
        }

        return decrypted;
    } catch (error) {
        console.error("Error decrypting token:", error);
        return false;
    }
}

export function doTokenStringCrypto(tokenString: string, action: "encrypt" | "decrypt") {
    try {
        if (action === "encrypt") {
            return encrypt(tokenString);
        } else {
            return decrypt(tokenString);
        }
    } catch (error) {
        console.error("Error in crypto operation:", error);
        return false;
    }
}