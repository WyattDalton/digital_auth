import kv from "@/lib/kv";
import { doTokenStringCrypto } from "./_doTokenStringCrypto";

export async function setKvToken(tokenData: any) {
    try {
        if (tokenData === null || tokenData === undefined) {
            throw new Error("No token data provided to store");
        }

        // Convert json to string
        const tokenString = JSON.stringify(tokenData);
        if (!tokenString) {
            throw new Error("No token string to store");
        }

        // Encrypt the token string
        const encryptedToken = doTokenStringCrypto(tokenString, "encrypt");
        if (!encryptedToken || typeof encryptedToken !== "string") {
            throw new Error("Failed to encrypt token");
        }

        // Set the encrypted token in KV store
        await kv.set("vet-access-token", encryptedToken);
        return tokenData;

    } catch (error) {
        console.error("Error Setting token:", error);
        return false;
    }
}