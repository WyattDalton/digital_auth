// import kv from "@/lib/kv";
import { doTokenStringCrypto } from "./_doTokenStringCrypto";
import { createClient } from 'redis';

export async function getKvToken() {
    try {
        const redisUrl = process.env.REDIS_URL || 'redis://127.0.0.1:6379';
        const client = createClient({ url: redisUrl });
        client.on('error', (err) => console.error('Redis client error', err));
        await client.connect();
        console.log("> Fetching token from KV store at", redisUrl);

        const tokenString = await client.get("vet-access-token");
        if (!tokenString) {
            // clean disconnect and return false so caller can regenerate
            client.destroy();
            console.log("--> No token found in KV store.");
            return false;
        }
        const decryptedToken = doTokenStringCrypto(tokenString, "decrypt");
        if (!decryptedToken || typeof decryptedToken !== "string") {
            client.destroy();
            throw new Error("Failed to decrypt token");
        }

        const tokenData = JSON.parse(decryptedToken);
        client.destroy();
        return tokenData;

    } catch (error) {
        console.error("Error fetching token from KV store::", error);
        return false;
    }
}