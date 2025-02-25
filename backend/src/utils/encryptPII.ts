import { createCipheriv, createDecipheriv, randomBytes } from "crypto";
import { EncryptedPayload } from "./crypto-utils";

if (!process.env.PII_ENCRYPTION_KEY) {
    throw new Error('PII_ENCRYPTION_KEY environment variable is not set');
}
const key = Buffer.from(process.env.PII_ENCRYPTION_KEY, "hex");
const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;

export function encryptPII(plainText): EncryptedPayload {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, key, iv);
    const encrypted = Buffer.concat([
        cipher.update(plainText, 'utf8'),
        cipher.final()
    ]);
    const tag = cipher.getAuthTag();

    return {
        content: encrypted.toString('hex'),
        iv: iv.toString('hex'),
        tag: tag.toString('hex'),
    };
}

export function decryptPII(payload: EncryptedPayload | string): string {
    let data: EncryptedPayload;
    if (typeof payload === 'string') {
        try {
            data = JSON.parse(payload);
            // console.log('Decrypting the following payload: ', data);
        } catch (error) {
            // console.error('Failed to parse the encrypted payload as JSON:', error);
            throw new Error('Failed to parse the encrypted payload as JSON.');
        }
    } else {
        data = payload;
    }

    const decipher = createDecipheriv(
        ALGORITHM,
        key,
        Buffer.from(data.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(data.tag, 'hex'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(data.content, 'hex')),
        decipher.final(),
    ]);

    // console.log('Decrypted:', decrypted.toString('utf8'));
    return decrypted.toString('utf8');
}
