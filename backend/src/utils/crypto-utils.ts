import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { config } from 'dotenv';

const PGP_ENCRYPTION_KEY = config().parsed?.PGP_ENCRYPTION_KEY;
if (!PGP_ENCRYPTION_KEY) {
    throw new Error('PGP_ENCRYPTION_KEY is not set in the environment variables.');
    process.exit(1);
}
const PGP_ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const PGP_ENCRYPTION_IV_LENGTH = 12;

export interface EncryptedPayload {
    iv: string;
    content: string;
    tag: string;
}

export function encryptPrivateKey(plainText: string): EncryptedPayload {
    if (!PGP_ENCRYPTION_KEY || PGP_ENCRYPTION_KEY.length !== 64) {
        throw new Error('Invalid PGP_KEY_ENCRYPTION_KEY: must be a 64-hex-character string (32 bytes). Length: ' + PGP_ENCRYPTION_KEY?.length);
    }

    const iv = randomBytes(PGP_ENCRYPTION_IV_LENGTH);
    const cipher = createCipheriv(PGP_ENCRYPTION_ALGORITHM, Buffer.from(PGP_ENCRYPTION_KEY, 'hex'), iv);

    const encrypted = Buffer.concat([
        cipher.update(plainText, 'utf8'),
        cipher.final(),
    ]);

    const tag = cipher.getAuthTag();

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex'),
        tag: tag.toString('hex'),
    };
}

export function decryptPrivateKey(payload: EncryptedPayload): string {
    if (!PGP_ENCRYPTION_KEY || PGP_ENCRYPTION_KEY.length !== 64) {
        throw new Error('Invalid PGP_KEY_ENCRYPTION_KEY: must be a 64-hex-character string (32 bytes).');
    }

    const decipher = createDecipheriv(
        PGP_ENCRYPTION_ALGORITHM,
        Buffer.from(PGP_ENCRYPTION_KEY, 'hex'),
        Buffer.from(payload.iv, 'hex')
    );
    decipher.setAuthTag(Buffer.from(payload.tag, 'hex'));

    const decrypted = Buffer.concat([
        decipher.update(Buffer.from(payload.content, 'hex')),
        decipher.final(),
    ]);

    return decrypted.toString('utf8');
}