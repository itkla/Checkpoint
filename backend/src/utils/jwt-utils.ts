import { JWTPayload, SignJWT, jwtVerify } from 'jose';

const encoder = new TextEncoder();
const secret_key = encoder.encode(process.env.JWT_SECRET_KEY!);

export async function signToken(
    payload: JWTPayload,
    expiresIn = '60d'
): Promise<string> {
    return await new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256' })
        .setExpirationTime(expiresIn)
        .sign(secret_key);
}

/** Verify a JWT. Throws if invalid/expired. Returns the payload if valid. */
export async function verifyToken(token: string): Promise<any> {
    const { payload } = await jwtVerify(token, secret_key);
    return payload;
}

export async function decodeToken(token: string): Promise<JWTPayload> {
    const { payload } = await jwtVerify(token, secret_key);
    return payload;
}