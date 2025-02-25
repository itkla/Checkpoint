import { FastifyPluginAsync } from 'fastify';
import { z, ZodError } from 'zod';
import argon2 from 'argon2';
import { signToken, verifyToken, decodeToken } from '../utils/jwt-utils';
import { LoginSchema, LoginSchemaType } from '../types/LoginSchema';
import { UserSchema } from '../types/UserSchema';
import { AuthMethodIdParam } from '../types/AuthMethodIdParam';
import generateUUID from '../utils/generateUUID';
import * as openpgp from 'openpgp';
import { encryptPrivateKey, EncryptedPayload } from '../utils/crypto-utils';
import { pool, redis } from '../utils/db';
import { hasRole, hasPermission } from '../utils/roles';
import passport, {PassportUser} from '@fastify/passport';
import { encryptPII, decryptPII } from '../utils/encryptPII';
import {
    generateRegistrationOptions,
    generateAuthenticationOptions,
    verifyRegistrationResponse,
    verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
    RegistrationResponseJSON,
    AuthenticationResponseJSON,
} from '@simplewebauthn/types';
import {
    isoBase64URL,
} from '@simplewebauthn/server/helpers';

import { authenticator } from 'otplib';
import QRCode from 'qrcode';


const rpID = process.env.DOMAIN || 'localhost';

async function stringToBuffer(str: string): Promise<Uint8Array> {
    return new TextEncoder().encode(str);
}

export const authRoutes: FastifyPluginAsync = async (server, opts) => {
    server.post<{ Body: LoginSchemaType }>('/login', async (request, reply) => {
        try {
            const validated = LoginSchema.parse(request.body);
            const { email, password } = validated;

            const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            const user = result.rows[0];

            if (!user) {
                reply.code(401).send({ error: 'Invalid credentials' });
                return;
            }

            const authResult = await pool.query(
                'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2',
                [user.id, 'password']
            );
            const authMethod = authResult.rows[0];
            // console.log(authMethod);

            if (!authMethod || !(await argon2.verify(authMethod.metadata, password))) {
                reply.code(401).send({ error: 'Invalid credentials' });
                return;
            }

            const isAdmin = await hasRole(user.id, 'admin');
            // console.log(roles, isAdmin, user.id);

            // check to see if user has 2FA enabled
            if (user.two_factor_enabled) {
                const tempToken = await signToken({ userId: user.id, pending2FA: true });
                console.log('2FA required for user:', { userId: user.id, tempToken });
                await redis.set(`ryftsession:${tempToken}`, String(user.id), { EX: 60 * 60 * 24 * 60 }); // 60 days
                return reply.send({ twoFactorRequired: true, tempToken });
            }

            const token = await signToken(
                {
                    userId: user.id,
                    isAdmin,
                },
                // { expiresIn: '60d' }
            );
            await redis.set(`session:${token}`, String(user.id), {
                EX: 60 * 60 * 24 * 60 // 60 days;
            });

            reply
                .setCookie('checkpoint_jwt', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    path: '/',
                    // maxAge: 3600 // (optional) 1 hour in seconds
                })
                .send({ user: { id: user.id, email: user.email }, token });

            // const token = server.jwtUser.sign({ userId: user.id });
            // return { user: { id: user.id, email: user.email, name: user.name }, token };
        } catch (err) {
            if (err instanceof z.ZodError) {
                reply.code(400).send({ error: 'Invalid request', details: err.issues });
                return;
            }
            console.error('Login error:', err);
            reply.code(500).send({ error: 'An error occurred: ', details: err.message });
        }

    });

    /*
    | POST /register
    | Register a new user
    |
    | Expected params:
    | 
    */
    server.post('/register', async (request, reply) => {

        try {
            console.log('Received body data: ', request.body);
            const userBody = request.body as any;
            const parseResult = UserSchema.safeParse({
                ...userBody,
                profile: {
                    ...userBody.profile,
                    dateOfBirth: new Date(userBody.profile.dateOfBirth)
                },
            });
            if (!parseResult.success) {
                console.error(parseResult.error);
                throw new Error('Invalid request data');
            }
            const body = parseResult.data;
            console.log('Parsed body:', body);

            // const body = UserSchema.parse(request.body);
            // generate pgp keypair for user federation
            const { publicKey, privateKey } = await openpgp.generateKey({
                userIDs: [{ name: body.profile.last_name, email: body.email }],
                type: 'ecc',
                curve: 'curve25519Legacy',
                format: 'armored'
            });

            const encryptedPrivateKey: EncryptedPayload = encryptPrivateKey(privateKey);

            console.log(typeof body.profile.first_name); // should be "string"
            console.log(typeof body.profile.last_name);
            console.log(typeof body.profile.phone);
            console.log(typeof body.profile.address);

            const userId = await generateUUID();
            const user_dob = (body.profile.dateOfBirth as Date).toISOString();
            const insertFields = {
                id: userId,
                email: body.email,
                first_name: encryptPII(body.profile.first_name),
                last_name: encryptPII(body.profile.last_name),
                public_key: publicKey,
                private_key: encryptedPrivateKey,
                dateOfBirth: encryptPII(user_dob),
                phone_number: encryptPII(body.profile.phone),
                address: encryptPII(JSON.stringify(body.profile.address)),
            };

            console.log('Inserting user:', insertFields);
            const columns = Object.keys(insertFields);
            const values = Object.values(insertFields);
            const placeholders = columns.map((_, i) => `$${i + 1}`);
            const query = `INSERT INTO users (${columns.join(
                ', '
            )}) VALUES (${placeholders.join(
                ', '
            )}) RETURNING id, email`;
            const result = await pool.query(query, values);

            if (body.password) {
                if (body.password.startsWith('$argon2id')) {
                    await pool.query(
                        'INSERT INTO auth_methods (user_id, type, metadata) VALUES ($1, $2, $3)',
                        [result.rows[0].id, 'password', body.password]
                    );
                } else {
                    const hashedPassword = await argon2.hash(body.password);
                    await pool.query(
                        'INSERT INTO auth_methods (user_id, type, metadata) VALUES ($1, $2, $3)',
                        [result.rows[0].id, 'password', JSON.stringify(hashedPassword)]
                    );
                }
            }

            const token = await signToken(
                { userId: result.rows[0].id },
            );
            await redis.set(`session:${token}`, String(result.rows[0].id), {
                EX: 60 * 60 * 24 * 60 // 60 days;
            });

            reply
                .setCookie('checkpoint_jwt', token, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                })
                .send({ user: result.rows[0], token });
            // return { user: result.rows[0], token };
        } catch (err: any) {
            if (err.constraint === 'users_email_key') {
                reply.code(400);
                return { error: 'Email already exists' };
            } else if (err instanceof ZodError) {
                reply.code(400);
                return { error: 'Invalid request', details: err.issues };
            } else {
                console.error(err);
                throw err;
            }
        }
    });
    
    server.get('/authenticate', async (request, reply) => {
        try {
            const token = request.headers.authorization?.replace('Bearer ', '');
            if (!token) {
                reply.code(401).send({ error: 'No token provided' });
                return;
            }
            const user = await server.jwt.verify(token);
            return { user };
        } catch (err) {
            reply.code(401).send({ error: 'Unauthorized' });
        }
    });

    server.get('/available-methods', async (request, reply) => {
        const result = await pool.query('SELECT DISTINCT type FROM auth_methods');
        return { methods: result.rows.map(row => row.type) };
    });

    server.post('/password-reset', async (request, reply) => {
        const { email } = request.body as { email: string };
        try {
            const userResult = await pool.query(`SELECT id FROM users WHERE email = $1`, [email]);
            if (userResult.rowCount === 0) {
                return reply.send({ success: true });
            }
            const userId = userResult.rows[0].id;
            const resetToken = generateUUID();
            await pool.query(
                `INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
                [userId, resetToken]
            );

            // sendMail(user.email, `Your reset link: ${FRONTEND_URL}/reset?token=${resetToken}`)

            reply.send({ success: true });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    });

    server.post('/password-reset/complete', async (request, reply) => {
        const { token, newPassword } = request.body as { token: string; newPassword: string };

        try {
            const prResult = await pool.query(
                `SELECT user_id FROM password_resets WHERE token = $1 AND expires_at > NOW()`,
                [token]
            );
            if (prResult.rowCount === 0) {
                return reply.status(400).send({ error: 'Invalid or expired reset token' });
            }
            const userId = prResult.rows[0].user_id;
            const hashedPassword = await argon2.hash(newPassword);
            await pool.query(
                `UPDATE auth_methods
                SET hashed_password = $1
              WHERE user_id = $2
                AND type = 'password'`,
                [hashedPassword, userId]
            );
            await pool.query(`DELETE FROM password_resets WHERE token = $1`, [token]);

            reply.send({ success: true });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    });

    server.put('/change-password', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { oldPassword, newPassword } = request.body as {
                oldPassword: string;
                newPassword: string;
            };
            const userId = request.jwtUser.userId;

            console.log('changing password for user:', userId);

            try {
                const authMethodRes = await pool.query(
                    `SELECT metadata FROM auth_methods 
                WHERE user_id = $1 AND type = 'password'`,
                    [userId]
                );
                if (authMethodRes.rowCount === 0) {
                    return reply.status(400).send({ error: 'No password set' });
                }
                const currentHashedPassword = authMethodRes.rows[0].metadata;
                const validOld = await argon2.verify(currentHashedPassword, oldPassword);
                if (!validOld) {
                    return reply.status(401).send({ error: 'Incorrect old password' });
                }
                const newHashed = await argon2.hash(newPassword);
                console.log(authMethodRes.rows[0].metadata, newHashed, validOld);
                await pool.query(
                    `UPDATE auth_methods SET metadata = $1::jsonb WHERE user_id = $2 AND type = 'password'`,
                    [JSON.stringify(newHashed), userId]
                );
                console.log('password changed');
                reply.send({ success: true });
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.get('/sessions', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                const userId = request.jwtUser.userId;
                const sessions = [];
                const keys = await redis.keys(`session:*`);

                for (const key of keys) {
                    const storedUserId = await redis.get(key);
                    if (storedUserId === String(userId)) {
                        const token = key.replace('session:', '');

                        try {
                            const decoded = await decodeToken(token);
                            sessions.push({
                                id: token,
                                device: decoded.device || 'Unknown Device',
                                browser: decoded.browser || 'Unknown Browser',
                                location: decoded.location || 'Unknown Location',
                                lastActive: decoded.iat ? new Date(decoded.iat * 1000).toISOString() : new Date().toISOString(),
                                current: request.headers.authorization?.includes(token) || false
                            });
                        } catch (err) {
                            continue;
                        }
                    }
                }

                return { sessions };
            } catch (error) {
                reply.code(500).send({ error: 'Failed to fetch sessions' });
            }
        }
    });

    server.delete('/sessions/:sessionId', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                const { sessionId } = request.params as { sessionId: string };
                const userId = request.jwtUser.userId;
                const storedUserId = await redis.get(`session:${sessionId}`);
                if (!storedUserId || storedUserId !== String(userId)) {
                    return reply.code(403).send({ error: 'Session not found or unauthorized' });
                }
                await redis.del(`session:${sessionId}`);

                return { success: true };
            } catch (error) {
                reply.code(500).send({ error: 'Failed to revoke session' });
            }
        }
    });

    server.delete('/sessions', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                const userId = request.jwtUser.userId;
                const currentToken = request.headers.authorization?.replace('Bearer ', '');
                const keys = await redis.keys('session:*');

                for (const key of keys) {
                    const storedUserId = await redis.get(key);
                    const token = key.replace('session:', '');
                    if (storedUserId === String(userId) && token !== currentToken) {
                        await redis.del(key);
                    }
                }

                return { success: true };
            } catch (error) {
                reply.code(500).send({ error: 'Failed to revoke sessions' });
            }
        }
    });

    server.post('/sessions/revoke', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const userId = request.jwtUser.userId;
            if (!(await hasPermission(String(userId), 'sessions.revoke'))) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const { tokenId } = request.body as { tokenId: string };

            try {
                await redis.del(`session:${tokenId}`);
                reply.send({ success: true });
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });
    server.post<{ Body: { email: string } }>('/passkey/login/start', async (request, reply) => {
        try {
            const { email } = request.body;
            const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
            if (userResult.rowCount === 0) {
                reply.code(400).send({ error: 'User does not exist.' });
                return;
            }
            const user = userResult.rows[0];
            const credentialsResult = await pool.query(
                'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2',
                [user.id, 'passkey']
            );
            // const allowedCredentials = credentialsResult.rows.map((row) => {
            //     const metadata = row.metadata;
            //     return {
            //         id: String(metadata.credentialID),
            //         // transports: ['internal'] as unknown as AuthenticatorTransport[],
            //     };
            // });
            const allowedCredentials = [];
            const options = await generateAuthenticationOptions({
                rpID,
                allowCredentials: allowedCredentials,
                userVerification: 'preferred',
            });
            await redis.set(`authentication_${user.id}`, options.challenge, { EX: 300 });
            reply.send(options);
        } catch (error) {
            console.error('Passkey login start error:', error);
            reply.code(500).send({
                error: 'Failed to start passkey login',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });


    server.post<{ Body: { email: string, response: AuthenticationResponseJSON } }>('/passkey/login/complete', async (request, reply) => {
        const { email, response } = request.body;
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rowCount === 0) {
            console.log('User does not exist:', email);
            reply.code(400).send({ error: 'User does not exist.' });
            return;
        }
        const user = userResult.rows[0];
        const expectedChallenge = await redis.get(`authentication_${user.id}`);
        if (!expectedChallenge) {
            console.log('Authentication session expired or invalid:', user.id);
            reply.code(400).send({ error: 'Authentication session expired or invalid.' });
            return;
        }

        try {
            if (!response || !response.id) {
                reply.code(400).send({ error: 'Missing credential id in response' });
                return;
            }

            console.log('Raw credential id:', response.id);
            const normalizedCredentialId = Buffer.from(response.id).toString('base64url');
            console.log('Normalized credential id:', normalizedCredentialId);
            const credentialResult = await pool.query(
                'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2 AND metadata->>\'credentialID\' = $3',
                [user.id, 'passkey', normalizedCredentialId]
            );
            if (credentialResult.rowCount === 0) {
                reply.code(400).send({ error: 'Invalid credential provided.' });
                return;
            }
            const storedCredential = credentialResult.rows[0].metadata;
            const verification = await verifyAuthenticationResponse({
                response,
                expectedChallenge,
                expectedOrigin: process.env.FRONTEND_URL || 'https://localhost:3000',
                expectedRPID: process.env.DOMAIN || 'localhost',
                credential: {
                    id: response.id,
                    publicKey: isoBase64URL.toBuffer(storedCredential.publicKey),
                    counter: storedCredential.counter,
                    transports: ['internal'],
                }
            });

            if (verification.verified) {
                console.log('Passkey authentication successful:', verification);
                const isAdmin = await hasRole(user.id, 'admin');

                const token = await signToken(
                    {
                        userId: user.id,
                        isAdmin,
                    }
                );

                await redis.set(`session:${token}`, String(user.id), {
                    EX: 60 * 60 * 24 * 60 // 60 days
                });
                await redis.del(`authentication_${user.id}`);

                reply
                    .setCookie('checkpoint_jwt', token, {
                        httpOnly: true,
                        secure: process.env.NODE_ENV === 'production',
                    })
                    .send({ success: true, token });
                // reply.send({success: true, token });
            } else {
                reply.code(400).send({ error: 'Authentication failed.' });
                console.log('Authentication failed:', verification);
            }
        } catch (err) {
            console.error('Passkey error:', err);
            reply.code(400).send({ error: 'Invalid authentication response.' });
        }
    });

    server.post('/passkey/register/start', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                const { userId } = request.jwtUser; // Get the authenticated user's ID
                const { name } = request.body as { name: string };

                if (!name) {
                    return reply.code(400).send({ error: 'Name is required' });
                }
                const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
                if (userResult.rowCount === 0) {
                    return reply.code(404).send({ error: 'User not found' });
                }
                const user = userResult.rows[0];

                const userIdBuffer = await stringToBuffer(user.id);

                console.log('Generating registration options...');
                const options = await generateRegistrationOptions({
                    rpName: 'Checkpoint',
                    rpID: process.env.DOMAIN || 'localhost',
                    userID: userIdBuffer,
                    userName: user.email,
                    attestationType: 'none',
                    authenticatorSelection: {
                        residentKey: 'preferred',
                        userVerification: 'preferred',
                        authenticatorAttachment: 'platform',
                    },
                });

                console.log('Generated options:', options);
                await redis.set(
                    `passkey_challenge:${user.id}`,
                    options.challenge,
                    { EX: 300 } // 5 minute expiration
                );

                return reply.send(options);
            } catch (error) {
                console.error('Passkey registration start error:', error);
                return reply.code(500).send({
                    error: 'Failed to start registration',
                    details: error instanceof Error ? error.message : 'Unknown error'
                });
            }
        }
    });

    server.options('/passkey/register/start', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {

            const { userId } = request.jwtUser; // Get the authenticated user's ID
            const { name } = request.body as { name: string };
            const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
            if (userResult.rowCount === 0) {
                return reply.code(404).send({ error: 'User not found' });
            }
            const user = userResult.rows[0];
            const options = await generateRegistrationOptions({
                rpName: 'Your App Name',
                rpID: process.env.DOMAIN || 'localhost',
                userID: user.id,
                userName: user.email,
                attestationType: 'none',
                authenticatorSelection: {
                    residentKey: 'preferred',
                    userVerification: 'preferred',
                    authenticatorAttachment: 'platform',
                },
            });

        }
    });

    server.post('/passkey/register/complete', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                const { userId } = request.jwtUser;
                const expectedChallenge = await redis.get(`passkey_challenge:${userId}`);
                if (!expectedChallenge) {
                    return reply.code(400).send({ error: 'Challenge expired or invalid' });
                }
                try {
                    const verification = await verifyRegistrationResponse({
                        response: request.body as RegistrationResponseJSON,
                        expectedChallenge,
                        expectedOrigin: process.env.FRONTEND_URL || 'https://localhost:3000',
                        expectedRPID: process.env.DOMAIN || 'localhost',
                        // attestationType: 'none',
                        // authenticatorSelection: {
                        //     userVerification: 'preferred'
                        // },
                    });

                    if (verification.verified) {
                        const { id: credentialID, publicKey: credentialPublicKey } = verification.registrationInfo.credential;
                        await pool.query(
                            `INSERT INTO auth_methods (user_id, type, metadata) 
                             VALUES ($1, $2, $3)`,
                            [
                                userId,
                                'passkey',
                                {
                                    credentialID: Buffer.from(credentialID).toString('base64url'),
                                    publicKey: Buffer.from(credentialPublicKey).toString('base64url'),
                                    name: (request.body as { name: string }).name,
                                },
                            ]
                        );

                        await redis.del(`passkey_challenge:${userId}`);
                        reply.send({ verified: true });
                    } else {
                        reply.code(400).send({ error: 'Registration failed' });
                    }
                } catch (err) {
                    reply.code(400).send({ error: 'Invalid registration response' });
                }
            } catch (error) {
                console.error('Passkey registration complete error:', error);
                return reply.code(500).send({ error: 'Failed to complete registration' });
            }
        }
    });

    server.get('/passkey', {
        preHandler: [server.authenticate]
    }, async (request, reply) => {
        try {
            const { userId } = request.jwtUser;

            const result = await pool.query(
                `SELECT id, metadata, created_at 
               FROM auth_methods 
               WHERE user_id = $1 AND type = 'passkey'`,
                [userId]
            );

            return reply.send(result.rows.map(row => ({
                id: row.id,
                credentialId: row.metadata.credentialID,
                name: row.metadata.name,
                createdAt: row.created_at,
                lastUsed: row.metadata.lastUsed,
            })));
        } catch (error) {
            console.error('Error fetching passkeys:', error);
            return reply.code(500).send({
                error: 'Failed to fetch passkeys',
                details: error instanceof Error ? error.message : 'Unknown error'
            });
        }
    });

    server.delete('/passkey/:credentialId', {
        preHandler: [server.authenticate]
    }, async (request, reply) => {
        const { userId } = request.jwtUser;
        const { credentialId } = request.params as AuthMethodIdParam;
        const formattedCredentialId = Buffer.from(credentialId, 'utf8');
        const result = await pool.query(
            'DELETE FROM auth_methods WHERE user_id = $1 AND type = $2 AND metadata->>\'credentialID\' = $3',
            [userId, 'passkey', formattedCredentialId]
        );
        if (result.rowCount === 0) {
            reply.code(404).send({ error: 'Passkey not found' });
            return;
        }
        return { success: true };
    });

    server.post('/2fa/setup', { onRequest: [server.authenticate] }, async (request, reply) => {
        try {
            const { userId, email } = request.jwtUser;
            const recovery_codes = Array.from({ length: 10 }, () => Math.floor(Math.random() * 1000000).toString().padStart(6, '0'));
            const secret = authenticator.generateSecret();
            const otpauth = authenticator.keyuri(email, process.env.APP_NAME, secret);
            console.log('Setting up 2FA for user:', userId, otpauth);
            const qrCodeDataURL = await QRCode.toDataURL(otpauth);
            const existingResult = await pool.query('SELECT * FROM user_2fa WHERE user_id = $1', [userId]);
            if (existingResult.rowCount > 0) {
                await pool.query('DELETE FROM user_2fa WHERE user_id = $1', [userId]);
            }
            await pool.query(
                'INSERT INTO user_2fa (user_id, totp_secret, recovery_codes) VALUES ($1, $2, $3::jsonb)',
                [userId, secret, JSON.stringify(recovery_codes)]
            );
    
            reply.send({ qrCodeDataURL, otpauth, recovery_codes });
        } catch (error) {
            console.error('2FA setup error:', error);
            reply.code(500).send({ error: 'Failed to set up 2FA: ', details: error.message });
        }
    });
    
    server.post<{ Body: { code: string } }>('/2fa/verify', { onRequest: [server.authenticate] }, async (request, reply) => {
        try {
            const { userId } = request.jwtUser;
            let { code } = request.body; // Only code is expected.
            // cast code to integer
            // code = parseInt(code, 10);
            // console.log('Verifying 2FA for user:', userId, code);
            const result = await pool.query('SELECT totp_secret FROM user_2fa WHERE user_id = $1', [userId]);
    
            if (result.rowCount === 0) {
                return reply.code(404).send({ error: 'User not found' });
            }
            const totpSecret = result.rows[0].totp_secret;
            console.log(totpSecret);
            if (!totpSecret) {
                return reply.code(400).send({ error: '2FA not set up for this user' });
            }
            const isValid = authenticator.check(code, totpSecret);
            console.log('2FA verification result:', { code, totpSecret, isValid });
            if (!isValid) {
                return reply.code(400).send({ error: 'Invalid TOTP code' });
            }
            await pool.query('UPDATE users SET two_factor_enabled = TRUE WHERE id = $1', [userId]);
            reply.send({ success: true });
        } catch (error) {
            console.log('2FA verification error:', error);
            reply.code(500).send({ error: 'Failed to verify 2FA', details: error.message });
        }
    });
    
    
    server.post('/2fa/disable', { onRequest: [server.authenticate] }, async (request, reply) => {
        try {
            const { userId } = request.jwtUser!;
            const { code } = request.body as { code: string };
            console.log('Disabling 2FA for user:', userId, code);
            const result = await pool.query('SELECT totp_secret FROM user_2fa WHERE user_id = $1', [userId]);
            if (result.rowCount === 0) {
                return reply.code(404).send({ error: 'User secret not found' });
            }
            const { totp_secret } = result.rows[0];
            console.log('2FA secret:', totp_secret);
    
            const isValid = authenticator.check(code, totp_secret);
            if (!isValid) {
                console.log(`Expected TOTP code: ${authenticator.generate(totp_secret)}`);
    
                console.error('Invalid TOTP code:', { code }, 'for user:', userId);
                return reply.code(400).send({ error: 'Invalid TOTP code' });
            }
            await pool.query('UPDATE users SET two_factor_enabled = FALSE WHERE id = $1', [userId]);
            await pool.query('DELETE FROM user_2fa WHERE user_id = $1', [userId]);
            console.log('2FA disabled for user:', userId);
            reply.send({ success: true });
        } catch (error) {
            console.error('2FA disable error:', error);
            reply.code(500).send({ error: 'Failed to disable 2FA', details: error.message });
        }
    });
    
    server.post('/2fa/login/verify', async (request, reply) => {
        try {
            const { tempToken, code } = request.body as { tempToken: string; code: string };
    
            if (typeof tempToken !== 'string' || !tempToken) {
                console.log('Invalid temporary token:', {tempToken});
                return reply.code(400).send({ error: 'Invalid temporary token' });
            }
            const payload = await verifyToken(tempToken);
            if (!payload.pending2FA) {
                console.log('Invalid temporary token:', {tempToken});
                return reply.code(400).send({ error: 'Invalid token for 2FA verification' });
            }
            const userId = payload.userId;
            const result = await pool.query('SELECT totp_secret, recovery_codes FROM user_2fa WHERE user_id = $1', [userId]);
            if (result.rowCount === 0) {
                return reply.code(404).send({ error: 'User not found' });
            }
            const totpSecret = result.rows[0].totp_secret;
            let recovery_codes = result.rows[0].recovery_codes as string[];
            console.log(result.rows[0].recovery_codes);
            if (!totpSecret) {
                console.log('2FA not set up for this user:', {userId});
                return reply.code(400).send({ error: '2FA not set up for this user' });
            }
            console.log(recovery_codes);
            const isValid = authenticator.check(code, totpSecret) || recovery_codes.includes(code);
            if (!isValid) {
                console.log('Invalid TOTP code:', {code});
                return reply.code(400).send({ error: 'Invalid TOTP code' });
            }
            const isAdmin = await hasRole(userId, 'admin');
            const finalToken = await signToken(
                {
                    userId: userId,
                    isAdmin,
                }
            );
            await redis.set(`session:${finalToken}`, String(userId), { EX: 60 * 60 * 24 * 60 }); // 60 days
            if (recovery_codes.includes(code)) {
                await pool.query(
                'UPDATE user_2fa SET recovery_codes = $1 WHERE user_id = $2',
                [JSON.stringify(recovery_codes.filter((rc: string) => rc !== code)), userId]
                );
            }
            reply
                .setCookie('checkpoint_jwt', finalToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                })
                .send({ success: true, finalToken });
        } catch (error: any) {
            console.error('2FA login verification error:', error);
            reply.code(500).send({ error: error.message || 'Failed to verify 2FA' });
        }
    });
    server.get('/sso/google', passport.authenticate('google', {
        scope: ['profile', 'email']
    }));
    
    server.get('/sso/google/callback', {
        preHandler: passport.authenticate('google', { session: false }),
        handler: async (request, reply) => {
            const user = request.user as { id: string; email?: string };
            const isAdmin = await hasRole(user.id, 'admin');
            const token = await signToken(
                {
                    userId: user.id,
                    isAdmin,
                },
            );
            await redis.set(`session:${token}`, String(user.id), {
                EX: 60 * 60 * 24 * 60 // 60 days;
            });
            reply.setCookie('checkpoint_jwt', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'none', // if the frontend is a different domain
                path: '/',
                // maxAge: 3600, // optional: 1 hour
            });
            reply.redirect(`${process.env.FRONTEND_URL}/dashboard`);
        }
    });
    
    server.get('/sso/line',
        passport.authenticate('line', {
            scope: ['profile', 'openid', 'email']
        })
    );
    
    server.get('/sso/line/callback', {
        preHandler: passport.authenticate('line', { session: false }),
        handler: async (request, reply) => {
            const user = request.user as PassportUser;
    
            const rolesRes = await pool.query(
                `SELECT r.name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1`,
                [user.id]
            );
            const roles = rolesRes.rows.map(row => row.name);
            const isAdmin = roles.includes('admin');
            const token = await signToken(
                { userId: user.id, isAdmin },
            );
            await redis.set(`session:${token}`, String(user.id), {
                EX: 60 * 60 * 24 * 60 // 60 days;
            });
    
            reply.setCookie('checkpoint_jwt', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'none',
            });
            reply.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
        }
    });
};

export default authRoutes;