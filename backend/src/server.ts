// src/server.ts
import fastify from 'fastify';
import cors from '@fastify/cors';
import jwt, { JWT } from '@fastify/jwt';
import cookie from '@fastify/cookie';
import { Pool } from 'pg';
// import bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import { z, ZodError } from 'zod';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import * as openpgp from 'openpgp';
import { createClient } from 'redis';

const redis = createClient({
    // url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
});
redis.connect()
    .then(() => console.log('Connected to Redis'))
    .catch((err) => {
        console.error('An error occurred connecting to Redis:', err);
        process.exit(1);
    });


import type {
    GenerateRegistrationOptionsOpts,
    VerifyRegistrationResponseOpts,
    GenerateAuthenticationOptionsOpts,
    VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server';
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

import passport, { PassportUser } from '@fastify/passport';
import fastifySecureSession from '@fastify/secure-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LineStrategy } from 'passport-line';

import { encryptPrivateKey, EncryptedPayload } from './utils/crypto-utils';

type UserIdParam = {
    id: string;  // The 'id' param is a string (e.g. your random 20-char user ID)
};

type AuthMethodIdParam = {
    authMethodId: string;
};

type ProviderIdParam = {
    id: string;
};

type RoleIdBody = {
    roleId: number;  // The body contains 'roleId' when assigning a role to a user
};

type SsoConnectionBody = {
    provider_id: number;
    external_user_id: string;
};

// Extend FastifyInstance type to include JWT
declare module 'fastify' {
    interface FastifyRequest {
        jwtUser: {
            userId: string | number;
            isAdmin?: boolean;
        };
    }
    interface FastifyInstance {
        jwt: JWT;
        authenticate: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    }
}

declare module '@fastify/passport' {
    interface PassportUser {
        id: string | number;
    }
    // interface AuthenticatedRequest {
    //     passportUser: PassportUser;
    // }
}

declare module '@fastify/jwt' {
    interface FastifyJWT {
        user: {
            id: string | number;
            email?: string;
            isAdmin?: boolean;
        }
    }
}

dotenv.config();

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
});

const server = fastify({ logger: true });

server.setErrorHandler((error, request, reply) => {
    if (error instanceof ZodError) {
        reply.code(400).send({
            statusCode: 400,
            error: 'Bad Request',
            issues: error.issues.map((issue) => ({
                format: issue

            }))
        });
        return;
    }
    reply.status(error.statusCode || 500).send({
        statusCode: error.statusCode || 500,

        error: error.name,
        message: error.message,
    });
});

server.decorate('authenticate', async (request, reply) => {
    try {
        // 1) Get token from either 'Authorization' header or cookie
        const authHeader = request.headers.authorization;
        let token: string | undefined;

        if (authHeader?.startsWith('Bearer ')) {
            token = authHeader.substring(7); // strip 'Bearer '
        } else {
            // fallback to cookie if you store it there
            token = request.cookies.checkpoint_jwt;
        }

        if (!token) {
            return reply.code(401).send({ error: 'No token provided' });
        }

        // 2) Verify JWT -> populates request.jwtUser (because of `namespace: 'jwtUser'`)
        // or throws if invalid
        const decoded = await request.jwtVerify();

        const sessionKey = `session:${token}`;
        const sessionUserId = await redis.get(sessionKey);

        if (!sessionUserId) {
            return reply.code(401).send({ error: 'Invalid session' });
        }

        // If valid, we continue to the route handler
    } catch (err) {
        // If verification failed or anything else, 401
        reply.code(401).send({ error: 'Unauthorized' });
    }
});

const rpName = 'Checkpoint';
const rpID = process.env.DOMAIN || 'localhost';
const origin = process.env.FRONTEND_URL || `https://${rpID}`;

// Register plugins
server.register(cors, {
    origin: process.env.FRONTEND_URL,
    credentials: true
});

server.register(fastifySecureSession, {
    key: process.env.SESSION_KEY || '85P5B+/sXn6zwnXP6O8/u6abFWb8M5aOXfrpJruhm1M=',
    cookie: {
        secure: process.env.NODE_ENV === 'production'
    }
});
server.register(passport.initialize());
server.register(jwt, {
    secret: process.env.JWT_SECRET!,
    sign: {
        expiresIn: '60d'
    },
    namespace: 'jwtUser',
    decoratorName: 'jwtUser'
});
server.register(passport.secureSession());

// Configure SSO providers
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID!,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        callbackURL: `${process.env.BACKEND_URL}/auth/google/callback`
    },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const email = profile.emails?.[0].value;
                if (!email) throw new Error('No email provided');

                const result = await pool.query(
                    'SELECT * FROM users WHERE email = $1',
                    [email]
                );

                let user = result.rows[0];

                if (!user) {
                    // Create new user if doesn't exist
                    const newUser = await pool.query(
                        'INSERT INTO users (email) VALUES ($1) RETURNING *',
                        [email]
                    );
                    user = newUser.rows[0];

                    // Add SSO as auth method
                    await pool.query(
                        'INSERT INTO auth_methods (user_id, type, is_preferred, metadata) VALUES ($1, $2, $3, $4)',
                        [user.id, 'sso', true, { provider: 'google', profile_id: profile.id }]
                    );
                }

                done(null, user);
            } catch (err) {
                done(err as Error, undefined);
            }
        }
    ))
};

if (process.env.LINE_CHANNEL_ID && process.env.LINE_CHANNEL_SECRET) {
    passport.use(new LineStrategy({
        channelID: process.env.LINE_CHANNEL_ID!,
        channelSecret: process.env.LINE_CHANNEL_SECRET!,
        callbackURL: `${process.env.BACKEND_URL}/auth/line/callback`
    },
        async (accessToken, refreshToken, profile, done) => {
            try {
                const email = profile.emails?.[0].value;
                if (!email) throw new Error('No email provided');

                const result = await pool.query(
                    'SELECT * FROM users WHERE email = $1',
                    [email]
                );

                let user = result.rows[0];

                if (!user) {
                    // Create new user if doesn't exist
                    const newUser = await pool.query(
                        'INSERT INTO users (email) VALUES ($1) RETURNING *',
                        [email]
                    );
                    user = newUser.rows[0];

                    // Add SSO as auth method
                    await pool.query(
                        'INSERT INTO auth_methods (user_id, type, is_preferred, metadata) VALUES ($1, $2, $3, $4)',
                        [user.id, 'sso', true, { provider: 'line', profile_id: profile.id }]
                    );
                }

                done(null, user);
            } catch (err) {
                done(err as Error, undefined);
            }
        }
    ));
};

// Schema definitions
const UserSchema = z.object({
    id: z.string().optional(),
    email: z.string().email(),
    password: z.string().min(8),
    first_name: z.string().optional(),
    last_name: z.string().optional(),
    public_key: z.string().optional(),
    private_key: z.string().optional(),
    profile_pic: z.string().optional(),
});

const LoginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
});

// Initialize database
async function initDB() {
    const client = await pool.connect();
    try {
        // Get all migration files from the migrations directory
        const migrationsPath = path.join(__dirname, '../migrations');
        const migrationFiles = fs.readdirSync(migrationsPath)
            .filter(file => file.endsWith('.sql'))
            .sort(); // Ensures migrations run in order

        // Get already executed migrations
        await client.query(`
            CREATE TABLE IF NOT EXISTS migrations (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(255) UNIQUE NOT NULL,
            executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            )
        `);

        const executedMigrations = await client.query(
            'SELECT filename FROM migrations'
        );
        const executedFiles = new Set(executedMigrations.rows.map(row => row.filename));

        // Execute new migrations
        for (const file of migrationFiles) {
            if (!executedFiles.has(file)) {
                console.log(`Executing migration: ${file}`);
                const migrationSQL = fs.readFileSync(
                    path.join(migrationsPath, file),
                    'utf8'
                );

                await client.query('BEGIN');
                try {
                    await client.query(migrationSQL);
                    await client.query(
                        'INSERT INTO migrations (filename) VALUES ($1)',
                        [file]
                    );
                    await client.query('COMMIT');
                    console.log(`Migration ${file} completed successfully`);
                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                }
            }
        }
    } finally {
        client.release();
    }
}

/*

FUNCTIONS

*/

async function requireRole(roleName: string, request: any, reply: any) {
    const { userId } = request.user; // assuming JWT payload contains userId
    const result = await pool.query(
        `SELECT r.name 
    FROM roles r 
    JOIN user_roles ur ON r.id = ur.role_id 
    WHERE ur.user_id = $1 AND r.name = $2`,
        [userId, roleName]
    );
    if (result.rowCount === 0) {
        reply.code(403).send({ error: 'Forbidden' });
        return false;
    }
    return true;
}

// Define an audit log helper function
async function auditLog(user_id: string, event: string, details: Record<string, any>) {
    await pool.query(
        'INSERT INTO audit_logs (event, details) VALUES ($1, $2)',
    );
}

async function getUserPermissions(userId: string): Promise<Set<string>> {
    const rolesRes = await pool.query(
        `SELECT r.permissions
           FROM user_roles ur
           JOIN roles r ON ur.role_id = r.id
          WHERE ur.user_id = $1`,
        [userId]
    );
    const allPerms = new Set<string>();
    for (const row of rolesRes.rows) {
        const permsArray: string[] = row.permissions?.permissions || row.permissions;
        // If row.permissions is { permissions: [...] }, adjust accordingly
        permsArray.forEach(p => allPerms.add(p));
    }
    return allPerms;
}

async function hasPermission(userId: string, permission: string): Promise<boolean> {
    const allPerms = await getUserPermissions(userId);
    return allPerms.has(permission) || allPerms.has('*');
}

async function generateUUID() {
    const chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    // return Array.from({ length: 20 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    // Check if UUID exists in database
    let uuid = Array.from({ length: 20 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
    let exists = true;
    while (exists) {
        const result = await pool.query('SELECT id FROM users WHERE id = $1', [uuid]);
        if (result.rowCount === 0) {
            exists = false;
        } else {
            uuid = Array.from({ length: 20 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        }
    }
    return uuid;
}

// Routes

/*
/api/auth

Handles all authentication-related routes
*/

server.post('/api/auth/register', async (request, reply) => {
    const body = UserSchema.parse(request.body);

    try {

        // generate pgp keypair for user federation
        const { publicKey, privateKey } = await openpgp.generateKey({
            userIDs: [{ name: body.last_name, email: body.email }],
            type: 'ecc',
            curve: 'curve25519Legacy',
            format: 'armored'
        });

        const encryptedPrivateKey: EncryptedPayload = encryptPrivateKey(privateKey);

        const userId = await generateUUID();
        const result = await pool.query(
            'INSERT INTO users (id, email, public_key, private_key) VALUES ($1, $2, $3, $4) RETURNING id, email',
            [userId, body.email, publicKey, encryptedPrivateKey]
        );

        if (body.password) {
            // hash the password using argon2
            const hashedPassword = await argon2.hash(body.password);
            // use auth_methods table to store hashed password if set
            await pool.query(
                'INSERT INTO auth_methods (user_id, type, metadata) VALUES ($1, $2, $3)',
                [result.rows[0].id, 'password', JSON.stringify(hashedPassword)]
            );
        }

        const token = server.jwt.sign(
            { userId: result.rows[0].id },
            { expiresIn: '60d' }
        );
        await redis.set(`session:${token}`, String(result.rows[0].id), {
            EX: 60 * 60 * 24 * 60 // 60 days;
        });
        return { user: result.rows[0], token };
    } catch (err: any) {
        if (err.constraint === 'users_email_key') {
            reply.code(400);
            return { error: 'Email already exists' };
        }
        throw err;
    }
});

server.post<{ Body: { email: string } }>('/api/auth/passkey/login/start', async (request, reply) => {
    const { email } = request.body;

    // Ensure the user exists
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rowCount === 0) {
        reply.code(400).send({ error: 'User does not exist.' });
        return;
    }
    const user = userResult.rows[0];

    // Retrieve stored passkey credentials (assumed to be stored in auth_methods)
    const credentialsResult = await pool.query(
        'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2',
        [user.id, 'passkey']
    );
    const allowedCredentials = credentialsResult.rows.map((row) => {
        const metadata = row.metadata;
        return {
            id: metadata.credentialID,
            type: 'public-key',
        };
    });

    // Generate authentication options for passkey login
    const options = generateAuthenticationOptions({
        rpID,
        allowCredentials: allowedCredentials,
        userVerification: 'preferred',
    });

    // Store the challenge in Redis for later verification
    await redis.set(`authentication_${user.id}`, JSON.stringify(options), { EX: 300 });
    reply.send(options);
});


server.post<{ Body: { email: string, response: any } }>('/api/auth/passkey/login/complete', async (request, reply) => {
    const { email, response } = request.body;

    // Ensure the user exists
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rowCount === 0) {
        reply.code(400).send({ error: 'User does not exist.' });
        return;
    }
    const user = userResult.rows[0];

    // Retrieve the expected challenge from Redis
    const expectedChallenge = await redis.get(`authentication_${user.id}`);
    if (!expectedChallenge) {
        reply.code(400).send({ error: 'Authentication session expired' });
        return;
    }

    try {
        // Get the credential info from auth_methods
        const credentialResult = await pool.query(
            'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2 AND metadata->>\'credentialID\' = $3',
            [user.id, 'passkey', response.id]
        );
        if (credentialResult.rowCount === 0) {
            reply.code(400).send({ error: 'Invalid credential' });
            return;
        }

        // Verify the authentication response using @simplewebauthn/server
        const verification = await verifyAuthenticationResponse({
            response: response as AuthenticationResponseJSON,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: response.id,
                publicKey: credentialResult.rows[0].metadata.publicKey,
                counter: credentialResult.rows[0].metadata.counter,
                transports: ['internal'],
            }
        });

        if (verification.verified) {
            // Issue a JWT on successful passkey authentication
            const rolesRes = await pool.query(
                `SELECT r.name 
            FROM user_roles ur
            JOIN roles r ON ur.role_id = r.id
            WHERE ur.user_id = $1`,
                [user.id]
            );
            const roles = rolesRes.rows.map(row => row.name);
            const isAdmin = roles.includes('admin');
        
            // Sign and return a JWT token
            const token = server.jwt.sign(
                { userId: user.id, isAdmin },
            );
            await redis.set(`session:${token}`, String(user.id), {
                EX: 60 * 60 * 24 * 60 // 60 days;
            });
            reply.send({ token });
        } else {
            reply.code(400).send({ error: 'Authentication failed' });
        }
    } catch (err) {
        reply.code(400).send({ error: 'Invalid authentication response' });
    }
});
server.post('/api/auth/passkey/register/start', async (request, reply) => {
    const { userId } = request.jwtUser;
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    if (userResult.rowCount === 0) {
        reply.code(400).send({ error: 'User does not exist.' });
        return;
    }
    const user = userResult.rows[0];

    // Generate registration options for passkey
    const options = generateRegistrationOptions({
        rpName,
        rpID,
        userID: user.id.toString(),
        userName: user.email,
        timeout: 60000,
        authenticatorSelection: {
            userVerification: 'preferred'
        },
    });

    // Store the challenge in Redis for later verification
    await redis.set(`registration_${user.id}`, JSON.stringify(options), { EX: 300 });
    reply.send(options);
});

server.post('/api/auth/passkey/register/complete', async (request, reply) => {
    const { userId } = request.jwtUser;
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
    const passkeyData = request.body as RegistrationResponseJSON
    if (userResult.rowCount === 0) {
        reply.code(400).send({ error: 'User does not exist.' });
        return;
    }
    const user = userResult.rows[0];

    // Retrieve the expected challenge from Redis
    const expectedChallenge = await redis.get(`registration_${user.id}`);
    if (!expectedChallenge) {
        reply.code(400).send({ error: 'Registration session expired' });
        return;
    }

    try {
        // Verify the registration response using @simplewebauthn/server
        const verification = await verifyRegistrationResponse({
            response: passkeyData,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            // attestationType: 'none',
            // authenticatorSelection: {
            //     userVerification: 'preferred'
            // },
        });

        if (verification.verified) {
            // Store the credential in the database
            const credential = verification.registrationInfo;
            await pool.query(
                'INSERT INTO auth_methods (user_id, type, metadata) VALUES ($1, $2, $3)',
                [user.id, 'passkey', {
                    credentialID: credential.credential.id,
                    publicKey: credential.credential.publicKey,
                    counter: '0',
                }]
            );
            reply.send({ success: true });
        } else {
            reply.code(400).send({ error: 'Registration failed' });
        }
    } catch (err) {
        reply.code(400).send({ error: 'Invalid registration response' });
    }
});

server.post('/api/auth/login', async (request, reply) => {
    const { email, password } = LoginSchema.parse(request.body);

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
        reply.code(401).send({ error: 'Invalid credentials' });
        return;
    }

    const authResult = await pool.query(
        'SELECT hashed_password FROM auth_methods WHERE user_id = $1 AND type = $2',
        [user.id, 'password']
    );
    const authMethod = authResult.rows[0];

    if (!authMethod || !(await argon2.verify(authMethod.hashed_password, password))) {
        reply.code(401).send({ error: 'Invalid credentials' });
        return;
    }

    const rolesRes = await pool.query(
        `SELECT r.name 
    FROM user_roles ur
    JOIN roles r ON ur.role_id = r.id
    WHERE ur.user_id = $1`,
        [user.id]
    );
    const roles = rolesRes.rows.map(row => row.name);
    const isAdmin = roles.includes('admin');

    // Sign and return a JWT token
    const token = server.jwt.sign(
        { userId: user.id, isAdmin },
        { expiresIn: '60d' }
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

    // const token = server.jwt.sign({ userId: user.id });
    // return { user: { id: user.id, email: user.email, name: user.name }, token };
});


server.get('/api/auth/authenticate', async (request, reply) => {
    try {
        // check if the request contains a valid JWT, and return the user if so
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

server.get('/api/auth/available-methods', async (request, reply) => {
    const result = await pool.query('SELECT DISTINCT type FROM auth_methods');
    return { methods: result.rows.map(row => row.type) };
});

server.post('/api/auth/password-reset', async (request, reply) => {
    const { email } = request.body as { email: string };
    try {
        // 1) Validate user exists
        const userResult = await pool.query(`SELECT id FROM users WHERE email = $1`, [email]);
        if (userResult.rowCount === 0) {
            // Do not reveal if the user doesn't exist (for privacy)
            return reply.send({ success: true });
        }
        const userId = userResult.rows[0].id;

        // 2) Generate token (like a random string)
        const resetToken = generateUUID(); // or your random generator
        // 3) Store token in DB or Redis with an expiration
        await pool.query(
            `INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
            [userId, resetToken]
        );

        // 4) Email or otherwise deliver reset link
        // e.g. sendMail(user.email, `Your reset link: ${FRONTEND_URL}/reset?token=${resetToken}`)

        reply.send({ success: true });
    } catch (err) {
        reply.status(500).send({ error: 'Database error' });
    }
});

server.post('/api/auth/password-reset/complete', async (request, reply) => {
    const { token, newPassword } = request.body as { token: string; newPassword: string };

    try {
        // 1) Validate token
        const prResult = await pool.query(
            `SELECT user_id FROM password_resets WHERE token = $1 AND expires_at > NOW()`,
            [token]
        );
        if (prResult.rowCount === 0) {
            return reply.status(400).send({ error: 'Invalid or expired reset token' });
        }
        const userId = prResult.rows[0].user_id;

        // 2) Hash new password
        const hashedPassword = await argon2.hash(newPassword);

        // 3) Update auth_methods
        await pool.query(
            `UPDATE auth_methods
            SET hashed_password = $1
          WHERE user_id = $2
            AND type = 'password'`,
            [hashedPassword, userId]
        );

        // 4) Invalidate or remove the used token
        await pool.query(`DELETE FROM password_resets WHERE token = $1`, [token]);

        reply.send({ success: true });
    } catch (err) {
        reply.status(500).send({ error: 'Database error' });
    }
});

server.post('/api/auth/change-password', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { oldPassword, newPassword } = request.body as {
            oldPassword: string;
            newPassword: string;
        };
        const userId = request.jwtUser.userId;

        // Check if user has permission or if you rely solely on user matching
        // E.g. if ( ! await hasPermission(userId, 'users.updateSelf') ) ...

        try {
            // 1) Get current hashed password
            const authMethodRes = await pool.query(
                `SELECT hashed_password FROM auth_methods 
            WHERE user_id = $1 AND type = 'password'`,
                [userId]
            );
            if (authMethodRes.rowCount === 0) {
                return reply.status(400).send({ error: 'No password set' });
            }
            const { hashed_password } = authMethodRes.rows[0];

            // 2) Verify old password
            const validOld = await argon2.verify(hashed_password, oldPassword);
            if (!validOld) {
                return reply.status(401).send({ error: 'Incorrect old password' });
            }

            // 3) Hash new password
            const newHashed = await argon2.hash(newPassword);

            // 4) Update DB
            await pool.query(
                `UPDATE auth_methods SET hashed_password = $1 WHERE user_id = $2 AND type = 'password'`,
                [newHashed, userId]
            );

            reply.send({ success: true });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// Suppose you store active tokens in a 'sessions' table in Redis
server.post('/api/auth/sessions/revoke', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const userId = request.jwtUser.userId;
        // e.g. only Admin can revoke sessions
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


// Protected route example
// server.get('/api/user', {
//     onRequest: [server.authenticate],
// }, async (request) => {
//     const userId = request.user.userId;
//     const result = await pool.query('SELECT id, email, name FROM users WHERE id = $1', [userId]);
//     return result.rows[0];
// });


/*

SSO ROUTES

*/

server.get('/api/sso', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const result = await pool.query(
                'SELECT id, name, client_id, config, created_at FROM sso_providers'
            );
            reply.send(result.rows);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

server.post('/api/sso', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { name, client_id, client_secret, config } = request.body as {
            name: string;
            client_id: string;
            client_secret: string;
            config?: any;
        };

        try {
            const result = await pool.query(
                `
            INSERT INTO sso_providers (name, client_id, client_secret, config)
                 VALUES ($1, $2, $3, COALESCE($4, '{}'))
              RETURNING id, name, client_id, config, created_at
          `,
                [name, client_id, client_secret, config]
            );
            reply.send(result.rows[0]);
        } catch (err: any) {
            if (err.code === '23505') {
                return reply.status(400).send({ error: 'SSO provider already exists' });
            }
            reply.status(500).send({ error: 'Database error' });
        }
    },
});
server.patch('/api/sso/:id', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as ProviderIdParam;
        const { name, client_id, client_secret, config } = request.body as {
            name?: string;
            client_id?: string;
            client_secret?: string;
            config?: any;
        };

        try {
            const result = await pool.query(
                `
            UPDATE sso_providers
               SET name          = COALESCE($1, name),
                   client_id     = COALESCE($2, client_id),
                   client_secret = COALESCE($3, client_secret),
                   config        = COALESCE($4, config)
             WHERE id = $5
             RETURNING id, name, client_id, config, created_at
          `,
                [name, client_id, client_secret, config, id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'SSO provider not found' });
            }
            reply.send(result.rows[0]);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});
server.delete('/api/sso/:id', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as ProviderIdParam;
        try {
            const result = await pool.query(
                'DELETE FROM sso_providers WHERE id = $1 RETURNING id',
                [id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'SSO provider not found' });
            }
            reply.send({ success: true, providerId: id });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

server.get('/auth/sso/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

server.get('/auth/sso/google/callback', {
    preHandler: passport.authenticate('google', { session: false }),
    handler: async (request, reply) => {
        const user = request.user as { id: number; email?: string };

        // 3) Create your own JWT
        const rolesRes = await pool.query(
            `SELECT r.name 
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1`,
            [user.id]
        );
        const roles = rolesRes.rows.map(row => row.name);
        const isAdmin = roles.includes('admin');
    
        // Sign and return a JWT token
        const token = server.jwt.sign(
            { userId: user.id, isAdmin },
            { expiresIn: '60d' }
        );
        await redis.set(`session:${token}`, String(user.id), {
            EX: 60 * 60 * 24 * 60 // 60 days;
        });

        // 4) Set it as an HTTP-only cookie
        reply.setCookie('checkpoint_jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none', // if the frontend is a different domain
            path: '/',
            // maxAge: 3600, // optional: 1 hour
        });

        // 5) Redirect the user to your frontend, WITHOUT the token
        //    in the URL. "server-to-server" exchange is done.
        reply.redirect(`${process.env.FRONTEND_URL}/dashboard`);
    }
});

server.get('/auth/sso/line',
    passport.authenticate('line', {
        scope: ['profile', 'openid', 'email']
    })
);

server.get('/auth/sso/line/callback', {
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
    
        // Sign and return a JWT token
        const token = server.jwt.sign(
            { userId: user.id, isAdmin },
            { expiresIn: '60d' }
        );
        await redis.set(`session:${token}`, String(user.id), {
            EX: 60 * 60 * 24 * 60 // 60 days;
        });

        reply.setCookie('checkpoint_jwt', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'none',
        });

        // Redirect to frontend with token
        reply.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    }
});

/*
/auth/users

Handles all user-related routes
*/

server.get('/api/users/exists', {
    handler: async (request, reply) => {
        const { email } = request.query as { email: string };
        const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        return { exists: result.rowCount > 0 };
    },
});

// get all users
server.get('/api/users', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            // If you want to restrict this to admins, do an additional check here:
            if (!(await hasPermission(String(request.jwtUser.userId), 'users.search')) || !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const { search, page = 1, pageSize = 10 } = request.query as {
                search?: string;
                page?: number;
                pageSize?: number;
            };
            const offset = (page - 1) * pageSize;
            const likeQuery = `%${search || ''}%`;

            try {
                const result = await pool.query(
                    `
                    SELECT id, email, first_name, last_name, created_at
                        FROM users
                    WHERE email ILIKE $1
                        OR first_name ILIKE $1
                        OR last_name ILIKE $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    `,
                    [likeQuery, pageSize, offset]
                );
                reply.send(result.rows);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// get user's profile
server.get('/api/users/:id', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as { id: string };
        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                'SELECT id, email, first_name, last_name, public_key, created_at FROM users WHERE id = $1',
                [id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            }
            reply.send(result.rows[0]);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// update user's profile
server.put('/api/users/:id', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as { id: string };
        const toUpdate = UserSchema.parse(request.body);

        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                'UPDATE users SET email = $1, first_name = $2, last_name = $3 WHERE id = $4 RETURNING *',
                [toUpdate.email, toUpdate.first_name, toUpdate.last_name, id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            }
            reply.send(result.rows[0]);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        };
    }
});

// delete user

server.delete('/api/users/:id', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as { id: string };
        try {
            // if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
            //   return reply.status(403).send({ error: 'Forbidden' });
            // }

            const result = await pool.query(
                'DELETE FROM users WHERE id = $1 RETURNING id',
                [id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            }
            reply.send({ success: true, userId: id });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// get user's auth methods
server.get('/api/users/:id/auth-methods', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as { id: string };
        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                `
            SELECT id, type, is_preferred, metadata, created_at, last_used_at
              FROM auth_methods
             WHERE user_id = $1
          `,
                [id]
            );
            reply.send(result.rows);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// add auth method to user
server.post('/api/users/:id/auth-methods', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as { id: string };
        const { type, is_preferred, metadata } = request.body as {
            type: 'password' | 'passkey' | 'biometric' | 'sso';
            is_preferred?: boolean;
            metadata?: any;
        };

        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                `
            INSERT INTO auth_methods (user_id, type, is_preferred, metadata)
                 VALUES ($1, $2, COALESCE($3, false), COALESCE($4, '{}'))
              RETURNING id, type, is_preferred, metadata, created_at, last_used_at
          `,
                [id, type, is_preferred, metadata]
            );
            reply.send(result.rows[0]);
        } catch (err: any) {
            if (err.code === '23503') {
                return reply.status(404).send({ error: 'User not found' });
            }
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// update auth method
server.get('/api/users/:id/sso', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as { id: string };
        try {
            // if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
            //   return reply.status(403).send({ error: 'Forbidden' });
            // }

            const result = await pool.query(
                `
            SELECT usc.id,
                   usc.provider_id,
                   sp.name as provider_name,
                   usc.external_user_id,
                   usc.created_at
              FROM user_sso_connections usc
              JOIN sso_providers sp ON usc.provider_id = sp.id
             WHERE usc.user_id = $1
          `,
                [id]
            );
            reply.send(result.rows);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// add sso connection to user
server.post('/api/users/:id/sso', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        const { provider_id, external_user_id } = request.body as SsoConnectionBody;

        try {
            // if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
            //   return reply.status(403).send({ error: 'Forbidden' });
            // }

            const result = await pool.query(
                `
            INSERT INTO user_sso_connections (user_id, provider_id, external_user_id)
                 VALUES ($1, $2, $3)
              RETURNING id, user_id, provider_id, external_user_id, created_at
          `,
                [id, provider_id, external_user_id]
            );
            reply.send(result.rows[0]);
        } catch (err: any) {
            if (err.code === '23503') {
                // foreign key violation for user or provider
                return reply.status(404).send({ error: 'User or provider not found' });
            }
            if (err.code === '23505') {
                // unique (provider_id, external_user_id)
                return reply.status(400).send({ error: 'This SSO connection already exists' });
            }
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// add role to user
server.post('/api/users/:id/role', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        const { roleId } = request.body as RoleIdBody;

        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            await pool.query(
                `
            INSERT INTO user_roles (user_id, role_id)
                 VALUES ($1, $2)
            ON CONFLICT (user_id, role_id) DO NOTHING
          `,
                [id, roleId]
            );
            reply.send({ success: true });
        } catch (err: any) {
            if (err.code === '23503') {
                // foreign key violation for user or role
                return reply.status(404).send({ error: 'User or role not found' });
            }
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// remove role from user
server.delete('/api/users/:id/role', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        const { roleId } = request.body as RoleIdBody;

        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                'DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 RETURNING user_id, role_id',
                [id, roleId]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User or role not found' });
            }
            reply.send({ success: true });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// get user's roles
server.get('/api/users/:id/roles', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                `
            SELECT r.id, r.name, r.description
              FROM user_roles ur
              JOIN roles r ON ur.role_id = r.id
             WHERE ur.user_id = $1
          `,
                [id]
            );
            reply.send(result.rows);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

/*

ROLES ROUTES

*/

server.get('/api/roles', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const result = await pool.query('SELECT id, name, permissions, icon, description FROM roles');
            reply.send(result.rows);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

server.post('/api/roles', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { name, description, permissions, icon } = request.body as {
            name: string;
            description?: string;
            permissions?: string[];
            icon?: string;
        };
        try {
            const result = await pool.query(
                `
            INSERT INTO roles (name, description, permissions, icon)
             VALUES ($1, $2, $3, $4)
              RETURNING id, name, permissions, icon, description
          `,
                [name, description ?? null, permissions ?? [], icon ?? null]
            );
            reply.send(result.rows[0]);
        } catch (err: any) {
            if (err.code === '23505') {
                return reply.status(400).send({ error: 'Role name already exists' });
            }
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

server.post('/api/roles/:roleId/permissions', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const userId = request.jwtUser.userId;
        // Only an admin can do this
        if (!(await hasPermission(String(userId), 'roles.update'))) {
            return reply.status(403).send({ error: 'Forbidden' });
        }

        const { roleId } = request.params as { roleId: string };
        const { permissionsToAdd } = request.body as { permissionsToAdd: string[] };

        try {
            // 1) Get current permissions from DB
            const rRes = await pool.query(`SELECT permissions FROM roles WHERE id = $1`, [roleId]);
            if (rRes.rowCount === 0) {
                return reply.status(404).send({ error: 'Role not found' });
            }
            let perms = rRes.rows[0].permissions || [];
            // 2) Merge in the new perms
            perms = Array.from(new Set([...perms, ...permissionsToAdd])); // deduplicate
            // 3) Update
            await pool.query(`UPDATE roles SET permissions = $1 WHERE id = $2`, [JSON.stringify(perms), roleId]);
            reply.send({ success: true, updatedPermissions: perms });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});



/*

AUTH METHODS ROUTES

*/

server.patch('/api/auth-methods/:authMethodId', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { authMethodId } = request.params as AuthMethodIdParam;
        const { is_preferred, metadata } = request.body as {
            is_preferred?: boolean;
            metadata?: any;
        };

        try {
            const result = await pool.query(
                `
            UPDATE auth_methods
               SET is_preferred = COALESCE($1, is_preferred),
                   metadata = COALESCE($2, metadata)
             WHERE id = $3
             RETURNING id, user_id, type, is_preferred, metadata, created_at, last_used_at
          `,
                [is_preferred, metadata, authMethodId]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'Auth method not found' });
            }
            reply.send(result.rows[0]);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// (2.4) DELETE AN AUTH METHOD
server.delete('/api/auth-methods/:authMethodId', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { authMethodId } = request.params as AuthMethodIdParam;
        try {
            const result = await pool.query(
                'DELETE FROM auth_methods WHERE id = $1 RETURNING id',
                [authMethodId]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'Auth method not found' });
            }
            reply.send({ success: true, authMethodId });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

/*

AUDIT LOGS ROUTES

*/

server.get('/api/audit-logs', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            // Possibly check if request.jwtUser.isAdmin

            const result = await pool.query(
                `
            SELECT al.id,
                   al.user_id,
                   al.action,
                   al.details,
                   al.created_at,
                   u.email as user_email
              FROM audit_logs al
         LEFT JOIN users u ON al.user_id = u.id
          ORDER BY al.created_at DESC
          `
            );
            reply.send(result.rows);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// Start server
async function start() {
    try {
        await initDB();
        await server.listen({ port: 3001 });
        console.log('Server running on port 3001');
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

start();