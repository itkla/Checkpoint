// src/server.ts
import fastify from 'fastify';
import cors from '@fastify/cors';
import jwt, { JWT } from '@fastify/jwt';
import { Pool } from 'pg';
// import bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import { z } from 'zod';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import * as openpgp from 'openpgp';
import { createClient } from 'redis';

const redis = createClient({
    // url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
});
try {
    redis.connect().catch(console.error);
    console.log('Connected to Redis');
} catch (err) {
    console.error("An error occurred connecting to Redis: " + err);
}


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

import passport from '@fastify/passport';
import fastifySecureSession from '@fastify/secure-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LineStrategy } from 'passport-line';

// Extend FastifyInstance type to include JWT
declare module 'fastify' {
    interface FastifyRequest {
        jwtUser: {
            userId: string | number;
        };
    }
    interface FastifyInstance {
        jwt: JWT;
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
    // decorateRequest: true,
    namespace: 'jwtUser'
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
    email: z.string().email(),
    password: z.string().min(8),
    first_name: z.string().optional(),
    last_name: z.string().optional(),
    public_key: z.string().optional(),
    private_key: z.string().optional(),
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

        const result = await pool.query(
            'INSERT INTO users (email, first_name, last_name, public_key, private_key) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, first_name, last_name',
            [body.email, body.first_name, body.last_name, publicKey, privateKey]
        );

        if (body.password) {
            // hash the password using argon2
            const hashedPassword = await argon2.hash(body.password);
            // use auth_methods table to store hashed password if set
            await pool.query(
                'INSERT INTO auth_methods (user_id, type, hashed_password) VALUES ($1, $2, $3)',
                [result.rows[0].id, 'password', hashedPassword]
            );
        }

        const token = server.jwt.sign({ userId: result.rows[0].id });
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
            const token = server.jwt.sign({ userId: user.id });
            reply.send({ token });
        } else {
            reply.code(400).send({ error: 'Authentication failed' });
        }
    } catch (err) {
        reply.code(400).send({ error: 'Invalid authentication response' });
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

    // Sign and return a JWT token
    const token = server.jwt.sign({ userId: user.id });
    reply.send({ user: { id: user.id, email: user.email }, token });

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

// Protected route example
// server.get('/api/user', {
//     onRequest: [server.authenticate],
// }, async (request) => {
//     const userId = request.user.userId;
//     const result = await pool.query('SELECT id, email, name FROM users WHERE id = $1', [userId]);
//     return result.rows[0];
// });


// SSO routes

/*
let ssoOptions = {};

server.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

server.get('/auth/google/callback',
    passport.authenticate('google', { session: false }),
    async (request, reply) => {
        const token = server.jwt.sign({ userId: (request.user as PassportUser).id });
        // Redirect to frontend with token
        reply.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    }
);

server.get('/auth/line',
    passport.authenticate('line', {
        scope: ['profile', 'openid', 'email']
    })
);

server.get('/auth/line/callback',
    passport.authenticate('line', { session: false }),
    async (request, reply) => {
        const token = server.jwt.sign({ userId: (request.user as PassportUser).id });
        // Redirect to frontend with token
        reply.redirect(`${process.env.FRONTEND_URL}/auth/callback?token=${token}`);
    }
);
*/

/*
/auth/users

Handles all user-related routes
*/

server.get('/api/users/:fnc', async (request, reply) => {
    // Destructure the "fnc" parameter from the request
    const { fnc } = request.params as { fnc: string };

    // (Token verification comes next – see snippet 4)
    // ...
    if (fnc === 'all') {
        const result = await pool.query('SELECT * FROM users');
        reply.send(result.rows);
    } else if (fnc !== "") {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [fnc]);
        reply.send(result.rows);
    } else {
        reply.send({ error: 'Invalid function' });
    }
});

server.post('/api/users/:userId/assign-role', async (request, reply) => {
    const { userId } = request.params as { userId: string };
    const { roleId } = request.body as { roleId: number };

    await pool.query('INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING', [userId, roleId]);
    reply.send({ success: true });
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