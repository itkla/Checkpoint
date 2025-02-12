// src/server.ts
import fastify from 'fastify';
import cors from '@fastify/cors';
// import jwt, { JWT } from '@fastify/jwt';
import Multipart from '@fastify/multipart';

import { signToken, verifyToken, decodeToken } from './utils/jwt-utils';
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

// import type {
//     GenerateRegistrationOptionsOpts,
//     VerifyRegistrationResponseOpts,
//     GenerateAuthenticationOptionsOpts,
//     VerifyAuthenticationResponseOpts,
// } from '@simplewebauthn/server';
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
import { profile } from 'console';

type UserIdParam = {
    id: string;  // The 'id' param is a string (e.g. your random 20-char user ID)
};

type AuthMethodIdParam = {
    authMethodId: string;
    credentialId?: string;
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
        jwtUser?: {
            userId: string | number;
            isAdmin?: boolean;
            [key: string]: any;
        };
    }
    interface FastifyInstance {
        // jwtUser: import('@fastify/jwt').JWT;
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

// declare module '@fastify/jwt' {
//     interface FastifyJWT {
//         user: {
//             id: string | number;
//             email?: string;
//             isAdmin?: boolean;
//         }
//     }
// }

dotenv.config();

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
});

const redis = createClient({
    // url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
});
redis.connect()
    .then(() => console.log('Connected to Redis'))
    .catch((err) => {
        console.error('An error occurred connecting to Redis:', err);
        process.exit(1);
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
        let token: string | undefined;
        const authHeader = request.headers.authorization;
        if (authHeader?.startsWith('Bearer ')) {
            token = authHeader.substring(7);
        } else {
            token = request.cookies?.checkpoint_jwt;
        }

        if (!token) {
            return reply.code(401).send({ error: 'No token provided' });
        }

        // 1) Verify JWT with jose
        const payload = await verifyToken(token);

        // 2) Optionally store the payload on request
        // (so the rest of your code can do request.jwtUser.userId)
        request.jwtUser = payload as { userId: string | number; isAdmin?: boolean };

        // 3) Check session in Redis (like before)
        const sessionKey = `session:${token}`;
        const sessionUserId = await redis.get(sessionKey);
        if (!sessionUserId) {
            return reply.code(401).send({ error: 'Invalid session' });
        }

        // proceed
    } catch (err) {
        reply.code(401).send({ error: 'Unauthorized' });
    }
});

const rpName = 'Checkpoint';
const rpID = process.env.DOMAIN || 'localhost';
const origin = process.env.FRONTEND_URL || `https://${rpID}`;

// Register plugins
try {
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
    server.register(passport.secureSession());
    server.register(import('@fastify/jwt'), {
        secret: process.env.JWT_SECRET!,
        sign: {
            expiresIn: '60d'
        },
        namespace: 'jwtUser',
        decoratorName: 'jwtUser'
    });
    console.log('Registered plugins');
} catch (err) {
    console.error('Error registering plugins:', err);
    process.exit(1);
}


// server.after(() => {
//     console.log('Server started');
//     console.log('has jwtUser? ' + server.hasDecorator('jwtUser'));
//     console.log('fasitfy.jwtUser = ' + server.jwtUser);
// });

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
    password: z.string().min(8).optional(),
    profile: z.object({
        address: z.object({
            street: z.string().optional(),
            street2: z.string().optional(),
            city: z.string().optional(),
            state: z.string().optional(),
            zip: z.string().optional(),
            country: z.string().optional(),
        }).optional(),
        department: z.string().optional(),
        dateOfBirth: z.date().optional(),
        first_name: z.string().optional(),
        last_name: z.string().optional(),
        profile_pic: z.string().optional(),
        phone: z.string().optional(),
    }),
    public_key: z.string().optional(),
    private_key: z.string().optional(),
    authMethod: z.string().optional(),
    confirmPassword: z.string().optional(),   
    password_changed_at: z.date().optional(),
});

const LoginSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
});

type LoginSchemaType = z.infer<typeof LoginSchema>;

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

function stringToBuffer(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

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
    const user_roles = await pool.query(
        `SELECT role_id
        FROM user_roles
        WHERE user_id = $1`,
        [userId]
    );

    const roles_res = await pool.query(
        `SELECT permissions
        FROM roles
        WHERE id = ANY($1)`,
        [user_roles.rows.map(row => row.role_id)]
    );
    const allPerms = new Set<string>();
    for (const row of roles_res.rows) {
        const permsArray: string[] = row.permissions?.permissions || row.permissions;
        // If row.permissions is { permissions: [...] }, adjust accordingly
        permsArray.forEach(p => allPerms.add(p));
    }

    // console.log('User permissions:', allPerms);
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

// encrypt user information (name, address, dob, etc) using private key


// Routes

/*
/api/auth

Handles all authentication-related routes
*/

server.post<{ Body: LoginSchemaType }>('/api/auth/login', async (request, reply) => {
    try {
        const validated = LoginSchema.parse(request.body);
        const {email, password} = validated;
    
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
    
        const rolesRes = await pool.query(
            `SELECT r.name 
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        WHERE ur.user_id = $1`,
            [user.id]
        );
        const roles = rolesRes.rows.map(row => row.name);
        const isAdmin = roles.includes('admin');
        // console.log(roles, isAdmin, user.id);
    
        // Sign and return a JWT token
        // console.log('server.jwtUser:' + server.jwtUser);
        const token = await signToken(
            { userId: user.id },
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

server.post('/api/auth/register', async (request, reply) => {
    
    try {
        console.log('Received body data: ', request.body);
        const userBody = request.body as any;
        // You can parse verbosely using safeParse:
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

        // This fails because extra fields like "department" and "authMethod" 
        // are not defined in UserSchema, and dateOfBirth is passed as a string 
        // when z.date() expects a Date object.
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

        const userId = await generateUUID();
        const insertFields = {
            id: userId,
            email: body.email,
            first_name: body.profile.first_name,
            last_name: body.profile.last_name,
            public_key: publicKey,
            private_key: encryptedPrivateKey,
            dateOfBirth: body.profile.dateOfBirth,
            phone_number: body.profile.phone,
            address: body.profile.address,
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
            // hash the password using argon2
            const hashedPassword = await argon2.hash(body.password);
            // use auth_methods table to store hashed password if set
            await pool.query(
                'INSERT INTO auth_methods (user_id, type, metadata) VALUES ($1, $2, $3)',
                [result.rows[0].id, 'password', JSON.stringify(hashedPassword)]
            );
        }

        const token = await signToken(
            { userId: result.rows[0].id },
        );
        await redis.set(`session:${token}`, String(result.rows[0].id), {
            EX: 60 * 60 * 24 * 60 // 60 days;
        });
        return { user: result.rows[0], token };
    } catch (err: any) {
        if (err.constraint === 'users_email_key') {
            reply.code(400);
            return { error: 'Email already exists' };
        } else if (err instanceof ZodError) {
            reply.code(400);
            return { error: 'Invalid request', details: err.issues };
        } else {
            throw err;
        }
    }
});

server.post<{ Body: { email: string } }>('/api/auth/passkey/login/start', async (request, reply) => {
    try {
        const { email } = request.body;

        // Ensure the user exists
        const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (userResult.rowCount === 0) {
            reply.code(400).send({ error: 'User does not exist.' });
            return;
        }
        const user = userResult.rows[0];

        // Retrieve stored passkey credentials for the user
        const credentialsResult = await pool.query(
            'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2',
            [user.id, 'passkey']
        );
        const allowedCredentials = credentialsResult.rows.map((row) => {
            const metadata = row.metadata;
            return {
                id: metadata.credentialID,
                type: 'public-key'
            };
        });

        // Generate authentication options for passkey login
        const options = await generateAuthenticationOptions({
            rpID,
            allowCredentials: allowedCredentials,
            userVerification: 'preferred',
        });

        // Store only the challenge in Redis for later verification
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


server.post<{ Body: { email: string, response: AuthenticationResponseJSON } }>('/api/auth/passkey/login/complete', async (request, reply) => {
    const { email, response } = request.body;

    // Ensure the user exists
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rowCount === 0) {
        console.log('User does not exist:', email);
        reply.code(400).send({ error: 'User does not exist.' });
        return;
    }
    const user = userResult.rows[0];

    // Retrieve the expected challenge from Redis
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
        // Get the credential info from auth_methods
        const credentialResult = await pool.query(
            'SELECT metadata FROM auth_methods WHERE user_id = $1 AND type = $2 AND metadata->>\'credentialID\' = $3',
            [user.id, 'passkey', response.id]
        );
        if (credentialResult.rowCount === 0) {
            reply.code(400).send({ error: 'Invalid credential provided.' });
            return;
        }
        const storedCredential = credentialResult.rows[0].metadata;

        // Verify the authentication response using @simplewebauthn/server
        const verification = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin: process.env.FRONTEND_URL || 'http://localhost:3000',
            expectedRPID: process.env.DOMAIN || 'localhost',
            credential: {
                id: response.id,
                publicKey: storedCredential.publicKey,
                counter: storedCredential.counter,
                transports: ['internal'],
            }
        });

        if (verification.verified) {
            console.log('Passkey authentication successful:', verification);
            // Optionally update the credential counter here if needed

            // Issue a JWT on successful passkey authentication
            const rolesRes = await pool.query(
                `SELECT r.name 
                 FROM user_roles ur
                 JOIN roles r ON ur.role_id = r.id
                 WHERE ur.user_id = $1`,
                [user.id]
            );
            const roles = rolesRes.rows.map(row => row.name);

            const token = await signToken({ userId: user.id });
            await redis.set(`session:${token}`, String(user.id), {
                EX: 60 * 60 * 24 * 60 // 60 days
            });

            // Remove the used challenge from Redis
            await redis.del(`authentication_${user.id}`);

            reply.send({ token });
        } else {
            reply.code(400).send({ error: 'Authentication failed.' });
            console.log('Authentication failed:', verification);
        }
    } catch (err) {
        console.error('Passkey login complete error:', err);
        reply.code(400).send({ error: 'Invalid authentication response.' });
    }
});

server.post('/api/auth/passkey/register/start', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const { userId } = request.jwtUser; // Get the authenticated user's ID
            const { name } = request.body as { name: string };

            if (!name) {
                return reply.code(400).send({ error: 'Name is required' });
            }

            // Get user from database
            const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
            if (userResult.rowCount === 0) {
                return reply.code(404).send({ error: 'User not found' });
            }
            const user = userResult.rows[0];

            const userIdBuffer = stringToBuffer(user.id);

            console.log('Generating registration options...');

            // Generate registration options
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

            // Store challenge in Redis for verification later
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

server.options('/api/auth/passkey/register/start', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {

        const { userId } = request.jwtUser; // Get the authenticated user's ID
        const { name } = request.body as { name: string };

        // Get user from database
        const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
        if (userResult.rowCount === 0) {
            return reply.code(404).send({ error: 'User not found' });
        }
        const user = userResult.rows[0];
        // send passkey registration options
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

server.post('/api/auth/passkey/register/complete', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const { userId } = request.jwtUser;
            const expectedChallenge = await redis.get(`passkey_challenge:${userId}`);
            if (!expectedChallenge) {
                return reply.code(400).send({ error: 'Challenge expired or invalid' });
            }



            try {
                // Verify the registration response using @simplewebauthn/server
                const verification = await verifyRegistrationResponse({
                    response: request.body as RegistrationResponseJSON,
                    expectedChallenge,
                    expectedOrigin: process.env.FRONTEND_URL || 'http://localhost:3000',
                    expectedRPID: process.env.DOMAIN || 'localhost',
                    // attestationType: 'none',
                    // authenticatorSelection: {
                    //     userVerification: 'preferred'
                    // },
                });

                if (verification.verified) {
                    // Store the credential in the database
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

server.get('/api/auth/passkey', {
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

server.delete('/api/auth/passkey/:credentialId', {
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

server.put('/api/auth/change-password', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { oldPassword, newPassword } = request.body as {
            oldPassword: string;
            newPassword: string;
        };
        const userId = request.jwtUser.userId;

        console.log('changing password for user:', userId);

        // Check if user has permission or if you rely solely on user matching
        // E.g. if ( ! await hasPermission(userId, 'users.updateSelf') ) ...

        try {
            // 1) Get current hashed password
            const authMethodRes = await pool.query(
                `SELECT metadata FROM auth_methods 
            WHERE user_id = $1 AND type = 'password'`,
                [userId]
            );
            if (authMethodRes.rowCount === 0) {
                return reply.status(400).send({ error: 'No password set' });
            }
            const currentHashedPassword = authMethodRes.rows[0].metadata;

            // 2) Verify old password
            const validOld = await argon2.verify(currentHashedPassword, oldPassword);
            if (!validOld) {
                return reply.status(401).send({ error: 'Incorrect old password' });
            }

            // 3) Hash new password
            const newHashed = await argon2.hash(newPassword);
            console.log(authMethodRes.rows[0].metadata, newHashed, validOld);

            // 4) Update DB
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

server.get('/api/auth/sessions', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const userId = request.jwtUser.userId;

            // Get all sessions from Redis for this user
            const sessions = [];
            const keys = await redis.keys(`session:*`);

            for (const key of keys) {
                const storedUserId = await redis.get(key);
                if (storedUserId === String(userId)) {
                    // Get token from key (remove 'session:' prefix)
                    const token = key.replace('session:', '');

                    try {
                        // Decode JWT to get device info
                        const decoded = await decodeToken(token);

                        // Add to sessions array if valid
                        sessions.push({
                            id: token,
                            device: decoded.device || 'Unknown Device',
                            browser: decoded.browser || 'Unknown Browser',
                            location: decoded.location || 'Unknown Location',
                            lastActive: decoded.iat ? new Date(decoded.iat * 1000).toISOString() : new Date().toISOString(),
                            current: request.headers.authorization?.includes(token) || false
                        });
                    } catch (err) {
                        // Skip invalid tokens
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

server.delete('/api/auth/sessions/:sessionId', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const { sessionId } = request.params as { sessionId: string };
            const userId = request.jwtUser.userId;

            // Check if session belongs to user
            const storedUserId = await redis.get(`session:${sessionId}`);
            if (!storedUserId || storedUserId !== String(userId)) {
                return reply.code(403).send({ error: 'Session not found or unauthorized' });
            }

            // Remove session from Redis
            await redis.del(`session:${sessionId}`);

            return { success: true };
        } catch (error) {
            reply.code(500).send({ error: 'Failed to revoke session' });
        }
    }
});

server.delete('/api/auth/sessions', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        try {
            const userId = request.jwtUser.userId;
            const currentToken = request.headers.authorization?.replace('Bearer ', '');

            // Get all sessions for user
            const keys = await redis.keys('session:*');

            for (const key of keys) {
                const storedUserId = await redis.get(key);
                const token = key.replace('session:', '');

                // Skip current session and sessions not belonging to user
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

server.get('/api/auth/sso/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

server.get('/api/auth/sso/google/callback', {
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
        const token = await signToken(
            { userId: user.id },
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

server.get('/api/auth/sso/line',
    passport.authenticate('line', {
        scope: ['profile', 'openid', 'email']
    })
);

server.get('/api/auth/sso/line/callback', {
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
            console.log(`Received request from user ${request.jwtUser.userId} on route GET /api/users`);
            const canSearch = await hasPermission(String(request.jwtUser.userId), 'users.search');
            if (canSearch) {
                console.log('User has permission to search users');
            } else {
                console.log('User does not have permission to search users');
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
                'SELECT id, email, first_name, last_name, public_key, profile_picture, dateOfBirth, phone_number, address, created_at FROM users WHERE id = $1',
                [id]
            );
            // console.log(result.rows[0]);
            let json_encoded_address = JSON.parse(result.rows[0].address);
            let parsedResult = {
                id: result.rows[0].id,
                email: result.rows[0].email,
                public_key: result.rows[0].public_key,
                profile: {
                    first_name: result.rows[0].first_name,
                    last_name: result.rows[0].last_name,
                    profile_picture: result.rows[0].profile_picture,
                    dateOfBirth: result.rows[0].dateofbirth,
                    phone: result.rows[0].phone_number,
                    address: json_encoded_address,
                },
                created_at: result.rows[0].created_at ?? new Date(),
            };
            let outgoing_ = UserSchema.parse(parsedResult);

            // get date time last changed password
            const password_changed_at = await pool.query(
                'SELECT created_at FROM auth_methods WHERE user_id = $1 AND type = $2',
                [id, 'password']
            );

            // store last password change date in the first row
            outgoing_.password_changed_at = password_changed_at.rows[0]?.created_at;

            if (!outgoing_) {
                return reply.status(404).send({ error: 'User not found' });
            }
            reply.send(outgoing_);
        } catch (err) {
            console.log(err);
            reply.status(500).send({ message: 'An error occurred: ' + err });
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
                [toUpdate.email, toUpdate.profile.first_name, toUpdate.profile.last_name, id]
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
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
              return reply.status(403).send({ error: 'Forbidden' });
            }

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

// user profile picture

server.post('/api/users/:id/profile-picture', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        const files = await request.files();
        const file = files[0];  // Get first uploaded file
        if (!file) {
            return reply.status(400).send({ error: 'No file uploaded' });
        }

        // Read file buffer
        const buffer = await file.toBuffer();

        // Convert to base64 string for storage
        const profile_picture = buffer.toString('base64');

        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                'UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING id, profile_picture',
                [profile_picture, id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            } else {
                // save the image to the file system
                try {
                    fs.writeFileSync(`../public/profile_images/${id}.png`, buffer);
                } catch (err) {
                    console.error(err);
                    return reply.status(500).send({ error: 'Failed to save image' });
                }
            }
            reply.send(result.rows[0]);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// get user's profile picture
server.get('/api/users/:id/profile-picture', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        try {
            const result = await pool.query(
                'SELECT profile_picture FROM users WHERE id = $1',
                [id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            }
            const profile_picture = result.rows[0].profile_picture;
            if (!profile_picture) {
                return reply.status(404).send({ error: 'Profile picture not found' });
            }
            reply.send({ profile_picture });
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// update user's profile picture
server.put('/api/users/:id/profile-picture', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        const files = await request.files();
        const file = files[0];  // Get first uploaded file
        if (!file) {
            return reply.status(400).send({ error: 'No file uploaded' });
        }

        // Read file buffer
        const buffer = await file.toBuffer();

        // Convert to base64 string for storage
        const profile_picture = buffer.toString('base64');

        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                'UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING id, profile_picture',
                [profile_picture, id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            } else {
                // save the image to the file system
                try {
                    fs.writeFileSync(`../public/profile_images/${id}.png`, buffer);
                } catch (err) {
                    console.error(err);
                    return reply.status(500).send({ error: 'Failed to save image' });
                }
            }
            reply.send(result.rows[0]);
        } catch (err) {
            reply.status(500).send({ error: 'Database error' });
        }
    },
});

// delete user's profile picture
server.delete('/api/users/:id/profile-picture', {
    onRequest: [server.authenticate],
    handler: async (request, reply) => {
        const { id } = request.params as UserIdParam;
        try {
            if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                return reply.status(403).send({ error: 'Forbidden' });
            }

            const result = await pool.query(
                'UPDATE users SET profile_picture = NULL WHERE id = $1 RETURNING id',
                [id]
            );
            if (result.rowCount === 0) {
                return reply.status(404).send({ error: 'User not found' });
            } else {
                // delete the image from the file system
                try {
                    fs.unlinkSync(`../public/profile_images/${id}.png`);
                } catch (err) {
                    console.error(err);
                    return reply.status(500).send({ error: 'Failed to delete image' });
                }
            }
            reply.send({ success: true });
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