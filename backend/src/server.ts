import fastify from 'fastify';
import cors from '@fastify/cors';
// import jwt, { JWT } from '@fastify/jwt';
import Multipart from '@fastify/multipart';

import { signToken, verifyToken, decodeToken } from './utils/jwt-utils';
import cookie from '@fastify/cookie';
import { pool, redis } from './utils/db';
// import bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import { z, ZodError } from 'zod';
import dotenv from 'dotenv';
import fs, { write } from 'fs';
import path from 'path';
import * as openpgp from 'openpgp';
import { createClient } from 'redis';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

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

import {
    isoBase64URL,
} from '@simplewebauthn/server/helpers';

import passport, { PassportUser } from '@fastify/passport';
import fastifySecureSession from '@fastify/secure-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LineStrategy } from 'passport-line';

import { encryptPrivateKey, EncryptedPayload } from './utils/crypto-utils';
import { profile } from 'console';
import { json } from 'stream/consumers';
import { get } from 'http';
import authMethodsRoutes from './routes/auth-methods.routes';
import authRoutes from './routes/auth.routes';
import userRoutes from './routes/user.routes';
import rolesRoutes from './routes/roles.routes';
import ssoRoutes from './routes/sso.routes';
import logsRoutes from './routes/logs.routes';

// type UserIdParam = {
//     id: string;  // The 'id' param is a string (e.g. random 20-char user ID)
// };

// type AuthMethodIdParam = {
//     authMethodId: string;
//     credentialId?: string;
// };

// type ProviderIdParam = {
//     id: string;
// };

// type RoleIdBody = {
//     roleId: number;  // The body contains 'roleId' when assigning a role to a user
// };

// type SsoConnectionBody = {
//     provider_id: number;
//     external_user_id: string;
// };

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

// const pool = new Pool({
//     user: process.env.DB_USER,
//     password: process.env.DB_PASSWORD,
//     host: process.env.DB_HOST,
//     port: Number(process.env.DB_PORT),
//     database: process.env.DB_NAME,
// });

// const redis = createClient({
//     // url: `redis://:${process.env.REDIS_PASSWORD}@${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
// });
// redis.connect()
//     .then(() => console.log('Connected to Redis'))
//     .catch((err) => {
//         console.error('An error occurred connecting to Redis:', err);
//         process.exit(1);
//     });

const server = fastify({
    logger: true,
    https: {
        key: fs.readFileSync(path.join(__dirname, '../../ssl-certs/backend/localhost-key.pem')),
        cert: fs.readFileSync(path.join(__dirname, '../../ssl-certs/backend/localhost.pem'))
    }
});

server.register(Multipart);

server.register(cookie, {
    secret: process.env.COOKIE_SECRET || 'supersecret',
    parseOptions: {}
});

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

        // Verify JWT with jose
        const payload = await verifyToken(token);

        // Optionally store the payload on request
        // (so the rest of code can do request.jwtUser.userId)
        request.jwtUser = payload as { userId: string | number; isAdmin?: boolean };

        // Check session in Redis (like before)
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

    // register routes
    server.register(authMethodsRoutes, {prefix: '/api/auth-methods'});
    server.register(authRoutes, {prefix: '/api/auth'});
    server.register(userRoutes, {prefix: '/api/users'});
    server.register(rolesRoutes, {prefix: '/api/roles'});
    server.register(ssoRoutes, {prefix: '/api/sso'});
    server.register(logsRoutes, {prefix: '/api/logs'});

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