// src/server.ts
import fastify from 'fastify';
import cors from '@fastify/cors';
import jwt, { JWT } from '@fastify/jwt';
import { Pool } from 'pg';

// Extend FastifyInstance type to include JWT
declare module 'fastify' {
    interface FastifyInstance {
        jwt: JWT;
    }
}
// import bcrypt from 'bcrypt';
import * as argon2 from 'argon2';
import { z } from 'zod';
import dotenv from 'dotenv';
import fs from 'fs';
import path from 'path';
import * as openpgp from 'openpgp';

dotenv.config();

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
});

const server = fastify();

// Register plugins
server.register(cors, {
    origin: process.env.FRONTEND_URL,
    credentials: true
});

server.register(jwt, {
    secret: process.env.JWT_SECRET!
});

// Schema definitions
const UserSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
    first_name: z.string().optional(),
    last_name: z.string().optional(),
    public_key: z.string().optional(),
    private_key: z.string().optional(),
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

// Routes
server.post('/api/register', async (request, reply) => {
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

        if(body.password) {
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

server.post('/api/login', async (request, reply) => {
    const body = UserSchema.parse(request.body);

    const result = await pool.query('SELECT * FROM users WHERE email = $1', [body.email]);
    const user = result.rows[0];

    if (!user || !(await argon2.verify(user.password, body.password))) {
        reply.code(401);
        return { error: 'Invalid credentials' };
    }

    const token = server.jwt.sign({ userId: user.id });
    return { user: { id: user.id, email: user.email, name: user.name }, token };
});

// Protected route example
// server.get('/api/user', {
//     onRequest: [server.authenticate],
// }, async (request) => {
//     const userId = request.user.userId;
//     const result = await pool.query('SELECT id, email, name FROM users WHERE id = $1', [userId]);
//     return result.rows[0];
// });

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

server.get('/api/users/:fnc', async (request, reply) => {
    const fnc = request.params;
    try {
        if(request.headers.authorization) {
            const token = request.headers.authorization.split(' ')[1];
            const decoded = server.jwt.decode<{ userId: number }>(token);
            if(decoded) {
                switch (fnc) {
                    case 'all':
                        const result = await pool.query('SELECT * FROM users');
                        return result.rows;
                    default:
                        return { error: 'Invalid function' };
                }
            }
        }
    } catch (err) {
        console.error(err);
        return { error: 'Invalid token' };
    }
});

start();