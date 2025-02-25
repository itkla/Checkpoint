import { Pool } from 'pg';
import { createClient } from 'redis';
import fs from 'fs';
import path from 'path';

import dotenv from 'dotenv';
dotenv.config();

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
});

const redis = createClient();
redis.connect()
    .then(() => console.log('Connected to Redis'))
    .catch((err) => {
        console.error('An error occurred connecting to Redis:', err);
        process.exit(1);
    });

async function initDB() {
    const client = await pool.connect();
    try {
        const migrationsPath = path.join(__dirname, '../../migrations');
        const migrationFiles = fs.readdirSync(migrationsPath)
            .filter(file => file.endsWith('.sql'))
            .sort(); // Ensures migrations run in order

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

export { initDB };

export { pool, redis };