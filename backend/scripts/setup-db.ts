import { Pool } from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: 'postgres',
});

async function setupDatabase() {
    try {
        await pool.query(`
      SELECT 'CREATE DATABASE checkpoint'
      WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'checkpoint')
    `);

        console.log('Database setup completed');
    } catch (error) {
        console.error('Database setup failed:', error);
        process.exit(1);
    } finally {
        await pool.end();
    }
}

setupDatabase();