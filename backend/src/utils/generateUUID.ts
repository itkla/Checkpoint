import { Pool } from 'pg';

const pool = new Pool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: Number(process.env.DB_PORT),
    database: process.env.DB_NAME,
});

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

export default generateUUID;