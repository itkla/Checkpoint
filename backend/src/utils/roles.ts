import { pool } from './db';

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

async function hasPermission(userId: string, permission: string): Promise<boolean> {
    const allPerms = await getUserPermissions(userId);
    return allPerms.has(permission) || allPerms.has('*');
}

async function hasRole(userId: string, roleName: string): Promise<boolean> {
    const result = await pool.query(
        `SELECT r.name 
    FROM roles r 
    JOIN user_roles ur ON r.id = ur.role_id 
    WHERE ur.user_id = $1 AND r.name = $2`,
        [userId, roleName]
    );
    return result.rowCount > 0;
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

export { requireRole, hasPermission, hasRole, getUserPermissions };