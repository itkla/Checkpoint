import { FastifyPluginAsync } from "fastify";
import { pool } from "../utils/db";
import { hasPermission } from "../utils/permissions";

export const rolesRoutes: FastifyPluginAsync = async (server, opts): Promise<void> => {
    server.get('/', {
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
    
    server.post('/', {
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
    
    server.post('/:roleId/permissions', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const userId = request.jwtUser.userId;
            if (!(await hasPermission(String(userId), 'roles.update'))) {
                return reply.status(403).send({ error: 'Forbidden' });
            }
    
            const { roleId } = request.params as { roleId: string };
            const { permissionsToAdd } = request.body as { permissionsToAdd: string[] };
    
            try {
                const rRes = await pool.query(`SELECT permissions FROM roles WHERE id = $1`, [roleId]);
                if (rRes.rowCount === 0) {
                    return reply.status(404).send({ error: 'Role not found' });
                }
                let perms = rRes.rows[0].permissions || [];
                perms = Array.from(new Set([...perms, ...permissionsToAdd])); // deduplicate
                await pool.query(`UPDATE roles SET permissions = $1 WHERE id = $2`, [JSON.stringify(perms), roleId]);
                reply.send({ success: true, updatedPermissions: perms });
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });
};

export default rolesRoutes;