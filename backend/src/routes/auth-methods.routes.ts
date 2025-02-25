import { FastifyPluginAsync } from "fastify";
import { pool } from "../utils/db";
import { AuthMethodIdParam } from "../types/AuthMethodIdParam";

export const authMethodsRoutes: FastifyPluginAsync = async (server, opts): Promise<void> => {
    server.patch('/:authMethodId', {
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
    
    // DELETE AN AUTH METHOD
    server.delete('/:authMethodId', {
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
};

export default authMethodsRoutes;