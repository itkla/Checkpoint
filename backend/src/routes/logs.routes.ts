import { FastifyPluginAsync } from "fastify";
import { pool } from "../utils/db";

export const logsRoutes: FastifyPluginAsync = async function (server, opts): Promise<void> {
    server.get('/', {
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
};

export default logsRoutes;