import { FastifyPluginAsync } from "fastify";
import { pool, redis } from "../utils/db";
import { hasRole } from "../utils/roles";
import passport, { PassportUser } from '@fastify/passport';
import { ProviderIdParam } from "../types/ProviderIdParam";
import { signToken, verifyToken, decodeToken } from '../utils/jwt-utils';

export const ssoRoutes: FastifyPluginAsync = async (server, opts) => {
    server.get('/', {
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
    
    server.post('/', {
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
    server.patch('/:id', {
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
    server.delete('/:id', {
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
};

export default ssoRoutes;