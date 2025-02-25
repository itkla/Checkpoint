import { FastifyPluginAsync } from 'fastify';
import { pool } from '../utils/db';
import { UserSchema, UserSchemaType } from '../types/UserSchema';
import { hasPermission } from '../utils/roles';
import fs from 'fs';
import { UserIdParam } from '../types/UserIdParam';
import { SsoConnectionBody } from '../types/SsoConnectionBody';
import { RoleIdBody } from '../types/RoleIdBody';
import { encryptPII, decryptPII } from '../utils/encryptPII';

export const userRoutes: FastifyPluginAsync = async (server, opts) => {
    server.get('/exists', {
        handler: async (request, reply) => {
            try {
                const { email } = request.query as { email: string };
                const result = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
                return { exists: result.rowCount > 0 };
            } catch (err) {
                console.error(`An error has occurred on route GET /api/users/exists: ${err}`);
                return reply.status(500).send({ error: 'Database error' });
            }
        },
    });
    
    server.get('/', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                console.log(`Received request from user ${request.jwtUser.userId} on route GET /api/users`);
                const canSearch = await hasPermission(String(request.jwtUser.userId), 'users.search');
                if (canSearch) {
                    console.log('User has permission to search users');
                } else {
                    console.log('User does not have permission to search users');
                    return reply.status(403).send({ error: 'Forbidden' });
                }
    
                const { search, page = 1, pageSize = 10 } = request.query as {
                    search?: string;
                    page?: number;
                    pageSize?: number;
                };
                const offset = (page - 1) * pageSize;
                
                try {
                    let query;
                    let params;
                    
                    // If search parameter is provided, filter results
                    if (search && search.trim() !== '') {
                        const likeQuery = `%${search}%`;
                        query = `
                            SELECT *
                            FROM users
                            WHERE email ILIKE $1
                                OR first_name ILIKE $1
                                OR last_name ILIKE $1
                            ORDER BY created_at DESC
                            LIMIT $2 OFFSET $3
                        `;
                        params = [encryptPII(likeQuery), pageSize, offset];
                    } else {
                        // If no search parameter, return all users with pagination
                        query = `
                            SELECT *
                            FROM users
                            ORDER BY created_at DESC
                            LIMIT $1 OFFSET $2
                        `;
                        params = [pageSize, offset];
                    }
    
                    const result = await pool.query(query, params);
                    // console.log(result.rows);
                    
                    // Also get total count for pagination
                    const countQuery = search && search.trim() !== '' 
                        ? `SELECT COUNT(*) FROM users WHERE email ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1`
                        : `SELECT COUNT(*) FROM users`;
                        
                    const countParams = search && search.trim() !== '' ? [encryptPII(`%${search}%`)] : [];
                    const countResult = await pool.query(countQuery, countParams);
                    const totalCount = parseInt(countResult.rows[0].count);
                    
                    const _outgoing = result.rows.map((row: any) => {
                        let json_encoded_address = JSON.parse(decryptPII(row.address));
                        let parsedResult = {
                            id: row.id,
                            email: row.email,
                            public_key: row.public_key,
                            created_at: row.created_at,
                            two_factor_enabled: row.two_factor_enabled,
                            profile: {
                                first_name: decryptPII(row.first_name),
                                last_name: decryptPII(row.last_name),
                                profile_picture: row.profile_picture || '',
                                dateOfBirth: decryptPII(row.dateofbirth),
                                phone: decryptPII(row.phone_number),
                                address: json_encoded_address,
                            },
                        };
                        return UserSchema.parse(parsedResult);
                    });
                    console.log(_outgoing);
                    
                    reply.send({
                        users: _outgoing,
                        pagination: {
                            total: totalCount,
                            page,
                            pageSize,
                            pages: Math.ceil(totalCount / pageSize)
                        }
                    });
                } catch (err) {
                    console.error('An error occurred:', err);
                    reply.status(500).send({ error: 'Database error' });
                }
            } catch (err) {
                console.error('Server error:', err);
                reply.status(500).send({ error: 'Server error' });
            }
        },
    });

    server.get('/me', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { userId } = request.jwtUser;
            try {
                const profile = await pool.query(
                    'SELECT * FROM users WHERE id = $1',
                    [userId]
                );
                const auth = await pool.query(
                    `SELECT type, is_preferred, metadata, created_at, last_used_at
                     FROM auth_methods
                     WHERE user_id = $1`,
                    [userId]
                );
                if (profile.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                let json_encoded_address = JSON.parse(decryptPII(profile.rows[0].address));
                let parsedResult = {
                    id: profile.rows[0].id,
                    email: profile.rows[0].email,
                    public_key: profile.rows[0].public_key,
                    created_at: profile.rows[0].created_at,
                    two_factor_enabled: profile.rows[0].two_factor_enabled,
                    profile: {
                        first_name: decryptPII(profile.rows[0].first_name),
                        last_name: decryptPII(profile.rows[0].last_name),
                        profile_picture: profile.rows[0].profile_picture || '',
                        dateOfBirth: new Date(decryptPII(profile.rows[0].dateofbirth)),
                        phone: decryptPII(profile.rows[0].phone_number),
                        address: json_encoded_address,
                    },
                };
                let outgoing_ = {
                    user: UserSchema.parse(parsedResult),
                    auth: auth.rows,
                }
                reply.send(outgoing_);
            } catch (err) {
                console.error(err);
                reply.status(500).send({ error: 'Database error' });
            }
        }
    });
    server.get('/:id', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    'SELECT * FROM users WHERE id = $1',
                    [id]
                );
                console.log(result.rows[0]);
                let json_encoded_address = JSON.parse(decryptPII(result.rows[0].address));
                let parsedResult = {
                    id: result.rows[0].id,
                    email: result.rows[0].email,
                    public_key: result.rows[0].public_key,
                    created_at: result.rows[0].created_at,
                    two_factor_enabled: result.rows[0].two_factor_enabled,
                    profile: {
                        first_name: decryptPII(result.rows[0].first_name),
                        last_name: decryptPII(result.rows[0].last_name),
                        profile_picture: result.rows[0].profile_picture || '',
                        dateOfBirth: decryptPII(result.rows[0].dateofbirth),
                        phone: decryptPII(result.rows[0].phone_number),
                        address: json_encoded_address,
                    },
                };
                let outgoing_ = UserSchema.parse(parsedResult);
                console.log(outgoing_);
                const password_changed_at = await pool.query(
                    'SELECT created_at FROM auth_methods WHERE user_id = $1 AND type = $2',
                    [id, 'password']
                );
                outgoing_.password_changed_at = password_changed_at.rows[0]?.created_at;

                if (!outgoing_) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                reply.send(outgoing_);
            } catch (err) {
                reply.status(500).send({ message: 'An error occurred: ' + err });
            }
        },
    });

    server.put('/:id', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            console.log(`Received request from user ${request.jwtUser.userId} on route PUT /api/users/${id}`);
            console.log('Data to update:', JSON.stringify(request.body, null, 2));

            console.log(`Comparing: JWT userId (${typeof request.jwtUser.userId}) ${request.jwtUser.userId} vs. param id (${typeof id}) ${id}`);
            try {
                const toUpdate = UserSchema.parse(request.body);
                try {
                    if (String(request.jwtUser.userId) !== String(id) && !request.jwtUser.isAdmin) {
                        return reply.status(403).send({ error: 'Forbidden' });
                    }
                    const addressString = typeof toUpdate.profile.address === 'object'
                        ? JSON.stringify(toUpdate.profile.address)
                        : toUpdate.profile.address;

                    const dob = (toUpdate.profile.dateOfBirth as Date).toISOString();
    
                    const result = await pool.query(
                        `UPDATE users 
                         SET email = $1, 
                             first_name = $2, 
                             last_name = $3, 
                             dateOfBirth = $4, 
                             phone_number = $5, 
                             address = $6, 
                             profile_picture = $7 
                         WHERE id = $8 RETURNING *`,
                        [
                            toUpdate.email,
                            encryptPII(toUpdate.profile.first_name),
                            encryptPII(toUpdate.profile.last_name),
                            encryptPII(dob),
                            encryptPII(toUpdate.profile.phone),
                            encryptPII(addressString), // Use the stringified address
                            toUpdate.profile.profile_picture,
                            id
                        ]
                    );
                    if (result.rowCount === 0) {
                        return reply.status(404).send({ error: 'User not found' });
                    }
                    reply.send(result.rows[0]);
                } catch (err) {
                    console.error(err);
                    reply.status(500).send({ error: 'Database error' });
                };
            } catch (err) {
                console.error(err);
                return reply.status(400).send({ error: 'Invalid data' });
            }
        }
    });

    server.delete('/:id', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            // const requester_permissions = getUserPermissions(String(request.jwtUser.userId));
            try {
                if (request.jwtUser.userId !== id && !hasPermission(String(request.jwtUser.userId), 'users.delete')) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    'DELETE FROM users WHERE id = $1 RETURNING id',
                    [id]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                reply.send({ success: true, userId: id });
            } catch (err) {
                console.log(err);
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.get('/:id/auth-methods', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    `
                SELECT id, type, is_preferred, metadata, created_at, last_used_at
                  FROM auth_methods
                 WHERE user_id = $1
              `,
                    [id]
                );
                reply.send(result.rows);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.get('/:email/login-auth-methods', {
        handler: async (request, reply) => {
            const { email } = request.params as { email: string };
            try {
                const user_id = await pool.query(
                    'SELECT id FROM users WHERE email = $1',
                    [email]
                );
                if (user_id.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                const result = await pool.query(
                    `
                SELECT id, type, is_preferred, metadata, created_at, last_used_at
                  FROM auth_methods
                 WHERE user_id = $1
              `,
                    [user_id.rows[0].id]
                );
                reply.send(result.rows);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.post('/:id/auth-methods', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            const { type, is_preferred, metadata } = request.body as {
                type: 'password' | 'passkey' | 'biometric' | 'sso';
                is_preferred?: boolean;
                metadata?: any;
            };

            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    `
                INSERT INTO auth_methods (user_id, type, is_preferred, metadata)
                     VALUES ($1, $2, COALESCE($3, false), COALESCE($4, '{}'))
                  RETURNING id, type, is_preferred, metadata, created_at, last_used_at
              `,
                    [id, type, is_preferred, metadata]
                );
                reply.send(result.rows[0]);
            } catch (err: any) {
                if (err.code === '23503') {
                    return reply.status(404).send({ error: 'User not found' });
                }
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.get('/:id/sso', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            try {
                // if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                //   return reply.status(403).send({ error: 'Forbidden' });
                // }

                const result = await pool.query(
                    `
                SELECT usc.id,
                       usc.provider_id,
                       sp.name as provider_name,
                       usc.external_user_id,
                       usc.created_at
                  FROM user_sso_connections usc
                  JOIN sso_providers sp ON usc.provider_id = sp.id
                 WHERE usc.user_id = $1
              `,
                    [id]
                );
                reply.send(result.rows);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.post('/:id/sso', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            const { provider_id, external_user_id } = request.body as SsoConnectionBody;

            try {
                // if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                //   return reply.status(403).send({ error: 'Forbidden' });
                // }

                const result = await pool.query(
                    `
                INSERT INTO user_sso_connections (user_id, provider_id, external_user_id)
                     VALUES ($1, $2, $3)
                  RETURNING id, user_id, provider_id, external_user_id, created_at
              `,
                    [id, provider_id, external_user_id]
                );
                reply.send(result.rows[0]);
            } catch (err: any) {
                if (err.code === '23503') {
                    // foreign key violation for user or provider
                    return reply.status(404).send({ error: 'User or provider not found' });
                }
                if (err.code === '23505') {
                    // unique (provider_id, external_user_id)
                    return reply.status(400).send({ error: 'This SSO connection already exists' });
                }
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.post('/:id/role', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            const { roleId } = request.body as RoleIdBody;

            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                await pool.query(
                    `
                INSERT INTO user_roles (user_id, role_id)
                     VALUES ($1, $2)
                ON CONFLICT (user_id, role_id) DO NOTHING
              `,
                    [id, roleId]
                );
                reply.send({ success: true });
            } catch (err: any) {
                if (err.code === '23503') {
                    // foreign key violation for user or role
                    return reply.status(404).send({ error: 'User or role not found' });
                }
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.delete('/:id/role', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            const { roleId } = request.body as RoleIdBody;

            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    'DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2 RETURNING user_id, role_id',
                    [id, roleId]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User or role not found' });
                }
                reply.send({ success: true });
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.get('/:id/roles', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    `
                SELECT r.id, r.name, r.description
                  FROM user_roles ur
                  JOIN roles r ON ur.role_id = r.id
                 WHERE ur.user_id = $1
              `,
                    [id]
                );
                reply.send(result.rows);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.post('/:id/profile-pic', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            let file: any;
            const parts = request.files();
            for await (const part of parts) {
                file = part;
                break;  // Get first uploaded file
            }
            if (!file) {
                console.error(`No file uploaded for user ${id}`);
                return reply.status(400).send({ error: 'No file uploaded' });
            }

            const buffer = await file.toBuffer();
            const profile_picture = buffer.toString('base64');

            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    'UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING id, profile_picture',
                    [profile_picture, id]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                } else {
                    try {
                        fs.writeFileSync(`../public/profile_images/${id}.png`, buffer);
                    } catch (err) {
                        console.error(err);
                        return reply.status(500).send({ error: 'Failed to save image' });
                    }
                }
                reply.send(result.rows[0]);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.get('/:id/profile-picture', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            try {
                const result = await pool.query(
                    'SELECT profile_picture FROM users WHERE id = $1',
                    [id]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                const profile_picture = result.rows[0].profile_picture;
                if (!profile_picture) {
                    return reply.status(404).send({ error: 'Profile picture not found' });
                }
                reply.send({ profile_picture });
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.put('/:id/profile-picture', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            const files = await request.files();
            const file = files[0];  // Get first uploaded file
            if (!file) {
                return reply.status(400).send({ error: 'No file uploaded' });
            }
            const buffer = await file.toBuffer();
            const profile_picture = buffer.toString('base64');

            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    'UPDATE users SET profile_picture = $1 WHERE id = $2 RETURNING id, profile_picture',
                    [profile_picture, id]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                } else {
                    try {
                        fs.writeFileSync(`../public/profile_images/${id}.png`, buffer);
                    } catch (err) {
                        console.error(err);
                        return reply.status(500).send({ error: 'Failed to save image' });
                    }
                }
                reply.send(result.rows[0]);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });

    server.delete('/:id/profile-picture', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            try {
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }

                const result = await pool.query(
                    'UPDATE users SET profile_picture = NULL WHERE id = $1 RETURNING id',
                    [id]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                } else {
                    try {
                        fs.unlinkSync(`../public/profile_images/${id}.png`);
                    } catch (err) {
                        console.error(err);
                        return reply.status(500).send({ error: 'Failed to delete image' });
                    }
                }
                reply.send({ success: true });
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            }
        },
    });
};

export default userRoutes;