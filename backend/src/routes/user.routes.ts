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
    
    // get all users
    server.get('/', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            try {
                // If you want to restrict this to admins, do an additional check here:
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
                const likeQuery = `%${search || ''}%`;
    
                try {
                    const result = await pool.query(
                        `
                        SELECT *
                            FROM users
                        WHERE email ILIKE $1
                            OR first_name ILIKE $1
                            OR last_name ILIKE $1
                        ORDER BY created_at DESC
                        LIMIT $2 OFFSET $3
                        `,
                        [encryptPII(likeQuery), pageSize, offset]
                    );
                    // for each result, parse each row as UserSchema then add to outgoing array
                    console.log(result.rows);
                    const _outgoing = result.rows.map((row) => {
                        let json_encoded_address = JSON.parse(row.address);
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
                                address: decryptPII(json_encoded_address),
                            },
                        };
                        return UserSchema.parse(parsedResult);
                    });
                    // console.log(_outgoing);
                    reply.send(_outgoing);
                } catch (err) {
                    reply.status(500).send({ error: 'Database error' });
                }
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
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
                // console.log(profile.rows[0]);
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
                // console.log("parsedResult: ", parsedResult);
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
    
    // get user's profile
    server.get('/:id', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            try {
                // only allow users to view their own profile, or admins to view any profile
                if (request.jwtUser.userId !== id && !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }
    
                const result = await pool.query(
                    'SELECT * FROM users WHERE id = $1',
                    [id]
                );
                console.log(result.rows[0]);
                // console.log(result.rows[0]);
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
    
                // get date time last changed password
                const password_changed_at = await pool.query(
                    'SELECT created_at FROM auth_methods WHERE user_id = $1 AND type = $2',
                    [id, 'password']
                );
    
                // store last password change date in the first row
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
    
    // update user's profile
    server.put('/:id', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            console.log(`Received request from user ${request.jwtUser.userId} on route PUT /api/users/${id}`);
            console.log(`Data to update: ${request.body}`);
            const toUpdate = UserSchema.parse(request.body);
            console.log(`Data to update: ${toUpdate}`);
    
            try {
                if (request.jwtUser.userId !== id || !request.jwtUser.isAdmin) {
                    return reply.status(403).send({ error: 'Forbidden' });
                }
    
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
                        encryptPII(toUpdate.profile.dateOfBirth),
                        encryptPII(toUpdate.profile.phone),
                        encryptPII(toUpdate.profile.address),
                        toUpdate.profile.profile_picture,
                        id
                    ]
                );
                if (result.rowCount === 0) {
                    return reply.status(404).send({ error: 'User not found' });
                }
                reply.send(result.rows[0]);
            } catch (err) {
                reply.status(500).send({ error: 'Database error' });
            };
        }
    });
    
    // delete user
    
    server.delete('/:id', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as { id: string };
            // const requester_permissions = getUserPermissions(String(request.jwtUser.userId));
            try {
                // allow user to delete their own account, or an admin to delete any account
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
    
    // get user's auth methods
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
    
    // add auth method to user
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
    
    // update auth method
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
    
    // add sso connection to user
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
    
    // add role to user
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
    
    // remove role from user
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
    
    // get user's roles
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
    
    // user profile picture
    
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
    
            // Read file buffer
            const buffer = await file.toBuffer();
    
            // Convert to base64 string for storage
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
                    // save the image to the file system
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
    
    // get user's profile picture
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
    
    // update user's profile picture
    server.put('/:id/profile-picture', {
        onRequest: [server.authenticate],
        handler: async (request, reply) => {
            const { id } = request.params as UserIdParam;
            const files = await request.files();
            const file = files[0];  // Get first uploaded file
            if (!file) {
                return reply.status(400).send({ error: 'No file uploaded' });
            }
    
            // Read file buffer
            const buffer = await file.toBuffer();
    
            // Convert to base64 string for storage
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
                    // save the image to the file system
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
    
    // delete user's profile picture
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
                    // delete the image from the file system
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