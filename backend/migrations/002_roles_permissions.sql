INSERT INTO roles (name, permissions, description)
VALUES
  (
    'admin',
    '[
      "users.read",
      "users.create",
      "users.update",
      "users.delete",
      "users.search",
      "auth-methods.read",
      "auth-methods.create",
      "auth-methods.update",
      "auth-methods.delete",
      "roles.read",
      "roles.create",
      "roles.update",
      "roles.delete",
      "roles.assign",
      "sso-providers.read",
      "sso-providers.create",
      "sso-providers.update",
      "sso-providers.delete",
      "audit-logs.read",
      "password.reset",
      "sessions.revoke"
    ]'::jsonb,
    'System administrator with full permissions'
  ),
  (
    'support',
    '[
      "users.read",
      "users.search",
      "auth-methods.read",
      "audit-logs.read"
    ]'::jsonb,
    'Support role with basic read/search permissions'
  ),
  (
    'customer',
    '[
      "users.readSelf",
      "users.updateSelf",
      "auth-methods.readSelf",
      "auth-methods.updateSelf"
    ]'::jsonb,
    'Customer role: can only manage their own account'
  ),
  (
    'user',
    '[
      "users.readSelf",
      "users.updateSelf",
      "auth-methods.readSelf",
      "auth-methods.updateSelf"
    ]'::jsonb,
    'Standard user role: can only read/update self'
  );

COMMIT;