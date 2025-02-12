-- backend/migrations/001_initial_schema.sql
BEGIN;

-- Drop tables if they exist (be careful with this in production!)
DROP TABLE IF EXISTS user_sso_connections;
DROP TABLE IF EXISTS sso_providers;
DROP TABLE IF EXISTS auth_methods;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS user_settings;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS password_resets;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS email_verifications;

-- Create users table
CREATE TABLE users (
    id VARCHAR(20) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255) NULL,
    last_name VARCHAR(255) NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    profile_picture VARCHAR(255),
    dateOfBirth DATE,
    phone_number VARCHAR(20),
    address VARCHAR(9999),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create auth_methods table
CREATE TABLE auth_methods (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(20) REFERENCES users(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL, -- 'password', 'passkey', 'biometric', 'sso'
    is_preferred BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB, -- Stores method-specific data (hashed passwords, passkey credentials, etc.)
    CONSTRAINT valid_auth_type CHECK (
        type IN ('password', 'passkey', 'biometric', 'sso')
    )
);

-- Create sso_providers table
CREATE TABLE sso_providers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret VARCHAR(255) NOT NULL,
    config JSONB, -- Stores provider-specific configuration
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(name)
);

-- Create user_sso_connections table
CREATE TABLE user_sso_connections (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(20) REFERENCES users(id) ON DELETE CASCADE,
    provider_id INTEGER REFERENCES sso_providers(id) ON DELETE CASCADE,
    external_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_id, external_user_id)
);

-- Create roles table
CREATE TABLE roles (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  permissions JSONB DEFAULT '[]'::JSONB,
  icon VARCHAR(255),
  description TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(name) -- or some other unique constraint
);

-- Create user_roles table
CREATE TABLE user_roles (
  user_id VARCHAR(20) REFERENCES users(id),
  role_id INT REFERENCES roles(id),
  PRIMARY KEY (user_id, role_id)
);

-- Create audit_logs table
CREATE TABLE audit_logs (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(20) REFERENCES users(id),
  action VARCHAR(50) NOT NULL,
  details JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create password_resets table
CREATE TABLE password_resets (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(20) REFERENCES users(id),
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create sessions table
CREATE TABLE sessions (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(20) REFERENCES users(id),
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create user_settings table
CREATE TABLE user_settings (
  user_id VARCHAR(20) REFERENCES users(id),
  key VARCHAR(50) NOT NULL,
  value JSONB,
  PRIMARY KEY (user_id, key)
);

-- Create email_verifications table
CREATE TABLE email_verifications (
  id SERIAL PRIMARY KEY,
  user_id VARCHAR(20) REFERENCES users(id),
  token VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX idx_auth_methods_user_id ON auth_methods(user_id);
CREATE INDEX idx_user_sso_connections_user_id ON user_sso_connections(user_id);
CREATE INDEX idx_user_sso_connections_provider_id ON user_sso_connections(provider_id);

-- Add some helper functions
CREATE OR REPLACE FUNCTION update_last_used_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_used_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to update last_used_at
CREATE TRIGGER update_auth_method_last_used
    BEFORE UPDATE ON auth_methods
    FOR EACH ROW
    EXECUTE FUNCTION update_last_used_at();

COMMIT;