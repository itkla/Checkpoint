-- backend/migrations/001_initial_schema.sql
BEGIN;

-- Drop tables if they exist (be careful with this in production!)
DROP TABLE IF EXISTS user_sso_connections;
DROP TABLE IF EXISTS sso_providers;
DROP TABLE IF EXISTS auth_methods;
DROP TABLE IF EXISTS users;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    private_key VARCHAR(255) NOT NULL,
    public_key VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create auth_methods table
CREATE TABLE auth_methods (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
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
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    provider_id INTEGER REFERENCES sso_providers(id) ON DELETE CASCADE,
    external_user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(provider_id, external_user_id)
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