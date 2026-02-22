CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DO $$
BEGIN
CREATE TYPE user_role AS ENUM ('super_admin', 'admin', 'user');
EXCEPTION
WHEN duplicate_object THEN null;
END $$;

CREATE TABLE
    IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4 (),
        first_name VARCHAR(255) NOT NULL,
        last_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        role user_role NOT NULL DEFAULT 'user',
        is_email_verified BOOLEAN NOT NULL DEFAULT false,
        email_verification_token CHAR(64),
        email_verification_expires TIMESTAMPTZ,
        password_hash TEXT NOT NULL,
        password_changed_at TIMESTAMPTZ,
        password_reset_token CHAR(64),
        password_reset_expires TIMESTAMPTZ,
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW (),
        deleted_at TIMESTAMPTZ
    );