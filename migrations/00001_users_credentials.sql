-- +goose Up
-- +goose StatementBegin
CREATE TABLE users (
    id uuid PRIMARY KEY,
    subject text NOT NULL UNIQUE,
    username text NOT NULL,
    username_normalized text NOT NULL UNIQUE,
    display_name text NOT NULL,
    email text NOT NULL,
    email_normalized text NOT NULL UNIQUE,
    email_verified boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'active',
    role text NOT NULL DEFAULT 'user',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    last_login_at timestamptz,
    CONSTRAINT users_subject_not_blank CHECK (
        length(subject) BETWEEN 20 AND 255 AND subject = btrim(subject)
    ),
    CONSTRAINT users_username_bounds CHECK (
        length(username) BETWEEN 1 AND 128
        AND length(username_normalized) BETWEEN 1 AND 256
    ),
    CONSTRAINT users_display_name_bounds CHECK (length(display_name) BETWEEN 1 AND 256),
    CONSTRAINT users_email_bounds CHECK (
        length(email) BETWEEN 3 AND 320
        AND length(email_normalized) BETWEEN 3 AND 320
    ),
    CONSTRAINT users_status_valid CHECK (status IN ('active', 'disabled')),
    CONSTRAINT users_role_valid CHECK (role IN ('user', 'admin')),
    CONSTRAINT users_timestamps_valid CHECK (
        updated_at >= created_at
        AND (last_login_at IS NULL OR last_login_at >= created_at)
    )
);

CREATE TABLE credentials (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    credential_type text NOT NULL DEFAULT 'password',
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT credentials_type_password CHECK (credential_type = 'password'),
    CONSTRAINT credentials_argon2id_phc CHECK (
        password_hash LIKE '$argon2id$v=%$m=%,t=%,p=%$%$%'
        AND length(password_hash) BETWEEN 80 AND 512
    ),
    CONSTRAINT credentials_timestamps_valid CHECK (updated_at >= created_at)
);

CREATE INDEX users_created_cursor_idx ON users (created_at DESC, id DESC);
CREATE INDEX users_status_role_idx ON users (status, role);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE credentials;
DROP TABLE users;
-- +goose StatementEnd
