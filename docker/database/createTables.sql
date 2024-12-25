

CREATE TABLE IF NOT EXISTS "users" (
    id VARCHAR(255) PRIMARY KEY NOT NULL,
    email TEXT NOT NULL,
    salt TEXT NOT NULL,
    verifier TEXT NOT NULL,
    blocked BOOLEAN NOT NULL DEFAULT FAlSE,
    verified BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS "invites" (
    id VARCHAR(255) PRIMARY KEY NOT NULL,
    email TEXT,
    expires INTEGER
);

CREATE TABLE IF NOT EXISTS "loginAttempts" (
    id VARCHAR(255) PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    server_secret TEXT NOT NULL,
    expires INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS "sessions" (
    id VARCHAR(255) PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    description TEXT,
    expires INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE OR REPLACE FUNCTION check_session_id()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the inserted id exists in the sessions table
    IF EXISTS (SELECT 1 FROM sessions WHERE id = NEW.id) THEN
        -- Raise an exception to prevent the insert
        RAISE EXCEPTION 'ID % already exists in the sessions table', NEW.id;
    END IF;
    -- Allow the insert to proceed
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER check_session_id_trigger
BEFORE INSERT ON loginAttempts
FOR EACH ROW
EXECUTE FUNCTION check_session_id();