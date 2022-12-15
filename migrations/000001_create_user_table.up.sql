CREATE TABLE IF NOT EXISTS "user"(
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR (50) UNIQUE NOT NULL,
    email VARCHAR (256) UNIQUE NOT NULL,
    password text NOT NULL,
    mfa_secret BYTEA,
    role BIGINT NOT NULL,
    recovery text[],
    active BOOLEAN NOT NULL

);

-- CONSTRAINT fk_role
--         FOREIGN KEY(user_id)
--             REFERENCES "user"(id)