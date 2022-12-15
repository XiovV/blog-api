CREATE TABLE IF NOT EXISTS post(
    id BIGSERIAL PRIMARY KEY NOT NULL,
    user_id BIGINT NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    CONSTRAINT fk_user
        FOREIGN KEY(user_id)
            REFERENCES "user"(id)
            ON DELETE CASCADE
)