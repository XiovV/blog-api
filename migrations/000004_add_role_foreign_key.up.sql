ALTER TABLE "user"
    ADD CONSTRAINT fk_role FOREIGN KEY(role)
        REFERENCES role(id)