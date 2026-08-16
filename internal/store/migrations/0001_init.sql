CREATE TABLE cas (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    parent_id  TEXT NULL REFERENCES cas(id),
    algorithm  TEXT NOT NULL,
    cert_pem   TEXT NOT NULL,
    key_id     TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE certificates (
    serial            TEXT PRIMARY KEY,
    ca_id             TEXT NOT NULL REFERENCES cas(id),
    subject_dn        TEXT NOT NULL,
    sans              TEXT NOT NULL DEFAULT '',
    algorithm         TEXT NOT NULL,
    cert_pem          TEXT NOT NULL,
    key_id            TEXT NULL,
    status            TEXT NOT NULL,
    not_before        TIMESTAMP NOT NULL,
    not_after         TIMESTAMP NOT NULL,
    revoked_at        TIMESTAMP NULL,
    revocation_reason INTEGER NULL
);

CREATE INDEX certificates_ca_id_idx ON certificates(ca_id);
CREATE INDEX certificates_status_idx ON certificates(ca_id, status);

CREATE TABLE tokens (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMP NOT NULL
);
