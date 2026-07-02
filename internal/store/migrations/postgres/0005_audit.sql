CREATE TABLE audit_log (
    id     BIGSERIAL PRIMARY KEY,
    ts     TIMESTAMPTZ NOT NULL,
    actor  TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    object TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    ip     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX audit_log_ts_idx ON audit_log (ts);
