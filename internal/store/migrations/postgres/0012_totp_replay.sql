-- Track the last accepted TOTP time-step counter so a captured code
-- cannot be replayed within the validity window.
ALTER TABLE users ADD COLUMN totp_last_counter BIGINT NOT NULL DEFAULT 0;
