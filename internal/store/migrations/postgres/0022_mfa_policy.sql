-- Two-factor requirements. mfa_policy says who must use a second factor
-- across the instance: 'off', 'admins' or 'all'. require_mfa additionally
-- demands one to use a given application, whatever the instance policy.
ALTER TABLE instance_settings ADD COLUMN mfa_policy TEXT NOT NULL DEFAULT 'off';
ALTER TABLE applications ADD COLUMN require_mfa BOOLEAN NOT NULL DEFAULT FALSE;
