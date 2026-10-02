-- How long activity-log events are kept, in days; 0 keeps them forever.
-- 90 matches the retention that was previously hard-coded.
ALTER TABLE instance_settings ADD COLUMN audit_retention_days INTEGER NOT NULL DEFAULT 90;
