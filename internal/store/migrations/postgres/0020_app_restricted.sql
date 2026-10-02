-- Whether an application is restricted to the groups in app_policies. It is
-- stored explicitly so access fails closed: deleting the last group an
-- application was restricted to must leave it locked, not open it to every
-- authenticated user (which an empty app_policies used to mean).
ALTER TABLE applications ADD COLUMN restricted BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE applications SET restricted = TRUE
WHERE id IN (SELECT DISTINCT application_id FROM app_policies);
