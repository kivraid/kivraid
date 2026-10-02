-- name: ListGroups :many
SELECT * FROM groups ORDER BY name;

-- name: ListAppPolicyGroupIDs :many
SELECT group_id FROM app_policies WHERE application_id = $1;

-- name: DeleteAppPolicies :exec
DELETE FROM app_policies WHERE application_id = $1;

-- name: AddAppPolicy :exec
INSERT INTO app_policies (application_id, group_id) VALUES ($1, $2);

-- name: SetApplicationRestricted :exec
UPDATE applications SET restricted = $1 WHERE id = $2;

-- name: ListApplicationsByPolicyGroup :many
-- Applications restricted to the group, with how many groups each one is
-- bound to in total (1 means the group is its only way in).
SELECT a.id, a.name, a.slug,
       (SELECT COUNT(*) FROM app_policies p2 WHERE p2.application_id = a.id) AS group_count
FROM applications a
JOIN app_policies p ON p.application_id = a.id
WHERE p.group_id = $1
ORDER BY a.name;

-- name: CountMatchingAppPolicies :one
SELECT COUNT(*)
FROM app_policies p
JOIN user_groups ug ON ug.group_id = p.group_id
WHERE p.application_id = $1 AND ug.user_id = $2;

-- name: ListLaunchableApplications :many
SELECT DISTINCT a.*
FROM applications a
LEFT JOIN app_policies p ON p.application_id = a.id
WHERE a.launch_url != ''
  AND (NOT a.restricted
       OR p.group_id IN (SELECT group_id FROM user_groups WHERE user_id = $1))
ORDER BY a.name;
