-- name: ListGroups :many
SELECT * FROM groups ORDER BY name;

-- name: ListAppPolicyGroupIDs :many
SELECT group_id FROM app_policies WHERE application_id = ?;

-- name: DeleteAppPolicies :exec
DELETE FROM app_policies WHERE application_id = ?;

-- name: AddAppPolicy :exec
INSERT INTO app_policies (application_id, group_id) VALUES (?, ?);

-- name: CountAppPolicies :one
SELECT COUNT(*) FROM app_policies WHERE application_id = ?;

-- name: CountMatchingAppPolicies :one
SELECT COUNT(*)
FROM app_policies p
JOIN user_groups ug ON ug.group_id = p.group_id
WHERE p.application_id = ? AND ug.user_id = ?;

-- name: ListLaunchableApplications :many
SELECT DISTINCT a.*
FROM applications a
LEFT JOIN app_policies p ON p.application_id = a.id
WHERE a.launch_url != ''
  AND (p.application_id IS NULL
       OR p.group_id IN (SELECT group_id FROM user_groups WHERE user_id = ?))
ORDER BY a.name;
