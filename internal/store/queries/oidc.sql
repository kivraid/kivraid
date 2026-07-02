-- name: CreateAuthRequest :exec
INSERT INTO auth_requests (id, request, created_at) VALUES (?, ?, ?);

-- name: GetAuthRequestByID :one
SELECT * FROM auth_requests WHERE id = ?;

-- name: GetAuthRequestByCode :one
SELECT * FROM auth_requests WHERE code = ?;

-- name: UpdateAuthRequest :exec
UPDATE auth_requests SET request = ? WHERE id = ?;

-- name: SetAuthRequestCode :exec
UPDATE auth_requests SET code = ? WHERE id = ?;

-- name: DeleteAuthRequest :exec
DELETE FROM auth_requests WHERE id = ?;

-- name: DeleteExpiredAuthRequests :exec
DELETE FROM auth_requests WHERE created_at < ?;

-- name: CreateAccessToken :exec
INSERT INTO access_tokens (id, user_id, client_id, scopes, audience, refresh_token_id, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAccessToken :one
SELECT * FROM access_tokens WHERE id = ?;

-- name: DeleteAccessToken :exec
DELETE FROM access_tokens WHERE id = ?;

-- name: DeleteAccessTokensByRefreshToken :exec
DELETE FROM access_tokens WHERE refresh_token_id = ?;

-- name: DeleteAccessTokensByUserClient :exec
DELETE FROM access_tokens WHERE user_id = ? AND client_id = ?;

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens WHERE expires_at < ?;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, client_id, scopes, audience, amr, auth_time, expires_at, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE id = ?;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens WHERE id = ?;

-- name: DeleteRefreshTokensByUserClient :exec
DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ?;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < ?;

-- name: CreateSigningKey :exec
INSERT INTO signing_keys (id, alg, private_key_enc, public_key_der, active, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetActiveSigningKeys :many
SELECT * FROM signing_keys WHERE active = TRUE ORDER BY created_at DESC;
