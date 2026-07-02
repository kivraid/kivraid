-- name: CreateAuthRequest :exec
INSERT INTO auth_requests (id, request, created_at) VALUES ($1, $2, $3);

-- name: GetAuthRequestByID :one
SELECT * FROM auth_requests WHERE id = $1;

-- name: GetAuthRequestByCode :one
SELECT * FROM auth_requests WHERE code = $1;

-- name: UpdateAuthRequest :exec
UPDATE auth_requests SET request = $1 WHERE id = $2;

-- name: SetAuthRequestCode :exec
UPDATE auth_requests SET code = $1 WHERE id = $2;

-- name: DeleteAuthRequest :exec
DELETE FROM auth_requests WHERE id = $1;

-- name: DeleteExpiredAuthRequests :exec
DELETE FROM auth_requests WHERE created_at < $1;

-- name: CreateAccessToken :exec
INSERT INTO access_tokens (id, user_id, client_id, scopes, audience, refresh_token_id, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: GetAccessToken :one
SELECT * FROM access_tokens WHERE id = $1;

-- name: DeleteAccessToken :exec
DELETE FROM access_tokens WHERE id = $1;

-- name: DeleteAccessTokensByRefreshToken :exec
DELETE FROM access_tokens WHERE refresh_token_id = $1;

-- name: DeleteAccessTokensByUserClient :exec
DELETE FROM access_tokens WHERE user_id = $1 AND client_id = $2;

-- name: DeleteExpiredAccessTokens :exec
DELETE FROM access_tokens WHERE expires_at < $1;

-- name: CreateRefreshToken :exec
INSERT INTO refresh_tokens (id, user_id, client_id, scopes, audience, amr, auth_time, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: GetRefreshToken :one
SELECT * FROM refresh_tokens WHERE id = $1;

-- name: DeleteRefreshToken :exec
DELETE FROM refresh_tokens WHERE id = $1;

-- name: DeleteRefreshTokensByUserClient :exec
DELETE FROM refresh_tokens WHERE user_id = $1 AND client_id = $2;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < $1;

-- name: CreateSigningKey :exec
INSERT INTO signing_keys (id, alg, private_key_enc, public_key_der, active, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetActiveSigningKeys :many
SELECT * FROM signing_keys WHERE active = TRUE ORDER BY created_at DESC;
