-- Client secrets move from hashed to encrypted-at-rest so the admin can
-- display them again (Authentik-style). Legacy rows keep their hash and
-- still verify; the secret becomes visible after the next rotation.
ALTER TABLE providers ADD COLUMN client_secret_enc BLOB;
