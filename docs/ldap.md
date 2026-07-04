# LDAP directories

Kivraid authenticates users against live LDAP directories (tested with
OpenLDAP and LLDAP) in addition to local accounts. Configure sources in
**Admin → Directories**.

## How it works

Users authenticate by **bind**: Kivraid binds to the directory as the user
to verify the password, so the directory's own password policy stays in
charge. On successful login, the user's profile, group memberships and
photo are read and mirrored into a local shadow row — everything except the
password, which is never stored.

Large directories are enumerated with **paged search** (RFC 2696, 500
entries per page), so a directory bigger than the server's size limit syncs
in full instead of being truncated at the first page. A manual sync is
available per directory from the admin UI.

## Group membership

The group filter supports both membership models with two placeholders:

- `{dn}` — for `groupOfNames` / `groupOfUniqueNames` (member is a DN).
- `{username}` — for `posixGroup` (`memberUid` is a bare username).

A filter may use either or both, e.g.:

```
(|(&(objectClass=groupOfNames)(member={dn}))(&(objectClass=posixGroup)(memberUid={username})))
```

## Service bind

The service account used for enumeration may bind **anonymously** if the
directory allows unauthenticated searches. Password write-back still works
in that case, because it uses the RFC 3062 Password Modify operation on the
**user's own** authenticated connection — the directory's ACLs decide
whether the change is allowed.

## Read-only mirror

Directory-sourced users and groups appear under **Admin → Users** and
**Admin → Groups** alongside local ones, but stay read-only: only
Kivraid-side flags (administrator, active) can be changed on a directory
user.

Any group — local or directory — can be flagged **"Members are
administrators"**. The administrator role is then computed from membership
on top of the per-user flag, so flagging a synced LDAP group lets the
directory drive who administers Kivraid.

## Local fixtures for testing

An OpenLDAP instance seeded with users, plus LLDAP, is provided for manual
testing:

```sh
docker compose -f fixtures/ldap/docker-compose.yml up -d
```

Connection settings are documented in that compose file.
