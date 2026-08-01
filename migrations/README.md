# Production migrations

Phase one intentionally creates no business tables. The `goose_db_version`
table created by `oneissuer migrate up` is the only production schema state at
this stage.

When a real use case requires a table, add an immutable Goose SQL migration
named `00001_description.sql` (then increment the number). Every migration must
contain both `-- +goose Up` and `-- +goose Down` sections. Do not add placeholder
users, clients, sessions, tokens, tenants, organizations, or realms.

Down/Up behavior is exercised with test-only migrations under
`internal/storage/postgres/testdata/migrations`; those files are never scanned
by the production migration command or copied into the runtime image.

