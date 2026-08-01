-- +goose Up
-- +goose StatementBegin
CREATE TABLE phase_one_migration_test_marker (
    id integer PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE phase_one_migration_test_marker;
-- +goose StatementEnd
