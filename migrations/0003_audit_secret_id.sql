-- +goose Up
-- The uuid a secret was addressed by when the action happened.
--
-- Recorded at write time rather than derived at read time, because the
-- derived id follows the name: a renamed secret would make old entries point
-- at a uuid nothing answers to. Nullable — entries from before this column
-- honestly do not know it.
ALTER TABLE audit ADD COLUMN secret_id UUID;
