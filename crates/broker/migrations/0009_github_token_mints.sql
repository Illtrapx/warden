-- The hour (Unix seconds / 3600) a GitHub token grant last minted in, and its
-- tokens that hour. Null for every other grant.
ALTER TABLE grants ADD COLUMN mint_hour INTEGER;
ALTER TABLE grants ADD COLUMN mint_count INTEGER;
