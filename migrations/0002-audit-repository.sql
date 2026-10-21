-- Existing records and old writers remain NULL: never infer ownership from bodies.
-- Additive migration; append-only triggers and existing object digests stay intact.
ALTER TABLE audit ADD COLUMN repository TEXT;
CREATE INDEX audit_repository_at ON audit(repository,at DESC);
CREATE INDEX audit_repository_category_at ON audit(repository,category,at DESC);
