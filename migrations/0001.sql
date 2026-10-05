CREATE TABLE audit (
 id TEXT PRIMARY KEY,
 at TEXT NOT NULL,
 correlation_id TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('success','error','credential','policy')),
 phase TEXT NOT NULL,
 operation TEXT NOT NULL,
 status INTEGER NOT NULL,
 object_key TEXT NOT NULL UNIQUE,
 sha256 TEXT NOT NULL
);
CREATE INDEX audit_category_at ON audit(category,at DESC);
CREATE INDEX audit_correlation ON audit(correlation_id);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'append only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'append only'); END;
