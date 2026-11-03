-- One database transaction owns originals, derivatives and pending work.
CREATE SCHEMA csl;
CREATE TABLE csl.schema_migrations (
 version integer PRIMARY KEY CHECK (version = 1), checksum text NOT NULL,
 schema_hash text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE csl.pipeline (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
 published_generation bigint NOT NULL DEFAULT 0 CHECK (published_generation >= 0),
 CHECK (published_generation <= generation)
);
INSERT INTO csl.pipeline(singleton) VALUES (true);
CREATE TABLE csl.batches (
 batch_id text PRIMARY KEY, checkpoint text NOT NULL UNIQUE CHECK (length(checkpoint) BETWEEN 1 AND 256),
 request_hash text NOT NULL, status text NOT NULL CHECK (status IN ('committed','failed')),
 generation bigint NOT NULL CHECK (generation >= 0),
 accepted_count integer NOT NULL CHECK (accepted_count >= 0),
 duplicate_count integer NOT NULL CHECK (duplicate_count >= 0),
 conflicting_count integer NOT NULL CHECK (conflicting_count >= 0),
 source_count integer NOT NULL DEFAULT 0 CHECK (source_count BETWEEN 0 AND 64),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE csl.checkpoints (
 checkpoint text PRIMARY KEY, batch_id text NOT NULL UNIQUE REFERENCES csl.batches(batch_id),
 generation bigint NOT NULL CHECK (generation >= 0)
);
CREATE TABLE csl.raw_objects (
 raw_id text PRIMARY KEY, source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
 archive_bytes bytea NOT NULL CHECK (octet_length(archive_bytes) <= 10485760),
 archive_hash text NOT NULL, content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
 expanded_size integer NOT NULL CHECK (expanded_size BETWEEN 0 AND 104857600),
 record_count integer NOT NULL CHECK (record_count BETWEEN 0 AND 10000),
 source_kind text NOT NULL DEFAULT 'synthetic' CHECK (source_kind = 'synthetic'),
 authenticated boolean NOT NULL DEFAULT false CHECK (NOT authenticated),
 schema_version text NOT NULL DEFAULT '1.0' CHECK (schema_version = '1.0'),
 parser_version text NOT NULL DEFAULT '1.0.0' CHECK (parser_version = '1.0.0'),
 canonicalization_version text NOT NULL DEFAULT '1.0' CHECK (canonicalization_version = '1.0'),
 CHECK (archive_hash = encode(sha256(archive_bytes), 'hex')), CHECK (raw_id = archive_hash)
);
CREATE TABLE csl.events (
 event_key text PRIMARY KEY CHECK (event_key ~ '^[0-9a-f]{64}$'),
 source_kind text NOT NULL CHECK (source_kind = 'synthetic'),
 account text NOT NULL, region text NOT NULL, event_id text NOT NULL,
 UNIQUE (source_kind,account,region,event_id)
);
CREATE TABLE csl.record_variants (
 event_key text NOT NULL REFERENCES csl.events(event_key), record_hash text NOT NULL,
 canonical_bytes bytea NOT NULL, normalized jsonb NOT NULL,
 CHECK ((normalized->>'source_kind' = 'synthetic'
 AND normalized->'authenticated' = 'false'::jsonb
 AND normalized->>'schema_version' = '1.0'
 AND normalized->>'parser_version' = '1.0.0'
 AND normalized->>'canonicalization_version' = '1.0') IS TRUE),
 schema_version text NOT NULL DEFAULT '1.0' CHECK (schema_version = '1.0'),
 parser_version text NOT NULL DEFAULT '1.0.0' CHECK (parser_version = '1.0.0'),
 canonicalization_version text NOT NULL DEFAULT '1.0' CHECK (canonicalization_version = '1.0'),
 PRIMARY KEY (event_key,record_hash), CHECK (record_hash = encode(sha256(canonical_bytes), 'hex'))
);
CREATE TABLE csl.raw_deliveries (
 batch_id text NOT NULL REFERENCES csl.batches(batch_id),
 raw_id text NOT NULL REFERENCES csl.raw_objects(raw_id),
 source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
 PRIMARY KEY (batch_id,raw_id,source_ref)
);
CREATE TABLE csl.source_references (
 batch_id text NOT NULL REFERENCES csl.batches(batch_id), raw_id text NOT NULL REFERENCES csl.raw_objects(raw_id),
 source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256), record_index integer NOT NULL CHECK (record_index >= 0),
 event_key text NOT NULL, record_hash text NOT NULL,
 PRIMARY KEY (batch_id,raw_id,source_ref,record_index),
 FOREIGN KEY (event_key,record_hash) REFERENCES csl.record_variants(event_key,record_hash),
 FOREIGN KEY (batch_id,raw_id,source_ref) REFERENCES csl.raw_deliveries(batch_id,raw_id,source_ref)
);
CREATE TABLE csl.conflicts (
 event_key text PRIMARY KEY REFERENCES csl.events(event_key), detected_generation bigint NOT NULL
);
CREATE TABLE csl.ingestion_errors (
 error_id bigserial PRIMARY KEY, checkpoint text NOT NULL,
 code text NOT NULL CHECK (code ~ '^[A-Z_]{1,64}$'),
 status text NOT NULL DEFAULT 'quarantined' CHECK (status = 'quarantined'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE csl.jobs (
 job_id text PRIMARY KEY, generation bigint NOT NULL UNIQUE CHECK (generation > 0),
 status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','leased','retryable','succeeded','dead','superseded')),
 claim_token text, lease_until timestamptz, attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
 max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 3), last_error text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 CHECK (attempts <= max_attempts), CHECK ((status = 'leased') = (claim_token IS NOT NULL AND lease_until IS NOT NULL))
);
CREATE TABLE csl.job_attempts (
 job_id text NOT NULL REFERENCES csl.jobs(job_id), attempt integer NOT NULL CHECK (attempt BETWEEN 1 AND 3),
 token text NOT NULL UNIQUE, started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz, result text, PRIMARY KEY (job_id,attempt)
);
CREATE TABLE csl.findings (
 finding_id text PRIMARY KEY, payload jsonb NOT NULL, generation bigint NOT NULL,
 status text NOT NULL CHECK (status IN ('pending','current','obsolete')),
 CHECK ((payload->>'source_kind' = 'synthetic' AND payload->'authenticated' = 'false'::jsonb) IS TRUE)
);
CREATE TABLE csl.finding_evidence (
 finding_id text NOT NULL REFERENCES csl.findings(finding_id), event_key text NOT NULL, record_hash text NOT NULL,
 PRIMARY KEY (finding_id,event_key,record_hash),
 FOREIGN KEY (event_key,record_hash) REFERENCES csl.record_variants(event_key,record_hash)
);
CREATE TABLE csl.cases (
 case_id text PRIMARY KEY, current_revision integer NOT NULL CHECK (current_revision >= 0),
 status text NOT NULL CHECK (status IN ('pending','current','superseded','withdrawn'))
);
CREATE TABLE csl.case_revisions (
 case_id text NOT NULL REFERENCES csl.cases(case_id), revision integer NOT NULL CHECK (revision > 0),
 payload jsonb NOT NULL, fingerprint text NOT NULL, finding_id text REFERENCES csl.findings(finding_id),
 generation bigint NOT NULL, status text NOT NULL CHECK (status IN ('current','superseded','withdrawn')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY (case_id,revision),
 CHECK ((payload->>'source_kind' = 'synthetic' AND payload->'authenticated' = 'false'::jsonb
 AND payload->'unreviewed' = 'true'::jsonb) IS TRUE)
);
ALTER TABLE csl.cases ADD CONSTRAINT case_current_revision_fk FOREIGN KEY (case_id,current_revision)
 REFERENCES csl.case_revisions(case_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE csl.case_timeline (
 timeline_id bigserial PRIMARY KEY, case_id text NOT NULL, revision integer NOT NULL, kind text NOT NULL,
 payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY (case_id,revision) REFERENCES csl.case_revisions(case_id,revision)
);
CREATE TABLE csl.case_lineage (
 parent_case_id text NOT NULL REFERENCES csl.cases(case_id), child_case_id text NOT NULL REFERENCES csl.cases(case_id),
 generation bigint NOT NULL, PRIMARY KEY (parent_case_id,child_case_id), CHECK (parent_case_id <> child_case_id)
);
CREATE TABLE csl.outbox (
 outbox_id text PRIMARY KEY, idempotency_key text NOT NULL UNIQUE, case_id text NOT NULL,
 revision integer NOT NULL, payload jsonb NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','attempted','retryable','locally_acknowledged','failed')),
 attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0), max_attempts integer NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 3),
 claim_token text, lease_until timestamptz, last_error text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), acknowledged_at timestamptz,
 FOREIGN KEY (case_id,revision) REFERENCES csl.case_revisions(case_id,revision), CHECK (attempts <= max_attempts),
 CHECK ((payload->>'source_kind' = 'synthetic' AND payload->'authenticated' = 'false'::jsonb
 AND payload->>'delivery_class' = 'offline_test_only') IS TRUE)
);
CREATE TABLE csl.offline_sink (
 idempotency_key text PRIMARY KEY REFERENCES csl.outbox(idempotency_key), payload jsonb NOT NULL,
 payload_hash text NOT NULL, received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE csl.audit (
 audit_id bigserial PRIMARY KEY, kind text NOT NULL, payload jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION csl.reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'immutable evidence or history'; END;
$$;
CREATE FUNCTION csl.restrict_finding_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'immutable finding'; END IF;
 IF NEW.finding_id <> OLD.finding_id OR NEW.payload <> OLD.payload THEN
 RAISE EXCEPTION 'immutable finding payload'; END IF;
 RETURN NEW;
 END;
$$;
CREATE FUNCTION csl.restrict_outbox_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF TG_OP = 'DELETE' THEN RAISE EXCEPTION 'immutable outbox'; END IF;
 IF NEW.outbox_id <> OLD.outbox_id OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.case_id <> OLD.case_id
 OR NEW.revision <> OLD.revision OR NEW.payload <> OLD.payload THEN
 RAISE EXCEPTION 'immutable outbox payload'; END IF;
 RETURN NEW;
 END;
$$;
CREATE TRIGGER immutable_findings BEFORE UPDATE OR DELETE ON csl.findings FOR EACH ROW EXECUTE FUNCTION csl.restrict_finding_mutation();
CREATE TRIGGER immutable_outbox BEFORE UPDATE OR DELETE ON csl.outbox FOR EACH ROW EXECUTE FUNCTION csl.restrict_outbox_mutation();
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['schema_migrations','raw_objects','raw_deliveries','events','record_variants','source_references',
 'batches','checkpoints','conflicts','ingestion_errors','finding_evidence','case_revisions','case_timeline',
 'case_lineage','offline_sink','audit'] LOOP
 EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON csl.%I FOR EACH ROW EXECUTE FUNCTION csl.reject_mutation()', tab);
 END LOOP;
END $$;
