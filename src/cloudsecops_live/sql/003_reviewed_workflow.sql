-- Human conclusions remain separate from immutable, unreviewed machine history.
ALTER TABLE csl.schema_migrations DROP CONSTRAINT schema_migrations_version_check;
ALTER TABLE csl.schema_migrations ADD CHECK(version BETWEEN 1 AND 3);
-- Machine table grants must never be inherited in another database with a different UUID.
DO $$ DECLARE prefix text;role_name text;BEGIN
 SELECT substr(encode(sha256(convert_to(database_id::text,'UTF8')),'hex'),1,12)
 INTO prefix FROM csl.schema_migrations WHERE version=2;
 IF prefix IS NULL THEN RAISE EXCEPTION 'PIPE_ROLES_REQUIRED';END IF;
 FOREACH role_name IN ARRAY ARRAY['csl_pc_'||prefix,'csl_pw_'||prefix] LOOP
 IF NOT EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=role_name) THEN
 EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);
 END IF;
 IF EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=role_name AND
 (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) OR
 EXISTS(SELECT FROM pg_catalog.pg_auth_members WHERE member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=role_name)) THEN RAISE EXCEPTION 'PIPE_ROLES_UNSAFE';END IF;
 END LOOP;END $$;
CREATE TABLE csl.ws_workflows (
 case_id text PRIMARY KEY REFERENCES csl.cases,
 workflow_version integer NOT NULL DEFAULT 0 CHECK(workflow_version>=0),
 epoch integer NOT NULL DEFAULT 1 CHECK(epoch>0),
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','recommended','approved','rejected','verified','contradicted','inconclusive','closed','reopen_required')),
 rec_version integer NOT NULL DEFAULT 0 CHECK(rec_version BETWEEN 0 AND 64)
);
CREATE TABLE csl.ws_recommendations (
 recommendation_id text NOT NULL CHECK(recommendation_id ~ '^[0-9a-f]{64}$'),
 version integer NOT NULL CHECK(version BETWEEN 1 AND 64),
 case_id text NOT NULL REFERENCES csl.ws_workflows,
 author_id text NOT NULL REFERENCES csl.ws_users,
 case_revision integer NOT NULL,case_fingerprint text NOT NULL,
 finding_id text NOT NULL REFERENCES csl.findings,generation bigint NOT NULL,epoch integer NOT NULL,
 source_manifest_hash text NOT NULL CHECK(source_manifest_hash ~ '^[0-9a-f]{64}$'),
 payload jsonb NOT NULL,recommendation_hash text NOT NULL CHECK(recommendation_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 PRIMARY KEY(recommendation_id,version),UNIQUE(case_id,version),
 FOREIGN KEY(case_id,case_revision) REFERENCES csl.case_revisions(case_id,revision),
 CHECK(recommendation_id=case_id),
 CHECK((payload->>'action'='NO_ACTION_AUTHORIZED_EXERCISE' AND payload->>'conclusion'='authorized_synthetic_exercise'
 AND payload->'execution_targets'='[]'::jsonb AND payload->>'source_kind'='synthetic' AND payload->'authenticated'='false'::jsonb) IS TRUE),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '30 minutes')
);
CREATE TABLE csl.ws_reviews (
 review_id text PRIMARY KEY CHECK(review_id ~ '^[0-9a-f]{32}$'),
 recommendation_id text NOT NULL,version integer NOT NULL,recommendation_hash text NOT NULL,
 reviewer_id text NOT NULL REFERENCES csl.ws_users,decision text NOT NULL CHECK(decision IN ('approve','reject')),
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 4000),review_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 FOREIGN KEY(recommendation_id,version) REFERENCES csl.ws_recommendations,
 UNIQUE(recommendation_id,version),UNIQUE(review_id,recommendation_id,version)
);
CREATE TABLE csl.ws_verifiers (
 verifier_id text PRIMARY KEY CHECK(verifier_id ~ '^[0-9a-f]{32}$'),
 login_role name NOT NULL UNIQUE CHECK(login_role::text ~ '^csl_v_[0-9a-f]{12}_[0-9a-f]{32}$'),
 case_id text NOT NULL REFERENCES csl.cases,
 checker_source_digest text NOT NULL CHECK(checker_source_digest ~ '^[0-9a-f]{64}$'),
 enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE csl.ws_verifier_grants (
 verifier_id text NOT NULL REFERENCES csl.ws_verifiers,case_id text NOT NULL REFERENCES csl.cases,
 PRIMARY KEY(verifier_id,case_id)
);
CREATE TABLE csl.ws_verification_requests (
 request_id text PRIMARY KEY CHECK(request_id ~ '^[0-9a-f]{32}$'),
 verifier_id text NOT NULL REFERENCES csl.ws_verifiers,case_id text NOT NULL REFERENCES csl.ws_workflows,
 recommendation_id text NOT NULL,version integer NOT NULL,review_id text NOT NULL,
 workflow_version integer NOT NULL,epoch integer NOT NULL,payload jsonb NOT NULL,
 source_manifest_hash text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,consumed boolean NOT NULL DEFAULT false,report_hash text,verification_id text,
 FOREIGN KEY(review_id,recommendation_id,version) REFERENCES csl.ws_reviews(review_id,recommendation_id,version),
 CHECK((consumed AND report_hash IS NOT NULL AND verification_id IS NOT NULL) OR
 (NOT consumed AND report_hash IS NULL AND verification_id IS NULL))
);
CREATE TABLE csl.ws_verifications (
 verification_id text PRIMARY KEY CHECK(verification_id ~ '^[0-9a-f]{32}$'),
 request_id text NOT NULL UNIQUE REFERENCES csl.ws_verification_requests,
 verifier_id text NOT NULL REFERENCES csl.ws_verifiers,case_id text NOT NULL REFERENCES csl.ws_workflows,
 recommendation_id text NOT NULL,version integer NOT NULL,review_id text NOT NULL,
 result text NOT NULL CHECK(result IN ('verified','contradicted','inconclusive')),
 checker_version text NOT NULL,checker_digest text NOT NULL,source_digest text NOT NULL,
 source_manifest_hash text NOT NULL,checks jsonb NOT NULL,details jsonb NOT NULL,
 scope text NOT NULL DEFAULT 'offline_synthetic_only' CHECK(scope='offline_synthetic_only'),
 source_kind text NOT NULL DEFAULT 'synthetic' CHECK(source_kind='synthetic'),
 authenticated boolean NOT NULL DEFAULT false CHECK(NOT authenticated),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,
 FOREIGN KEY(review_id,recommendation_id,version) REFERENCES csl.ws_reviews(review_id,recommendation_id,version),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '10 minutes')
);
CREATE TABLE csl.ws_closures (
 closure_id text PRIMARY KEY CHECK(closure_id ~ '^[0-9a-f]{32}$'),
 case_id text NOT NULL REFERENCES csl.ws_workflows,epoch integer NOT NULL,
 recommendation_id text NOT NULL,version integer NOT NULL,review_id text NOT NULL,
 verification_id text NOT NULL REFERENCES csl.ws_verifications,reviewer_id text NOT NULL REFERENCES csl.ws_users,
 reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 4000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(case_id,epoch),
 FOREIGN KEY(review_id,recommendation_id,version) REFERENCES csl.ws_reviews(review_id,recommendation_id,version)
);
CREATE TABLE csl.ws_transitions (
 transition_id text PRIMARY KEY CHECK(transition_id ~ '^[0-9a-f]{32}$'),
 case_id text NOT NULL REFERENCES csl.ws_workflows,workflow_version integer NOT NULL,
 epoch integer NOT NULL,action text NOT NULL,old_state text NOT NULL,new_state text NOT NULL,
 actor_id text,payload jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(case_id,workflow_version)
);
CREATE TABLE csl.ws_workflow_csrf (
 nonce_hash text PRIMARY KEY,user_id text NOT NULL REFERENCES csl.ws_users,
 session_hash text NOT NULL REFERENCES csl.ws_sessions ON DELETE CASCADE,
 action text NOT NULL CHECK(action IN ('recommend','review','close','reopen')),
 case_id text NOT NULL REFERENCES csl.cases,workflow_version integer NOT NULL,
 rec_version integer,expires_at timestamptz NOT NULL,used boolean NOT NULL DEFAULT false
);
CREATE TABLE csl.ws_pipeline_identities (
 pipeline_id text PRIMARY KEY CHECK(pipeline_id ~ '^[0-9a-f]{32}$'),
 login_role name NOT NULL UNIQUE CHECK(login_role::text ~ '^csl_p_[0-9a-f]{12}_[0-9a-f]{32}_[cw]$'),
 kind text NOT NULL CHECK(kind IN ('collector','worker')),enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE csl.ws_pipeline_batches (
 transaction_id xid8 NOT NULL,batch_id text PRIMARY KEY REFERENCES csl.batches,
 pipeline_id text NOT NULL REFERENCES csl.ws_pipeline_identities,
 server_started_at timestamptz NOT NULL DEFAULT pg_catalog.pg_postmaster_start_time(),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX pipeline_batch_transaction ON csl.ws_pipeline_batches(transaction_id,pipeline_id);
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['ws_recommendations','ws_reviews','ws_verifications','ws_closures','ws_transitions','ws_pipeline_batches'] LOOP
 EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON csl.%I FOR EACH ROW EXECUTE FUNCTION csl.reject_mutation()',tab);
 END LOOP;
END $$;
CREATE FUNCTION csl.vf_request_mutation() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog,csl,pg_temp AS $$ BEGIN
 IF TG_OP='DELETE' OR OLD.consumed OR NOT NEW.consumed OR NEW.report_hash !~ '^[0-9a-f]{64}$' OR NEW.verification_id !~ '^[0-9a-f]{32}$'
 OR (to_jsonb(NEW)-ARRAY['consumed','report_hash','verification_id']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['consumed','report_hash','verification_id']) THEN RAISE EXCEPTION 'immutable verification request';END IF;
 RETURN NEW;END $$;
CREATE TRIGGER immutable_request BEFORE UPDATE OR DELETE ON csl.ws_verification_requests FOR EACH ROW EXECUTE FUNCTION csl.vf_request_mutation();

CREATE FUNCTION csl.wf_canonical(value jsonb) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT
 SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE result text;BEGIN
 IF jsonb_typeof(value)='object' THEN
 SELECT '{'||coalesce(string_agg(to_jsonb(key)::text||':'||csl.wf_canonical(val),',' ORDER BY key COLLATE "C"),'')||'}' INTO result FROM jsonb_each(value) AS x(key,val);
 ELSIF jsonb_typeof(value)='array' THEN
 SELECT '['||coalesce(string_agg(csl.wf_canonical(val),',' ORDER BY ord),'')||']' INTO result FROM jsonb_array_elements(value) WITH ORDINALITY x(val,ord);
 ELSE result:=value::text;END IF;RETURN result;
END $$;
CREATE FUNCTION csl.wf_hash(value jsonb) RETURNS text LANGUAGE sql IMMUTABLE STRICT
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT encode(sha256(convert_to(csl.wf_canonical(value),'UTF8')),'hex') $$;
CREATE FUNCTION csl.wf_policy() RETURNS text LANGUAGE sql IMMUTABLE
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT 'offline-no-action/1'::text $$;
CREATE FUNCTION csl.wf_manifest() RETURNS jsonb LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT jsonb_build_object(
 'raw_objects',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY raw_id),'[]'::jsonb) FROM
 (SELECT raw_id,archive_hash,content_hash,octet_length(archive_bytes) AS archive_size,expanded_size,record_count,source_kind,authenticated,schema_version,parser_version,canonicalization_version FROM csl.raw_objects)x),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY event_key),'[]'::jsonb) FROM csl.events x),
 'record_variants',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY event_key,record_hash),'[]'::jsonb) FROM
 (SELECT event_key,record_hash,encode(sha256(canonical_bytes),'hex') AS canonical_hash,normalized,schema_version,parser_version,canonicalization_version FROM csl.record_variants)x),
 'source_references',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY batch_id,raw_id,source_ref,record_index),'[]'::jsonb) FROM csl.source_references x),
 'raw_deliveries',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY batch_id,raw_id,source_ref),'[]'::jsonb) FROM csl.raw_deliveries x),
 'batches',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY batch_id),'[]'::jsonb) FROM
 (SELECT batch_id,checkpoint,request_hash,status,generation,accepted_count,duplicate_count,conflicting_count,source_count FROM csl.batches)x),
 'conflicts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY event_key),'[]'::jsonb) FROM csl.conflicts x)) $$;

-- Every mutation first serializes against ingestion/publication, then the case and workflow.
CREATE FUNCTION csl.wf_lock(cid text) RETURNS csl.ws_workflows LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;BEGIN
 PERFORM 1 FROM csl.pipeline WHERE singleton FOR UPDATE;
 PERFORM 1 FROM csl.jobs WHERE generation=(SELECT generation FROM csl.pipeline WHERE singleton) FOR SHARE;
 PERFORM 1 FROM csl.cases WHERE case_id=cid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 INSERT INTO csl.ws_workflows(case_id) VALUES(cid) ON CONFLICT DO NOTHING;
 SELECT * INTO w FROM csl.ws_workflows WHERE case_id=cid FOR UPDATE;RETURN w;
END $$;
CREATE FUNCTION csl.wf_actor(raw_token text,cid text,expected_role text DEFAULT NULL,auth boolean DEFAULT false) RETURNS csl.ws_users LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;BEGIN
 u:=csl.ws_account(raw_token,auth);
 PERFORM 1 FROM csl.ws_users WHERE user_id=u.user_id AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 PERFORM 1 FROM csl.ws_sessions WHERE token_hash=csl.ws_hash(raw_token) AND NOT revoked AND expires_at>clock_timestamp() FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 PERFORM 1 FROM csl.ws_case_grants WHERE user_id=u.user_id AND case_id=cid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 -- Refresh the mapping and role after row-lock waits; the earlier account was only a locator.
 u:=csl.ws_account(raw_token,auth);
 IF expected_role IS NOT NULL AND u.app_role<>expected_role THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 RETURN u;END $$;
CREATE FUNCTION csl.wf_eligible(cid text) RETURNS boolean LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT EXISTS(SELECT FROM csl.cases c JOIN csl.case_revisions r ON (r.case_id,r.revision)=(c.case_id,c.current_revision)
 JOIN csl.findings f ON f.finding_id=r.finding_id CROSS JOIN csl.pipeline p WHERE c.case_id=cid AND c.status='current' AND r.status='current' AND f.status='current'
 AND p.singleton AND p.generation=p.published_generation
 AND EXISTS(SELECT FROM csl.jobs j WHERE j.generation=p.generation AND j.status='succeeded')
 AND NOT EXISTS(SELECT FROM csl.conflicts)) $$;
CREATE FUNCTION csl.wf_transition(cid text,new_state text,act text,actor text,data jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;t csl.ws_transitions;BEGIN
 SELECT * INTO w FROM csl.ws_workflows WHERE case_id=cid;
 IF (SELECT count(*) FROM csl.ws_transitions WHERE case_id=cid)>=1000 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 UPDATE csl.ws_workflows SET state=new_state,workflow_version=workflow_version+1 WHERE case_id=cid;
 INSERT INTO csl.ws_transitions(transition_id,case_id,workflow_version,epoch,action,old_state,new_state,actor_id,payload)
 VALUES(replace(gen_random_uuid()::text,'-',''),cid,w.workflow_version+1,w.epoch,act,w.state,new_state,actor,data) RETURNING * INTO t;
 INSERT INTO csl.audit(kind,payload) VALUES('workflow_'||act,to_jsonb(t));END $$;
CREATE FUNCTION csl.wf_text(value text) RETURNS boolean LANGUAGE sql IMMUTABLE
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT value IS NOT NULL AND length(value) BETWEEN 1 AND 4000 AND value ~ '[^[:space:]]' $$;
CREATE FUNCTION csl.wf_issue_csrf(raw_token text,nonce text,act text,cid text,wv integer,rv integer DEFAULT NULL) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;BEGIN
 PERFORM csl.wf_lock(cid);u:=csl.wf_actor(raw_token,cid,NULL,true);
 IF nonce IS NULL OR length(nonce) NOT BETWEEN 32 AND 256 OR act IS NULL OR act NOT IN ('recommend','review','close','reopen') OR wv IS NULL OR wv<0 OR (act IN ('review','close') AND (rv IS NULL OR rv<1)) THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 DELETE FROM csl.ws_workflow_csrf WHERE session_hash=csl.ws_hash(raw_token) AND (used OR expires_at<=clock_timestamp());
 IF (SELECT count(*) FROM csl.ws_workflow_csrf WHERE session_hash=csl.ws_hash(raw_token))>=128 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 INSERT INTO csl.ws_workflow_csrf VALUES(csl.ws_hash(nonce),u.user_id,csl.ws_hash(raw_token),act,cid,wv,rv,clock_timestamp()+interval '10 minutes',false);
END $$;
CREATE FUNCTION csl.wf_use_csrf(raw_token text,nonce text,act text,cid text,wv integer,rv integer DEFAULT NULL) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ BEGIN
 UPDATE csl.ws_workflow_csrf SET used=true WHERE nonce_hash=csl.ws_hash(nonce) AND session_hash=csl.ws_hash(raw_token) AND action=act AND case_id=cid AND workflow_version=wv AND rec_version IS NOT DISTINCT FROM rv AND NOT used AND expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;END $$;
CREATE FUNCTION csl.wf_rec_current(rec csl.ws_recommendations) RETURNS boolean LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT csl.wf_eligible(rec.case_id) AND rec.expires_at>clock_timestamp() AND rec.payload->>'policy_version'=csl.wf_policy()
 AND rec.recommendation_hash=csl.wf_hash(rec.payload) AND rec.source_manifest_hash=csl.wf_hash(csl.wf_manifest())
 AND EXISTS(SELECT FROM csl.ws_users u JOIN csl.ws_case_grants g ON g.user_id=u.user_id
 WHERE u.user_id=rec.author_id AND u.enabled AND u.app_role='analyst' AND g.case_id=rec.case_id) AND EXISTS(
 SELECT FROM csl.ws_workflows w JOIN csl.cases c ON c.case_id=w.case_id JOIN csl.case_revisions r ON (r.case_id,r.revision)=(c.case_id,c.current_revision)
 CROSS JOIN csl.pipeline p WHERE w.case_id=rec.case_id AND w.rec_version=rec.version AND w.epoch=rec.epoch AND c.current_revision=rec.case_revision
 AND r.fingerprint=rec.case_fingerprint AND r.finding_id=rec.finding_id AND p.generation=rec.generation AND w.state NOT IN ('open','rejected','reopen_required')) $$;
CREATE FUNCTION csl.wf_approval_current(rec csl.ws_recommendations,review csl.ws_reviews) RETURNS boolean LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT csl.wf_rec_current(rec) AND review.decision='approve' AND review.expires_at>clock_timestamp()
 AND review.recommendation_id=rec.recommendation_id AND review.version=rec.version AND review.recommendation_hash=rec.recommendation_hash AND review.reviewer_id<>rec.author_id
 AND review.review_hash=csl.wf_hash(jsonb_build_object('review_id',review.review_id,'recommendation_id',review.recommendation_id,'version',review.version,'recommendation_hash',review.recommendation_hash,'reviewer_id',review.reviewer_id,'decision',review.decision,'reason',review.reason))
 AND EXISTS(SELECT FROM csl.ws_users u JOIN csl.ws_case_grants g ON g.user_id=u.user_id WHERE u.user_id=review.reviewer_id AND u.enabled AND u.app_role='reviewer' AND g.case_id=rec.case_id) $$;
CREATE FUNCTION csl.wf_lock_author(rec csl.ws_recommendations) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ BEGIN
 PERFORM 1 FROM csl.ws_users WHERE user_id=rec.author_id AND enabled AND app_role='analyst' FOR SHARE;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM csl.ws_case_grants WHERE user_id=rec.author_id AND case_id=rec.case_id FOR SHARE;
 RETURN FOUND;END $$;
CREATE FUNCTION csl.wf_lock_approval(rec csl.ws_recommendations,review csl.ws_reviews) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ BEGIN
 IF NOT csl.wf_lock_author(rec) THEN RETURN false;END IF;
 PERFORM 1 FROM csl.ws_users WHERE user_id=review.reviewer_id AND enabled AND app_role='reviewer' FOR SHARE;
 IF NOT FOUND THEN RETURN false;END IF;
 PERFORM 1 FROM csl.ws_case_grants WHERE user_id=review.reviewer_id AND case_id=rec.case_id FOR SHARE;
 RETURN FOUND AND coalesce(csl.wf_approval_current(rec,review),false);END $$;
CREATE FUNCTION csl.wf_receipt_current(rec csl.ws_recommendations,review csl.ws_reviews,receipt csl.ws_verifications) RETURNS boolean LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT csl.wf_approval_current(rec,review) AND receipt.result='verified' AND receipt.expires_at>clock_timestamp()
 AND receipt.review_id=review.review_id AND receipt.recommendation_id=rec.recommendation_id AND receipt.version=rec.version AND receipt.source_manifest_hash=rec.source_manifest_hash
 AND EXISTS(SELECT FROM csl.ws_verifiers v JOIN csl.ws_verifier_grants g ON g.verifier_id=v.verifier_id WHERE v.verifier_id=receipt.verifier_id AND v.enabled AND v.case_id=rec.case_id AND g.case_id=rec.case_id AND v.checker_source_digest=receipt.source_digest)
 AND NOT EXISTS(SELECT FROM csl.ws_verifications newer WHERE newer.recommendation_id=rec.recommendation_id AND newer.version=rec.version AND (newer.created_at,newer.verification_id)>(receipt.created_at,receipt.verification_id)) $$;

CREATE FUNCTION csl.wf_rec_view(rec csl.ws_recommendations) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE review csl.ws_reviews;receipt csl.ws_verifications;effective boolean;BEGIN
 SELECT * INTO review FROM csl.ws_reviews WHERE recommendation_id=rec.recommendation_id AND version=rec.version;
 SELECT * INTO receipt FROM csl.ws_verifications WHERE recommendation_id=rec.recommendation_id AND version=rec.version ORDER BY created_at DESC,verification_id DESC LIMIT 1;
 effective:=coalesce(csl.wf_rec_current(rec),false);
 IF review.review_id IS NOT NULL THEN effective:=effective AND coalesce(csl.wf_approval_current(rec,review),false);END IF;
 IF receipt.verification_id IS NOT NULL THEN effective:=effective AND coalesce(csl.wf_receipt_current(rec,review,receipt),false);END IF;
 RETURN to_jsonb(rec)||jsonb_build_object('review',CASE WHEN review.review_id IS NULL THEN NULL ELSE to_jsonb(review) END,'verification',CASE WHEN receipt.verification_id IS NULL THEN NULL ELSE to_jsonb(receipt) END,
 'effective',effective,'blocking_reasons',CASE WHEN effective THEN '[]'::jsonb ELSE '["stale_or_expired_binding"]'::jsonb END);END $$;
CREATE FUNCTION csl.wf_view(raw_token text,cid text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;w csl.ws_workflows;r csl.case_revisions;rec csl.ws_recommendations;BEGIN
 u:=csl.ws_account(raw_token);
 IF NOT EXISTS(SELECT FROM csl.ws_case_grants WHERE user_id=u.user_id AND case_id=cid) THEN RETURN NULL;END IF;
 SELECT x.* INTO r FROM csl.case_revisions x JOIN csl.cases c ON (c.case_id,c.current_revision)=(x.case_id,x.revision) WHERE c.case_id=cid;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO w FROM csl.ws_workflows WHERE case_id=cid;
 SELECT * INTO rec FROM csl.ws_recommendations WHERE case_id=cid ORDER BY version DESC LIMIT 1;
 RETURN jsonb_build_object('case_id',cid,'state',coalesce(w.state,'open'),'workflow_version',coalesce(w.workflow_version,0),'epoch',coalesce(w.epoch,1),
 'eligible',csl.wf_eligible(cid),'policy_version',csl.wf_policy(),'case_revision',r.revision,'fingerprint',r.fingerprint,
 'current_recommendation',CASE WHEN rec.recommendation_id IS NULL THEN NULL ELSE csl.wf_rec_view(rec) END,
 'recommendations',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.version),'[]'::jsonb) FROM
 (SELECT recommendation_id,version,recommendation_hash,author_id,case_revision,created_at,expires_at
 FROM csl.ws_recommendations WHERE case_id=cid ORDER BY version DESC LIMIT 20)x),
 'recommendation_count',(SELECT count(*) FROM csl.ws_recommendations WHERE case_id=cid),
 'recommendations_truncated',(SELECT count(*)>20 FROM csl.ws_recommendations WHERE case_id=cid),
 'transitions',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.workflow_version),'[]'::jsonb) FROM (SELECT * FROM csl.ws_transitions WHERE case_id=cid ORDER BY workflow_version DESC LIMIT 50)x),
 'closures',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.created_at,x.closure_id),'[]'::jsonb) FROM (SELECT * FROM csl.ws_closures WHERE case_id=cid ORDER BY created_at DESC,closure_id DESC LIMIT 20)x));
END $$;
CREATE FUNCTION csl.wf_recommendation(raw_token text,cid text,rv integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;rec csl.ws_recommendations;BEGIN
 u:=csl.ws_account(raw_token);
 IF cid IS NULL OR cid !~ '^[0-9a-f]{64}$' OR rv IS NULL OR rv NOT BETWEEN 1 AND 64 THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT FROM csl.ws_case_grants WHERE user_id=u.user_id AND case_id=cid) THEN RETURN NULL;END IF;
 SELECT * INTO rec FROM csl.ws_recommendations WHERE case_id=cid AND version=rv;
 IF NOT FOUND THEN RETURN NULL;END IF;RETURN csl.wf_rec_view(rec);END $$;
CREATE FUNCTION csl.wf_queue(raw_token text,off integer DEFAULT 0,lim integer DEFAULT 20) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;result jsonb;BEGIN
 u:=csl.ws_account(raw_token);IF off IS NULL OR lim IS NULL OR off<0 OR off>10000 OR lim<1 OR lim>50 THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) INTO result FROM (SELECT c.case_id,coalesce(w.state,'open') AS state,coalesce(w.workflow_version,0) AS workflow_version,c.current_revision,c.status FROM csl.cases c JOIN csl.ws_case_grants g ON g.case_id=c.case_id AND g.user_id=u.user_id LEFT JOIN csl.ws_workflows w ON w.case_id=c.case_id ORDER BY c.case_id OFFSET off LIMIT lim)x;RETURN result;END $$;

CREATE FUNCTION csl.wf_recommend(raw_token text,nonce text,cid text,rev integer,fp text,wv integer,rationale text,counterevidence text,visibility_gaps text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;u csl.ws_users;r csl.case_revisions;rec csl.ws_recommendations;data jsonb;at timestamptz;BEGIN
 w:=csl.wf_lock(cid);u:=csl.wf_actor(raw_token,cid,'analyst');
 IF wv IS NULL OR w.workflow_version<>wv OR w.state IN ('closed','reopen_required') OR NOT csl.wf_eligible(cid) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 SELECT x.* INTO r FROM csl.case_revisions x JOIN csl.cases c ON (c.case_id,c.current_revision)=(x.case_id,x.revision) WHERE c.case_id=cid;
 IF rev IS NULL OR fp IS NULL OR r.revision<>rev OR r.fingerprint<>fp THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF NOT csl.wf_text(rationale) OR NOT csl.wf_text(counterevidence) OR NOT csl.wf_text(visibility_gaps) THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 IF w.rec_version>=64 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 data:=jsonb_build_object('case_id',cid,'case_revision',rev,'case_fingerprint',fp,'finding_id',r.finding_id,'generation',(SELECT generation FROM csl.pipeline),'epoch',w.epoch,
 'evidence',(SELECT coalesce(jsonb_agg(jsonb_build_object('event_key',event_key,'record_hash',record_hash) ORDER BY event_key,record_hash),'[]'::jsonb) FROM csl.finding_evidence WHERE finding_id=r.finding_id),
 'source_manifest_hash',csl.wf_hash(csl.wf_manifest()),'policy_version',csl.wf_policy(),'action','NO_ACTION_AUTHORIZED_EXERCISE','conclusion','authorized_synthetic_exercise','execution_targets','[]'::jsonb,'source_kind','synthetic','authenticated',false,
 'rationale',rationale,'counterevidence',counterevidence,'visibility_gaps',visibility_gaps);
 PERFORM csl.wf_use_csrf(raw_token,nonce,'recommend',cid,wv,NULL);at:=clock_timestamp();
 INSERT INTO csl.ws_recommendations VALUES(cid,w.rec_version+1,cid,u.user_id,rev,fp,r.finding_id,(SELECT generation FROM csl.pipeline),w.epoch,data->>'source_manifest_hash',data,csl.wf_hash(data),at,at+interval '30 minutes') RETURNING * INTO rec;
 UPDATE csl.ws_workflows SET rec_version=rec.version WHERE case_id=cid;
 PERFORM csl.wf_transition(cid,'recommended','recommend',u.user_id,jsonb_build_object('recommendation_id',cid,'version',rec.version,'recommendation_hash',rec.recommendation_hash));RETURN to_jsonb(rec);END $$;
CREATE FUNCTION csl.wf_review(raw_token text,nonce text,cid text,wv integer,rid text,rv integer,rh text,decision text,reason text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;u csl.ws_users;rec csl.ws_recommendations;review csl.ws_reviews;identifier text;data jsonb;BEGIN
 w:=csl.wf_lock(cid);u:=csl.wf_actor(raw_token,cid,'reviewer');
 SELECT * INTO rec FROM csl.ws_recommendations WHERE recommendation_id=rid AND version=rv AND case_id=cid;
 IF wv IS NULL OR w.workflow_version<>wv OR w.state<>'recommended' OR rec.recommendation_id IS NULL OR rh IS NULL OR rec.recommendation_hash<>rh OR NOT csl.wf_lock_author(rec) OR NOT csl.wf_rec_current(rec) OR EXISTS(SELECT FROM csl.ws_reviews WHERE recommendation_id=rid AND version=rv) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF rec.author_id=u.user_id THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 IF decision IS NULL OR decision NOT IN ('approve','reject') OR NOT csl.wf_text(reason) THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 PERFORM csl.wf_use_csrf(raw_token,nonce,'review',cid,wv,rv);identifier:=replace(gen_random_uuid()::text,'-','');
 data:=jsonb_build_object('review_id',identifier,'recommendation_id',rid,'version',rv,'recommendation_hash',rh,'reviewer_id',u.user_id,'decision',decision,'reason',reason);
 INSERT INTO csl.ws_reviews VALUES(identifier,rid,rv,rh,u.user_id,decision,reason,csl.wf_hash(data),clock_timestamp(),rec.expires_at) RETURNING * INTO review;
 PERFORM csl.wf_transition(cid,CASE WHEN decision='approve' THEN 'approved' ELSE 'rejected' END,'review',u.user_id,to_jsonb(review));RETURN to_jsonb(review);END $$;
CREATE FUNCTION csl.wf_close(raw_token text,nonce text,cid text,wv integer,rid text,rv integer,rh text,reviewid text,verificationid text,reason text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;u csl.ws_users;rec csl.ws_recommendations;review csl.ws_reviews;receipt csl.ws_verifications;closure csl.ws_closures;BEGIN
 w:=csl.wf_lock(cid);u:=csl.wf_actor(raw_token,cid,'reviewer');
 SELECT * INTO rec FROM csl.ws_recommendations WHERE recommendation_id=rid AND version=rv AND case_id=cid;
 SELECT * INTO review FROM csl.ws_reviews WHERE review_id=reviewid;
 SELECT * INTO receipt FROM csl.ws_verifications WHERE verification_id=verificationid;
 IF wv IS NULL OR w.workflow_version<>wv OR w.state<>'verified' OR rec.recommendation_id IS NULL OR review.review_id IS NULL OR receipt.verification_id IS NULL OR rh IS NULL OR rec.recommendation_hash<>rh OR NOT coalesce(csl.wf_receipt_current(rec,review,receipt),false) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF u.user_id<>review.reviewer_id OR u.user_id=rec.author_id THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 IF NOT csl.wf_lock_approval(rec,review) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 PERFORM 1 FROM csl.ws_verifiers v JOIN csl.ws_verifier_grants g ON g.verifier_id=v.verifier_id WHERE v.verifier_id=receipt.verifier_id AND v.enabled AND g.case_id=cid FOR SHARE OF v,g;
 IF NOT FOUND OR NOT coalesce(csl.wf_receipt_current(rec,review,receipt),false) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF NOT csl.wf_text(reason) THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 PERFORM csl.wf_use_csrf(raw_token,nonce,'close',cid,wv,rv);
 INSERT INTO csl.ws_closures VALUES(replace(gen_random_uuid()::text,'-',''),cid,w.epoch,rid,rv,reviewid,verificationid,u.user_id,reason,clock_timestamp()) RETURNING * INTO closure;
 PERFORM csl.wf_transition(cid,'closed','close',u.user_id,to_jsonb(closure));RETURN to_jsonb(closure);END $$;
CREATE FUNCTION csl.wf_reopen(raw_token text,nonce text,cid text,wv integer,reason text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;u csl.ws_users;BEGIN
 w:=csl.wf_lock(cid);u:=csl.wf_actor(raw_token,cid,'reviewer');
 IF wv IS NULL OR w.workflow_version<>wv OR w.state<>'reopen_required' OR NOT csl.wf_eligible(cid) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF NOT csl.wf_text(reason) THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 PERFORM csl.wf_use_csrf(raw_token,nonce,'reopen',cid,wv,NULL);
 UPDATE csl.ws_workflows SET epoch=epoch+1 WHERE case_id=cid;
 PERFORM csl.wf_transition(cid,'open','reopen',u.user_id,jsonb_build_object('reason',reason));RETURN csl.wf_view(raw_token,cid);END $$;

-- Only actual maintenance authority may bypass normal machine identity checks.
CREATE FUNCTION csl.pi_actor() RETURNS csl.ws_pipeline_identities LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE identity csl.ws_pipeline_identities;capability text;BEGIN
 IF EXISTS(SELECT FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER AND rolsuper) OR
 EXISTS(SELECT FROM pg_catalog.pg_database WHERE datname=current_database() AND pg_has_role(SESSION_USER,datdba,'USAGE')) THEN RETURN NULL;END IF;
 SELECT * INTO identity FROM csl.ws_pipeline_identities WHERE login_role=SESSION_USER AND enabled FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'PIPE_DENIED';END IF;
 SELECT 'csl_p'||CASE WHEN identity.kind='collector' THEN 'c' ELSE 'w' END||'_'||substr(encode(sha256(convert_to(database_id::text,'UTF8')),'hex'),1,12)
 INTO capability FROM csl.schema_migrations WHERE version=2;
 IF NOT EXISTS(SELECT FROM pg_catalog.pg_auth_members m JOIN pg_catalog.pg_roles r ON r.oid=m.roleid
 WHERE r.rolname=capability AND NOT m.admin_option AND m.member=(SELECT oid FROM pg_catalog.pg_roles WHERE rolname=SESSION_USER)) THEN RAISE EXCEPTION 'PIPE_DENIED';END IF;
 RETURN identity;END $$;
CREATE FUNCTION csl.pi_write_guard() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE identity csl.ws_pipeline_identities;w csl.ws_workflows;BEGIN
 -- A statement trigger runs before any target tuples can be locked or changed.
 PERFORM 1 FROM csl.pipeline WHERE singleton FOR UPDATE;
 identity:=csl.pi_actor();
 IF identity.pipeline_id IS NULL THEN RETURN NULL;END IF;
 IF identity.kind='collector' THEN
 IF TG_TABLE_NAME='batches' AND TG_OP='INSERT' THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT FROM csl.ws_pipeline_batches WHERE transaction_id=pg_current_xact_id() AND pipeline_id=identity.pipeline_id AND server_started_at=pg_catalog.pg_postmaster_start_time()) THEN RAISE EXCEPTION 'PIPE_BATCH_REQUIRED';END IF;
 RETURN NULL;END IF;
 -- Processing leases are serialized, but old-job bookkeeping does not alter evidence.
 IF TG_TABLE_NAME='jobs' AND TG_OP='UPDATE' THEN RETURN NULL;END IF;
 FOR w IN SELECT * FROM csl.ws_workflows WHERE state NOT IN ('open','reopen_required') ORDER BY case_id FOR UPDATE LOOP
 PERFORM csl.wf_transition(w.case_id,CASE WHEN w.state='closed' THEN 'reopen_required' ELSE 'open' END,'machine_changed',identity.pipeline_id,
 jsonb_build_object('relation',TG_TABLE_NAME,'operation',TG_OP));
 END LOOP;RETURN NULL;END $$;

CREATE FUNCTION csl.wf_invalidate_batch() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;identity csl.ws_pipeline_identities;BEGIN
 PERFORM 1 FROM csl.pipeline WHERE singleton FOR UPDATE;
 identity:=csl.pi_actor();
 IF identity.pipeline_id IS NOT NULL THEN
 IF identity.kind<>'collector' THEN RAISE EXCEPTION 'PIPE_DENIED';END IF;
 INSERT INTO csl.ws_pipeline_batches(transaction_id,batch_id,pipeline_id) VALUES(pg_current_xact_id(),NEW.batch_id,identity.pipeline_id);
 END IF;
 FOR w IN SELECT * FROM csl.ws_workflows ORDER BY case_id FOR UPDATE LOOP
 PERFORM csl.wf_transition(w.case_id,CASE WHEN w.state IN ('closed','reopen_required') THEN 'reopen_required' ELSE 'open' END,'evidence_invalidated',NULL,jsonb_build_object('batch_id',NEW.batch_id,'generation',NEW.generation));
 END LOOP;RETURN NEW;END $$;
CREATE TRIGGER workflow_batch_invalidation AFTER INSERT ON csl.batches FOR EACH ROW EXECUTE FUNCTION csl.wf_invalidate_batch();

-- Authentication mutations lock user before session before nonce, matching workflow checks.
CREATE OR REPLACE FUNCTION csl.ws_revoke(raw_token text,nonce text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;BEGIN
 u:=csl.ws_account(raw_token,true);PERFORM 1 FROM csl.ws_users WHERE user_id=u.user_id FOR UPDATE;
 PERFORM 1 FROM csl.ws_sessions WHERE token_hash=csl.ws_hash(raw_token) FOR UPDATE;
 PERFORM csl.ws_account(raw_token,true);PERFORM csl.ws_use_csrf(raw_token,nonce,'logout');
 UPDATE csl.ws_sessions SET revoked=true WHERE token_hash=csl.ws_hash(raw_token);END $$;
CREATE OR REPLACE FUNCTION csl.ws_rotate(raw_token text,nonce text,new_token text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE u csl.ws_users;BEGIN
 u:=csl.ws_account(raw_token,true);PERFORM 1 FROM csl.ws_users WHERE user_id=u.user_id FOR UPDATE;
 PERFORM 1 FROM csl.ws_sessions WHERE token_hash=csl.ws_hash(raw_token) FOR UPDATE;
 PERFORM csl.ws_account(raw_token,true);PERFORM csl.ws_use_csrf(raw_token,nonce,'rotate');
 UPDATE csl.ws_sessions SET revoked=true WHERE token_hash=csl.ws_hash(raw_token);RETURN csl.ws_create_session(new_token);END $$;

CREATE FUNCTION csl.vf_identity() RETURNS jsonb LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT jsonb_build_object('verifier_id',v.verifier_id,'case_id',v.case_id,'checker_policy','synthetic-aws-lab-001-independent/1','checker_version','1.0','checker_source_digest',v.checker_source_digest)
 FROM csl.ws_verifiers v JOIN csl.ws_verifier_grants g ON g.verifier_id=v.verifier_id AND g.case_id=v.case_id WHERE v.login_role=SESSION_USER AND v.enabled $$;
CREATE FUNCTION csl.vf_actor(cid text) RETURNS csl.ws_verifiers LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE v csl.ws_verifiers;BEGIN
 SELECT * INTO v FROM csl.ws_verifiers WHERE login_role=SESSION_USER AND enabled AND case_id=cid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 PERFORM 1 FROM csl.ws_verifier_grants WHERE verifier_id=v.verifier_id AND case_id=cid FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;RETURN v;END $$;
CREATE FUNCTION csl.vf_begin(rid text,rv integer,run_id text DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE w csl.ws_workflows;v csl.ws_verifiers;rec csl.ws_recommendations;review csl.ws_reviews;q csl.ws_verification_requests;data jsonb;manifest jsonb;identifier text;BEGIN
 SELECT * INTO rec FROM csl.ws_recommendations WHERE recommendation_id=rid AND version=rv;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 w:=csl.wf_lock(rec.case_id);v:=csl.vf_actor(rec.case_id);
 SELECT * INTO review FROM csl.ws_reviews WHERE recommendation_id=rid AND version=rv;
 IF NOT csl.wf_lock_approval(rec,review) OR w.state IN ('closed','reopen_required') THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF run_id IS NOT NULL AND run_id !~ '^[0-9a-f]{32}$' THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 identifier:=coalesce(run_id,substr(csl.wf_hash(jsonb_build_object('verifier',v.verifier_id,'recommendation',rid,'version',rv,'review',review.review_id)),1,32));
 SELECT * INTO q FROM csl.ws_verification_requests WHERE request_id=identifier;
 IF FOUND THEN
 IF q.verifier_id<>v.verifier_id OR q.recommendation_id<>rid OR q.version<>rv OR q.review_id<>review.review_id THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 RETURN q.payload||CASE WHEN q.consumed THEN jsonb_build_object('retained_receipt',(SELECT to_jsonb(x) FROM csl.ws_verifications x WHERE verification_id=q.verification_id)) ELSE '{}'::jsonb END;END IF;
 IF (SELECT count(*) FROM csl.ws_verification_requests WHERE case_id=rec.case_id)>=128 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 manifest:=csl.wf_manifest();
 data:=jsonb_build_object('request_id',identifier,'request_version','1.0','database_id',(SELECT database_id FROM csl.schema_migrations WHERE version=2),'checker_policy','synthetic-aws-lab-001-independent/1','checker_version','1.0','checker_source_digest',v.checker_source_digest,
 'case_id',rec.case_id,'case_revision',rec.case_revision,'case_fingerprint',rec.case_fingerprint,'finding_id',rec.finding_id,'generation',rec.generation,'published_generation',(SELECT published_generation FROM csl.pipeline),'source_manifest_hash',rec.source_manifest_hash,
 'case_payload',(SELECT payload FROM csl.case_revisions WHERE case_id=rec.case_id AND revision=rec.case_revision),'finding_payload',(SELECT payload FROM csl.findings WHERE finding_id=rec.finding_id),
 'recommendation',to_jsonb(rec),'approval',to_jsonb(review),'manifest',manifest,'finding_evidence',(SELECT coalesce(jsonb_agg(jsonb_build_object('event_key',event_key,'record_hash',record_hash) ORDER BY event_key,record_hash),'[]'::jsonb) FROM csl.finding_evidence WHERE finding_id=rec.finding_id),
 'expires_at',least(rec.expires_at,clock_timestamp()+interval '10 minutes'));
 INSERT INTO csl.ws_verification_requests(request_id,verifier_id,case_id,recommendation_id,version,review_id,workflow_version,epoch,payload,source_manifest_hash,expires_at)
 VALUES(identifier,v.verifier_id,rec.case_id,rid,rv,review.review_id,w.workflow_version,w.epoch,data,rec.source_manifest_hash,(data->>'expires_at')::timestamptz);
 RETURN data;END $$;
CREATE FUNCTION csl.vf_original(qid text,rawid text) RETURNS bytea LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE q csl.ws_verification_requests;v csl.ws_verifiers;result bytea;BEGIN
 SELECT * INTO q FROM csl.ws_verification_requests WHERE request_id=qid;
 IF NOT FOUND THEN RETURN NULL;END IF;
 v:=csl.vf_actor(q.case_id);
 IF v.verifier_id<>q.verifier_id OR q.expires_at<=clock_timestamp() OR q.consumed OR NOT EXISTS(SELECT FROM jsonb_array_elements(q.payload->'manifest'->'raw_objects') x WHERE x->>'raw_id'=rawid) THEN RETURN NULL;END IF;
 SELECT archive_bytes INTO result FROM csl.raw_objects WHERE raw_id=rawid;RETURN result;END $$;
CREATE FUNCTION csl.vf_finish(qid text,report jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE q csl.ws_verification_requests;v csl.ws_verifiers;w csl.ws_workflows;rec csl.ws_recommendations;review csl.ws_reviews;receipt csl.ws_verifications;verdict text;digest text;key text;value text;at timestamptz;BEGIN
 SELECT * INTO q FROM csl.ws_verification_requests WHERE request_id=qid;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 w:=csl.wf_lock(q.case_id);v:=csl.vf_actor(q.case_id);
 SELECT * INTO q FROM csl.ws_verification_requests WHERE request_id=qid FOR UPDATE;
 IF q.verifier_id<>v.verifier_id THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 IF NOT coalesce(report IS NOT NULL AND jsonb_typeof(report)='object' AND octet_length(report::text)<=32768 AND jsonb_typeof(report->'details')='object' AND jsonb_typeof(report->'checks')='object' AND (SELECT count(*) FROM jsonb_object_keys(report))=9 AND report->>'checker_version'='1.0' AND report->>'checker_digest'='41f0cb578bf05c42e39053fa5b41f1aa02408117286401e6365ddb19fcd71627' AND report->>'source_digest'=v.checker_source_digest AND report->>'scope'='offline_synthetic_only' AND report->>'source_kind'='synthetic' AND report->'authenticated'='false'::jsonb,false) THEN RAISE EXCEPTION 'WS_INVALID';END IF; -- pragma: allowlist secret - public checker definition SHA-256
 IF NOT report ?& ARRAY['checker_version','checker_digest','source_digest','result','checks','details','scope','source_kind','authenticated'] THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(report->'checks'))<>7 THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 verdict:='verified';
 FOREACH key IN ARRAY ARRAY['integrity','completeness','canonical_records','conflicts','evidence_binding','predicate','case_binding'] LOOP
 value:=report->'checks'->>key;
 IF value IS NULL OR value NOT IN ('pass','fail','unknown') THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 IF value='unknown' OR (key IN ('integrity','completeness','canonical_records') AND value='fail') THEN verdict:='inconclusive';
 ELSIF value='fail' AND verdict='verified' THEN verdict:='contradicted';END IF;
 END LOOP;
 IF report->>'result' IS NULL OR report->>'result'<>verdict THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 digest:=csl.wf_hash(report);
 IF q.consumed THEN
 IF q.report_hash<>digest THEN RAISE EXCEPTION 'WS_STALE';END IF;
 SELECT * INTO receipt FROM csl.ws_verifications WHERE verification_id=q.verification_id;RETURN to_jsonb(receipt);END IF;
 SELECT * INTO rec FROM csl.ws_recommendations WHERE recommendation_id=q.recommendation_id AND version=q.version;
 SELECT * INTO review FROM csl.ws_reviews WHERE review_id=q.review_id;
 IF q.expires_at<=clock_timestamp() OR q.workflow_version<>w.workflow_version OR q.epoch<>w.epoch OR w.state IN ('closed','reopen_required') OR NOT csl.wf_lock_approval(rec,review) OR q.source_manifest_hash<>csl.wf_hash(csl.wf_manifest()) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF (SELECT count(*) FROM csl.ws_verifications WHERE case_id=q.case_id)>=128 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 at:=clock_timestamp();
 INSERT INTO csl.ws_verifications(verification_id,request_id,verifier_id,case_id,recommendation_id,version,review_id,result,checker_version,checker_digest,source_digest,source_manifest_hash,checks,details,created_at,expires_at)
 VALUES(replace(gen_random_uuid()::text,'-',''),qid,v.verifier_id,q.case_id,q.recommendation_id,q.version,q.review_id,verdict,report->>'checker_version',report->>'checker_digest',report->>'source_digest',q.source_manifest_hash,report->'checks',report->'details',at,least(rec.expires_at,at+interval '10 minutes')) RETURNING * INTO receipt;
 UPDATE csl.ws_verification_requests SET consumed=true,report_hash=digest,verification_id=receipt.verification_id WHERE request_id=qid;
 PERFORM csl.wf_transition(q.case_id,verdict,'verification',v.verifier_id,to_jsonb(receipt));RETURN to_jsonb(receipt);END $$;

CREATE FUNCTION csl.pi_identity() RETURNS jsonb LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT jsonb_build_object('pipeline_id',pipeline_id,'kind',kind,'source_kind','synthetic','authenticated',false)
 FROM csl.ws_pipeline_identities WHERE login_role=SESSION_USER AND enabled $$;
CREATE FUNCTION csl.pi_audit(act text,data jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ DECLARE identity csl.ws_pipeline_identities;BEGIN
 identity:=csl.pi_actor();
 IF identity.pipeline_id IS NULL OR act IS NULL OR NOT ((identity.kind='collector' AND act='ingestion_committed') OR
 (identity.kind='worker' AND act IN ('job_claim','job_failure','job_completed','case_revision','outbox_attempt','outbox_local_ack','outbox_receipt_reconciled'))) THEN RAISE EXCEPTION 'PIPE_DENIED';END IF;
 IF data IS NULL OR jsonb_typeof(data)<>'object' OR octet_length(data::text)>104857600 THEN RAISE EXCEPTION 'PIPE_INVALID';END IF;
 INSERT INTO csl.audit(kind,payload) VALUES(act,data||jsonb_build_object('pipeline_id',identity.pipeline_id,'pipeline_kind',identity.kind));END $$;

DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['batches','raw_objects','raw_deliveries','events','record_variants','source_references','conflicts','checkpoints','jobs','findings','finding_evidence','cases','case_revisions','case_timeline','case_lineage'] LOOP
 EXECUTE format('CREATE TRIGGER machine_insert_guard BEFORE INSERT ON csl.%I FOR EACH STATEMENT EXECUTE FUNCTION csl.pi_write_guard()',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['pipeline','findings','cases','jobs'] LOOP
 EXECUTE format('CREATE TRIGGER machine_update_guard BEFORE UPDATE ON csl.%I FOR EACH STATEMENT EXECUTE FUNCTION csl.pi_write_guard()',tab);
 END LOOP;END $$;
