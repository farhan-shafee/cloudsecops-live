-- Forward-only workspace objects. Cluster role creation is an explicit offline step.
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname='csl_ws_owner' AND NOT rolcanlogin AND NOT rolsuper) THEN
 RAISE EXCEPTION 'WS_ROLES_REQUIRED'; END IF;
END $$;
ALTER TABLE csl.schema_migrations DROP CONSTRAINT schema_migrations_version_check;
ALTER TABLE csl.schema_migrations ADD CHECK (version BETWEEN 1 AND 2);
ALTER TABLE csl.schema_migrations ADD COLUMN structural_hash text;
ALTER TABLE csl.schema_migrations ADD COLUMN database_id uuid;
CREATE TABLE csl.ws_users (
 user_id text PRIMARY KEY CHECK(user_id ~ '^[0-9a-f]{32}$'),
 username text NOT NULL UNIQUE CHECK(username ~ '^[a-z][a-z0-9_]{0,31}$'),
 app_role text NOT NULL CHECK(app_role IN ('analyst','reviewer','auditor')),
 password_hash text NOT NULL CHECK(length(password_hash) BETWEEN 32 AND 512),
 auth_role name NOT NULL UNIQUE, data_role name NOT NULL UNIQUE,
 enabled boolean NOT NULL DEFAULT true,
 CHECK(auth_role<>data_role AND auth_role::text ~ '^csl_u_[0-9a-f]{12}_[0-9a-f]{32}_a$'
 AND data_role::text ~ '^csl_u_[0-9a-f]{12}_[0-9a-f]{32}_d$')
);
CREATE TABLE csl.ws_sessions (
 token_hash text PRIMARY KEY CHECK(token_hash ~ '^[0-9a-f]{64}$'),
 user_id text NOT NULL REFERENCES csl.ws_users, expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false
);
CREATE TABLE csl.ws_csrf (
 nonce_hash text PRIMARY KEY CHECK(nonce_hash ~ '^[0-9a-f]{64}$'),
 user_id text NOT NULL REFERENCES csl.ws_users,
 session_hash text NOT NULL REFERENCES csl.ws_sessions ON DELETE CASCADE,
 action text NOT NULL CHECK(action IN ('note','logout','rotate')),
 case_id text,revision integer,expires_at timestamptz NOT NULL,used boolean NOT NULL DEFAULT false,
 CHECK((action='note' AND case_id IS NOT NULL AND revision>0) OR
 (action<>'note' AND case_id IS NULL AND revision IS NULL))
);
CREATE TABLE csl.ws_preauth (
 nonce_hash text PRIMARY KEY,csrf_hash text NOT NULL,expires_at timestamptz NOT NULL
);
CREATE TABLE csl.ws_throttle (
 bucket text PRIMARY KEY,window_start timestamptz NOT NULL,attempts integer NOT NULL CHECK(attempts BETWEEN 1 AND 26)
);
CREATE TABLE csl.ws_case_grants (
 user_id text NOT NULL REFERENCES csl.ws_users,case_id text NOT NULL REFERENCES csl.cases,
 PRIMARY KEY(user_id,case_id)
);
CREATE TABLE csl.ws_notes (
 note_id text PRIMARY KEY CHECK(note_id ~ '^[0-9a-f]{32}$'),
 user_id text NOT NULL REFERENCES csl.ws_users,case_id text NOT NULL,revision integer NOT NULL,
 fingerprint text NOT NULL,body text NOT NULL CHECK(length(body) BETWEEN 1 AND 4000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(case_id,revision) REFERENCES csl.case_revisions(case_id,revision)
);
CREATE TRIGGER immutable_notes BEFORE UPDATE OR DELETE ON csl.ws_notes
 FOR EACH ROW EXECUTE FUNCTION csl.reject_mutation();

CREATE FUNCTION csl.ws_hash(value text) RETURNS text LANGUAGE sql IMMUTABLE STRICT
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT CASE WHEN pg_catalog.octet_length(value) BETWEEN 1 AND 1024
 THEN pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(value,'UTF8')),'hex') ELSE NULL END $$;
CREATE FUNCTION csl.ws_identity() RETURNS jsonb LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
 SELECT pg_catalog.jsonb_build_object('user_id',u.user_id,'username',u.username,'app_role',u.app_role,'role',u.app_role,'enabled',u.enabled,
 'identity_kind',CASE WHEN u.auth_role=SESSION_USER THEN 'auth' ELSE 'data' END)
 FROM csl.ws_users u WHERE (u.auth_role=SESSION_USER OR u.data_role=SESSION_USER) AND u.enabled
$$;
CREATE FUNCTION csl.ws_password_hash() RETURNS text LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
 SELECT u.password_hash FROM csl.ws_users u WHERE u.auth_role=SESSION_USER AND u.enabled
$$;
CREATE FUNCTION csl.ws_account(raw_token text,auth boolean DEFAULT false) RETURNS csl.ws_users
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users; BEGIN
 IF raw_token IS NULL OR length(raw_token) NOT BETWEEN 64 AND 256 THEN RAISE EXCEPTION 'WS_DENIED'; END IF;
 SELECT a.* INTO u FROM csl.ws_users a JOIN csl.ws_sessions s ON s.user_id=a.user_id
 WHERE (CASE WHEN auth THEN a.auth_role ELSE a.data_role END)=SESSION_USER AND a.enabled
 AND s.token_hash=csl.ws_hash(raw_token) AND NOT s.revoked AND s.expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED'; END IF; RETURN u;
END $$;
CREATE FUNCTION csl.ws_create_session(raw_token text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users;s csl.ws_sessions;BEGIN
 SELECT * INTO u FROM csl.ws_users WHERE auth_role=SESSION_USER AND enabled FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 IF raw_token IS NULL OR length(raw_token) NOT BETWEEN 64 AND 256 OR left(raw_token,33)<>u.user_id||'.' THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 DELETE FROM csl.ws_sessions WHERE user_id=u.user_id AND (expires_at<=clock_timestamp() OR revoked);
 IF (SELECT count(*) FROM csl.ws_sessions WHERE user_id=u.user_id)>=8 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 INSERT INTO csl.ws_sessions VALUES(csl.ws_hash(raw_token),u.user_id,clock_timestamp()+interval '30 minutes',false) RETURNING * INTO s;
 RETURN csl.ws_identity()||jsonb_build_object('expires_at',s.expires_at);
END $$;
CREATE FUNCTION csl.ws_session(raw_token text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users;BEGIN u:=csl.ws_account(raw_token);RETURN csl.ws_identity()||
 (SELECT jsonb_build_object('expires_at',expires_at) FROM csl.ws_sessions WHERE token_hash=csl.ws_hash(raw_token));
EXCEPTION WHEN raise_exception THEN RETURN NULL;END $$;
CREATE FUNCTION csl.ws_issue_csrf(raw_token text,nonce text,act text,cid text DEFAULT NULL,rev integer DEFAULT NULL)
 RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users;BEGIN u:=csl.ws_account(raw_token,true);
 PERFORM 1 FROM csl.ws_users WHERE user_id=u.user_id FOR UPDATE;
 IF nonce IS NULL OR length(nonce) NOT BETWEEN 32 AND 256 OR act NOT IN ('note','logout','rotate') THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 IF act='note' AND NOT EXISTS(SELECT FROM csl.ws_case_grants WHERE user_id=u.user_id AND case_id=cid) THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 DELETE FROM csl.ws_csrf WHERE session_hash=csl.ws_hash(raw_token) AND (used OR expires_at<=clock_timestamp());
 IF (SELECT count(*) FROM csl.ws_csrf WHERE session_hash=csl.ws_hash(raw_token))>=128 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 INSERT INTO csl.ws_csrf VALUES(csl.ws_hash(nonce),u.user_id,csl.ws_hash(raw_token),act,cid,rev,clock_timestamp()+interval '10 minutes',false);
END $$;
CREATE FUNCTION csl.ws_use_csrf(raw_token text,nonce text,act text,cid text DEFAULT NULL,rev integer DEFAULT NULL)
 RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
BEGIN
 UPDATE csl.ws_csrf SET used=true WHERE nonce_hash=csl.ws_hash(nonce) AND session_hash=csl.ws_hash(raw_token)
 AND action=act AND case_id IS NOT DISTINCT FROM cid AND revision IS NOT DISTINCT FROM rev
 AND NOT used AND expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'WS_DENIED';END IF;
END $$;
CREATE FUNCTION csl.ws_revoke(raw_token text,nonce text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
BEGIN PERFORM csl.ws_account(raw_token,true);PERFORM csl.ws_use_csrf(raw_token,nonce,'logout');
 UPDATE csl.ws_sessions SET revoked=true WHERE token_hash=csl.ws_hash(raw_token);END $$;
CREATE FUNCTION csl.ws_rotate(raw_token text,nonce text,new_token text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
BEGIN PERFORM csl.ws_account(raw_token,true);PERFORM csl.ws_use_csrf(raw_token,nonce,'rotate');
 UPDATE csl.ws_sessions SET revoked=true WHERE token_hash=csl.ws_hash(raw_token);
 RETURN csl.ws_create_session(new_token);END $$;
CREATE FUNCTION csl.ws_list_cases(raw_token text,off integer DEFAULT 0,lim integer DEFAULT 20) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users; result jsonb;BEGIN u:=csl.ws_account(raw_token);
 IF off IS NULL OR lim IS NULL OR off<0 OR off>10000 OR lim<1 OR lim>50 THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(q)),'[]'::jsonb) INTO result FROM
 (SELECT c.case_id,c.status,c.current_revision,r.fingerprint FROM csl.cases c
 JOIN csl.ws_case_grants g ON g.case_id=c.case_id AND g.user_id=u.user_id
 JOIN csl.case_revisions r ON (r.case_id,r.revision)=(c.case_id,c.current_revision)
 ORDER BY c.case_id OFFSET off LIMIT lim)q;RETURN result;END $$;
CREATE FUNCTION csl.ws_case(raw_token text,cid text,rev integer DEFAULT NULL) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users;result jsonb;r csl.case_revisions;BEGIN u:=csl.ws_account(raw_token);
 IF cid IS NULL OR length(cid)<>64 OR (rev IS NOT NULL AND rev<1) THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT FROM csl.ws_case_grants WHERE user_id=u.user_id AND case_id=cid) THEN RETURN NULL;END IF;
 SELECT x.* INTO r FROM csl.case_revisions x JOIN csl.cases c ON c.case_id=x.case_id
 WHERE x.case_id=cid AND x.revision=coalesce(rev,c.current_revision);
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('case_id',c.case_id,'status',c.status,'current_revision',c.current_revision,
 'revision',r.revision,'fingerprint',r.fingerprint,'payload',r.payload,
 'history',(SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.revision),'[]'::jsonb) FROM
 (SELECT x.revision,x.status,x.fingerprint,x.created_at FROM csl.case_revisions x WHERE x.case_id=cid ORDER BY x.revision DESC LIMIT 100) h),
 'history_count',(SELECT count(*) FROM csl.case_revisions h WHERE h.case_id=cid),
 'history_truncated',(SELECT count(*)>100 FROM csl.case_revisions h WHERE h.case_id=cid),
 'notes',(SELECT coalesce(jsonb_agg(to_jsonb(n)||jsonb_build_object('username',a.username) ORDER BY n.created_at,n.note_id),'[]'::jsonb)
 FROM (SELECT x.* FROM csl.ws_notes x WHERE x.case_id=cid ORDER BY x.created_at DESC,x.note_id DESC LIMIT 50) n JOIN csl.ws_users a ON a.user_id=n.user_id),
 'notes_count',(SELECT count(*) FROM csl.ws_notes n WHERE n.case_id=cid),
 'notes_truncated',(SELECT count(*)>50 FROM csl.ws_notes n WHERE n.case_id=cid),
 'lineage',(SELECT coalesce(jsonb_agg(jsonb_build_object('parent_case_id',l.parent_case_id,'child_case_id',l.child_case_id)),'[]'::jsonb)
 FROM csl.case_lineage l WHERE (l.parent_case_id=cid OR l.child_case_id=cid)
 AND EXISTS(SELECT FROM csl.ws_case_grants g WHERE g.user_id=u.user_id AND g.case_id=l.parent_case_id)
 AND EXISTS(SELECT FROM csl.ws_case_grants g WHERE g.user_id=u.user_id AND g.case_id=l.child_case_id)),
 'evidence',(SELECT coalesce(jsonb_agg(jsonb_build_object('event_key',e.event_key,'record_hash',e.record_hash)),'[]'::jsonb)
 FROM csl.finding_evidence e WHERE e.finding_id=r.finding_id)) INTO result FROM csl.cases c WHERE c.case_id=cid;
 RETURN result;END $$;
CREATE FUNCTION csl.ws_evidence(raw_token text,cid text,rev integer,ek text,rh text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users;result jsonb;BEGIN u:=csl.ws_account(raw_token);
 IF cid IS NULL OR ek IS NULL OR rh IS NULL OR length(cid)<>64 OR length(ek)<>64 OR length(rh)<>64 OR rev IS NULL OR rev<1 THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('event_key',v.event_key,'record_hash',v.record_hash,'canonical_record',convert_from(v.canonical_bytes,'UTF8'),'normalized',v.normalized,
 'sources',(SELECT coalesce(jsonb_agg(to_jsonb(s)-'batch_id' ORDER BY s.raw_id,s.source_ref,s.record_index,s.batch_id),'[]'::jsonb) FROM
 (SELECT sr.batch_id,sr.raw_id,ro.archive_hash,ro.content_hash,sr.source_ref,sr.record_index
 FROM csl.source_references sr JOIN csl.raw_objects ro ON ro.raw_id=sr.raw_id
 WHERE sr.event_key=ek AND sr.record_hash=rh ORDER BY sr.raw_id,sr.source_ref,sr.record_index,sr.batch_id LIMIT 50) s),
 'source_count',(SELECT count(*) FROM csl.source_references sr WHERE sr.event_key=ek AND sr.record_hash=rh))
 INTO result FROM csl.ws_case_grants g JOIN csl.case_revisions r ON r.case_id=g.case_id AND r.revision=rev
 JOIN csl.finding_evidence e ON e.finding_id=r.finding_id AND e.event_key=ek AND e.record_hash=rh
 JOIN csl.record_variants v ON (v.event_key,v.record_hash)=(e.event_key,e.record_hash)
 WHERE g.user_id=u.user_id AND g.case_id=cid;RETURN result;END $$;
CREATE FUNCTION csl.ws_add_note(raw_token text,nonce text,cid text,rev integer,fp text,note_body text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE u csl.ws_users;c csl.cases;n csl.ws_notes;BEGIN u:=csl.ws_account(raw_token);
 IF u.app_role<>'analyst' OR NOT EXISTS(SELECT FROM csl.ws_case_grants WHERE user_id=u.user_id AND case_id=cid) THEN RAISE EXCEPTION 'WS_DENIED';END IF;
 IF note_body IS NULL OR length(note_body) NOT BETWEEN 1 AND 4000 OR note_body !~ '[^[:space:]]' THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 SELECT * INTO c FROM csl.cases WHERE case_id=cid FOR UPDATE;
 IF NOT FOUND OR c.current_revision<>rev OR c.status<>'current' OR NOT EXISTS
 (SELECT FROM csl.case_revisions WHERE case_id=cid AND revision=rev AND fingerprint=fp) THEN RAISE EXCEPTION 'WS_STALE';END IF;
 IF (SELECT count(*) FROM csl.ws_notes WHERE case_id=cid)>=1000 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 PERFORM csl.ws_use_csrf(raw_token,nonce,'note',cid,rev);
 INSERT INTO csl.ws_notes(note_id,user_id,case_id,revision,fingerprint,body)
 VALUES(replace(gen_random_uuid()::text,'-',''),u.user_id,cid,rev,fp,note_body) RETURNING * INTO n;
 INSERT INTO csl.audit(kind,payload) VALUES('workspace_note',jsonb_build_object('note_id',n.note_id,'user_id',u.user_id,'case_id',cid,'revision',rev,'fingerprint',fp));
 RETURN to_jsonb(n)||jsonb_build_object('username',u.username);END $$;
CREATE FUNCTION csl.ws_challenge(nonce text,csrf text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
BEGIN PERFORM pg_advisory_xact_lock(7242601104);
 IF nonce IS NULL OR csrf IS NULL OR length(nonce) NOT BETWEEN 32 AND 256 OR length(csrf) NOT BETWEEN 32 AND 256 THEN RAISE EXCEPTION 'WS_INVALID';END IF;
 DELETE FROM csl.ws_preauth WHERE expires_at<=clock_timestamp();
 IF (SELECT count(*) FROM csl.ws_preauth)>=1000 THEN RAISE EXCEPTION 'WS_LIMIT';END IF;
 INSERT INTO csl.ws_preauth VALUES(csl.ws_hash(nonce),csl.ws_hash(csrf),clock_timestamp()+interval '5 minutes');END $$;
CREATE FUNCTION csl.ws_consume(nonce text,csrf text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
BEGIN DELETE FROM csl.ws_preauth WHERE nonce_hash=csl.ws_hash(nonce) AND csrf_hash=csl.ws_hash(csrf) AND expires_at>clock_timestamp();RETURN FOUND;END $$;
CREATE FUNCTION csl.ws_throttle(username text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$
DECLARE k text; n integer; permitted boolean:=true;duration interval;maximum integer;BEGIN
 PERFORM pg_advisory_xact_lock(7242601105);
 IF username IS NULL OR length(username)>128 THEN RETURN false;END IF;
 DELETE FROM csl.ws_throttle WHERE window_start<clock_timestamp()-interval '5 minutes';
 FOREACH k IN ARRAY ARRAY['global','user:'||csl.ws_hash(username)] LOOP
 duration:=CASE WHEN k='global' THEN interval '1 minute' ELSE interval '5 minutes' END;
 maximum:=CASE WHEN k='global' THEN 25 ELSE 5 END;
 IF NOT EXISTS(SELECT FROM csl.ws_throttle WHERE bucket=k) AND (SELECT count(*) FROM csl.ws_throttle)>=1000 THEN RETURN false;END IF;
 INSERT INTO csl.ws_throttle VALUES(k,clock_timestamp(),1) ON CONFLICT(bucket) DO UPDATE SET
 attempts=CASE WHEN csl.ws_throttle.window_start<=clock_timestamp()-duration THEN 1 ELSE least(csl.ws_throttle.attempts+1,26) END,
 window_start=CASE WHEN csl.ws_throttle.window_start<=clock_timestamp()-duration THEN clock_timestamp() ELSE csl.ws_throttle.window_start END RETURNING attempts INTO n;
 permitted:=permitted AND n<=maximum;
 END LOOP;RETURN permitted;END $$;
CREATE FUNCTION csl.ws_schema_receipt() RETURNS jsonb LANGUAGE sql SECURITY DEFINER
 SET search_path=pg_catalog,csl,pg_temp AS $$ SELECT jsonb_agg(to_jsonb(m) ORDER BY version) FROM csl.schema_migrations m $$;

-- The Python helper uses this same canonical ownership/grant reconstruction on restore.
