create extension if not exists pg_cron with schema extensions;
create extension if not exists pgjwt with schema extensions;
create extension if not exists pg_net with schema extensions;

create schema private;

CREATE FUNCTION supabase_url()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  secret_value TEXT;
BEGIN
  SELECT decrypted_secret 
  INTO secret_value 
  FROM vault.decrypted_secrets 
  WHERE name = 'supabase_url';
  RETURN secret_value;
END;
$$;

CREATE FUNCTION private.jwt_secret()
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  secret_value TEXT;
BEGIN
  SELECT decrypted_secret 
  INTO secret_value 
  FROM vault.decrypted_secrets 
  WHERE name = 'app.jwt_secret';
  RETURN secret_value;
END;
$$;

CREATE TABLE job (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    job_name TEXT NOT NULL CHECK (TRIM(job_name) <> ''),
    request_body JSONB,
    state TEXT NOT NULL DEFAULT 'pending',
    retries INT DEFAULT 0,
    max_retries INT DEFAULT 3,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_run_at TIMESTAMP WITH TIME ZONE,
    next_run_at TIMESTAMP WITH TIME ZONE,
    locked_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_valid_state CHECK (state IN (
    	'pending', 'running', 'completed', 'failed', 'canceled'
    ))
);
ALTER TABLE job ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage their own job runs"
ON job FOR ALL TO authenticated USING (
    (SELECT auth.uid()) = user_id
) WITH CHECK (
  (select auth.uid()) = user_id
);

CREATE INDEX idx_job_user_jobname ON job(user_id, job_name);
CREATE INDEX idx_job_state ON job(state);
CREATE INDEX idx_job_locked_at ON job(locked_at);
CREATE INDEX idx_job_pending ON job(user_id, job_name)
WHERE state IN ('pending', 'running');


CREATE TABLE job_config (
    job_name TEXT PRIMARY KEY,
    concurrency_limit INT DEFAULT 1 CHECK (concurrency_limit > 0),
    enabled BOOLEAN NOT NULL
);
ALTER TABLE job_config ENABLE ROW LEVEL SECURITY;

CREATE TABLE job_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id UUID REFERENCES job(id) ON DELETE NO ACTION,
    log_message TEXT,
    log_level TEXT NOT NULL DEFAULT 'INFO',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

ALTER TABLE job_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage their own job run logs"
ON job_logs FOR ALL TO authenticated USING (
    EXISTS (
    SELECT 1
    FROM job
    WHERE job.id = job_logs.job_id
    AND job.user_id = (select auth.uid())
  )
) WITH CHECK (
  EXISTS (
    SELECT 1
    FROM job
    WHERE job.id = job_logs.job_id
    AND job.user_id = (select auth.uid())
  )
);

-- Public methods
CREATE OR REPLACE FUNCTION public.queue_job(
  _job_name TEXT,
  _request_body JSONB,
  _max_retries INT DEFAULT 3
)
RETURNS UUID
SET search_path = public, extensions
AS $$
DECLARE
  new_job_id UUID;
BEGIN
  -- Insert a new job for the current user
  INSERT INTO job (user_id, job_name, request_body, max_retries)
  VALUES ((select auth.uid()), _job_name, _request_body, _max_retries)
  RETURNING id INTO new_job_id;

  -- Log the creation of the job
  PERFORM public.log_job(new_job_id, 'job run created');

  -- Return the ID of the new job
  RETURN new_job_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION public.dequeue_job(
  _job_id UUID
)
RETURNS VOID
SET search_path = public, extensions
AS $$
BEGIN
  -- Update the job to 'canceled' if it is still in the pending state
  UPDATE job
  SET state = 'canceled', updated_at = now()
  WHERE id = _job_id
    AND state = 'pending';

  -- Log the cancellation of the job
  PERFORM public.log_job(_job_id, 'job run canceled');
END;
$$ LANGUAGE plpgsql;


CREATE FUNCTION private.generate_user_jwt(
	p_user_id UUID, p_user_role TEXT, p_user_email TEXT)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  jwt_token TEXT;
  exp_time TIMESTAMP;
BEGIN
  -- Calculate expiration time (1 hour from now)
  exp_time := now() + interval '1 hour';

  -- Generate the JWT
  jwt_token := extensions.sign(
    payload := json_build_object(
      'sub', p_user_id,
      'aud', p_user_role,
      'role', p_user_role,
      'email', p_user_email,
      'iat', extract(epoch from now()),
      'exp', extract(epoch from exp_time)
    )::json,
    secret := (select private.jwt_secret()),
    algorithm := 'HS256'
  );

  RETURN 'Bearer ' || jwt_token;
END;
$$;


CREATE FUNCTION private.run_job(
  _job_id UUID,
  _job_name TEXT,
  _request_body JSONB,
  _user_id UUID,
  _role TEXT,
  _email TEXT
)
RETURNS VOID 
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  timeout_milliseconds INT := 5 * 60 * 1000;
  auth_header TEXT;
BEGIN
  -- Generate the JWT for the current user based on their role and email
  auth_header := private.generate_user_jwt(_user_id, _role, _email);

  PERFORM
    net.http_post(
      url := supabase_url() || '/functions/v1/' || _job_name,
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', auth_header,
        'X-Correlation-ID', _job_id::TEXT,
        'X-Job', 'true'
      ),
      body := _request_body,
      timeout_milliseconds := timeout_milliseconds
    );
  
END;
$$;

CREATE FUNCTION private.run_jobs()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
    job_group RECORD;
    max_concurrency INT;
    running_jobs INT;
    available_slots INT;
    job_enabled BOOLEAN;
    current_job RECORD;
BEGIN
    -- Fetch all user-job pairs with pending jobs
    FOR job_group IN
        SELECT job.user_id, job.job_name
        FROM job
        WHERE job.state = 'pending'
          AND job.locked_at IS NULL
          AND (job.next_run_at IS NULL OR job.next_run_at <= now())
        GROUP BY job.user_id, job.job_name
    LOOP
        -- Skip if job is disabled
        SELECT enabled INTO job_enabled
        FROM job_config
        WHERE job_name = job_group.job_name;

        IF NOT job_enabled THEN
        RAISE LOG 'job %s disabled via job_config', job_group.job_name;
          CONTINUE;
        END IF;

        -- Get the global concurrency limit for the job
        SELECT concurrency_limit INTO max_concurrency
        FROM job_config
        WHERE job_name = job_group.job_name;

        -- Default to 1 if not specified
        IF max_concurrency IS NULL THEN
            max_concurrency := 1;
        END IF;

        -- Count the number of currently running jobs for this user-job pair
        SELECT COUNT(*) INTO running_jobs
        FROM job
        WHERE job_name = job_group.job_name
          AND user_id = job_group.user_id
          AND state = 'running';

        -- Calculate available slots for this user-job pair
        available_slots := max_concurrency - running_jobs;

        IF available_slots > 0 THEN
            -- Select pending jobs up to the available slots
            FOR current_job IN
                SELECT job.id, job.request_body,
                			 job.job_name, u.id AS user_id, u.role, u.email
                FROM job
                JOIN auth.users u ON u.id = job.user_id
                WHERE job.job_name = job_group.job_name
                  AND job.user_id = job_group.user_id
                  AND job.state = 'pending'
                  AND job.locked_at IS NULL
                  AND (job.next_run_at IS NULL OR job.next_run_at <= now())
                ORDER BY job.created_at
                LIMIT available_slots
                FOR UPDATE SKIP LOCKED
            LOOP
                -- Update the job to 'running' and set locked_at
                UPDATE job
                SET locked_at = now(),
                		state = 'running',
                		last_run_at = now(),
                		updated_at = now()
                WHERE id = current_job.id;

                -- Log the start of the job run
                PERFORM public.log_job(current_job.id, 'job run started');

                -- Execute the job using pg_net
                PERFORM private.run_job(
                    current_job.id,
                    current_job.job_name,
                    current_job.request_body,
                    current_job.user_id,
                    current_job.role,
                    current_job.email
                );
            END LOOP;
        END IF;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION private.process_jobs()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  response RECORD;
  job_record RECORD;
  normalized_headers JSONB;
BEGIN
  FOR response IN
    SELECT * FROM net._http_response
    FOR UPDATE SKIP LOCKED  -- Lock the response to prevent concurrent processing
  LOOP
    -- Normalize headers to lowercase
    SELECT jsonb_object_agg(lower(key), value) INTO normalized_headers
    FROM jsonb_each_text(response.headers);
    IF normalized_headers ? 'x-job' THEN
      -- Find and lock the corresponding job record
      IF normalized_headers ? 'x-correlation-id' THEN
        SELECT * INTO job_record
        FROM job
        WHERE id = (normalized_headers->>'x-correlation-id')::UUID
        FOR UPDATE;
        IF FOUND THEN
          DELETE FROM net._http_response WHERE id = response.id;
          IF response.status_code = 200
          OR response.status_code = 201
          OR response.status_code = 204 THEN
            -- Success: Update job to 'completed'
            UPDATE job
            SET state = 'completed', locked_at = NULL, updated_at = now()
            WHERE id = job_record.id;
            -- Log the successful completion
            PERFORM public.log_job(job_record.id,
            	'job run completed successfully');
          ELSE
            -- Failure: Handle retries or mark as failed
            PERFORM private.fail_job_with_retry(job_record.id);
            PERFORM public.log_job(job_record.id,
            	'job run failed and will be retried');
          END IF;
        END IF;
      ELSE
        RAISE LOG 'job run failed due to a missing X-Correlation-ID header. '
              'This is a permanent failure and will not be retried.';
        DELETE FROM net._http_response WHERE id = response.id;
      END IF;
    END IF;
  END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION public.log_job(
  _job_id UUID,
  _log_message TEXT,
  _log_level TEXT DEFAULT 'INFO'
)
RETURNS VOID
AS $$
BEGIN
  INSERT INTO job_logs(job_id, log_message, log_level)
  VALUES (_job_id, _log_message, _log_level);
END;
$$ LANGUAGE plpgsql;

-- mark a job as failed, and queue for a retry 
CREATE OR REPLACE FUNCTION private.fail_job_with_retry(
  _job_id UUID
)
RETURNS VOID
SECURITY DEFINER
AS $$
DECLARE
  _retries INT;
  _max_retries INT;
BEGIN
  -- Fetch the current retries and max_retries for the job
  SELECT retries, max_retries INTO _retries, _max_retries
  FROM job
  WHERE id = _job_id;

  IF _retries + 1 >= _max_retries THEN
    -- Mark job as permanently failed
    UPDATE job 
    SET state = 'failed', locked_at = NULL, updated_at = now()
    WHERE id = _job_id;
  ELSE
    -- Increment retry count and schedule next retry
    UPDATE job 
    SET retries = _retries + 1, 
        state = 'pending',
     		-- Exponential backoff
        next_run_at = now() + INTERVAL '5 minutes' * (2 ^ _retries),
        locked_at = NULL,
        updated_at = now()
    WHERE id = _job_id;
  END IF;
END;
$$ LANGUAGE plpgsql;

-- When a job has expired, reset its status to pending
CREATE OR REPLACE FUNCTION private.reset_stuck_jobs(
  _timeout INTERVAL DEFAULT '15 minutes'
)
RETURNS VOID
SECURITY DEFINER
AS $$
BEGIN
  UPDATE job
  SET locked_at = NULL, state = 'pending', updated_at = now()
  WHERE locked_at < now() - _timeout
    AND state = 'running';
END;
$$ LANGUAGE plpgsql;

SELECT cron.schedule(
  'run-jobs',
  '20 seconds',
  $$
  SELECT private.run_jobs();
  $$
);

SELECT cron.schedule(
  'process-jobs',
  '6 seconds',
  $$ 
  SELECT private.process_jobs();
  $$
);

SELECT cron.schedule(
  'reset-stuck-jobs',
  '*/8 * * * *',
  $$
  SELECT private.reset_stuck_jobs('8 minutes');
  $$
);

