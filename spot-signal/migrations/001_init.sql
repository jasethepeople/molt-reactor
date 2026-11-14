CREATE TABLE IF NOT EXISTS reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  submission_id uuid NOT NULL,
  category text NOT NULL CHECK (category IN ('spot', 'full', 'hazard', 'activity', 'resource')),
  location geometry(Point, 4326) NOT NULL CHECK (ST_SRID(location) = 4326),
  confidence smallint NOT NULL CHECK (confidence BETWEEN 1 AND 3),
  confirm_count integer NOT NULL DEFAULT 0 CHECK (confirm_count >= 0),
  deny_count integer NOT NULL DEFAULT 0 CHECK (deny_count >= 0),
  device_hash char(64) NOT NULL CHECK (device_hash ~ '^[0-9a-f]{64}$'),
  activity_opt_in boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
  created_at timestamptz NOT NULL,
  visible_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  CHECK (visible_at >= created_at AND expires_at > visible_at),
  CHECK (category <> 'activity' OR activity_opt_in),
  UNIQUE (device_hash, submission_id)
);

CREATE INDEX IF NOT EXISTS reports_visible_expiry_idx ON reports (status, visible_at, expires_at);
CREATE INDEX IF NOT EXISTS reports_location_gix ON reports USING gist (location);
CREATE INDEX IF NOT EXISTS reports_device_created_idx ON reports (device_hash, created_at DESC);

CREATE TABLE IF NOT EXISTS votes (
  id bigserial PRIMARY KEY,
  report_id uuid NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
  device_hash char(64) NOT NULL CHECK (device_hash ~ '^[0-9a-f]{64}$'),
  vote text NOT NULL CHECK (vote IN ('confirm', 'deny')),
  created_at timestamptz NOT NULL,
  UNIQUE (report_id, device_hash)
);

CREATE INDEX IF NOT EXISTS votes_report_created_idx ON votes (report_id, created_at DESC);

CREATE TABLE IF NOT EXISTS alert_preferences (
  device_hash char(64) PRIMARY KEY CHECK (device_hash ~ '^[0-9a-f]{64}$'),
  location geometry(Point, 4326) NOT NULL CHECK (ST_SRID(location) = 4326),
  radius_m integer NOT NULL CHECK (radius_m BETWEEN 100 AND 5000),
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS alert_preferences_location_gix ON alert_preferences USING gist (location);
CREATE INDEX IF NOT EXISTS alert_preferences_expiry_idx ON alert_preferences (expires_at);
