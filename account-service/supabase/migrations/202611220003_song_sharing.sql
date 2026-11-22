-- Temporary sharing state stays private and is never archived to GitHub.
CREATE INDEX IF NOT EXISTS salam_share_expiry ON salam_private.state (((value->>'until')::bigint))
  WHERE key LIKE 'share/%';
-- Expiry is checked on every receive. This job only reclaims storage, with no Edge invocation.
SELECT cron.schedule('salam-song-share-cleanup', '*/5 * * * *', $$
  DELETE FROM salam_private.state
  WHERE key LIKE 'share/%' AND (value->>'until')::bigint <= extract(epoch FROM now())*1000;
$$);
