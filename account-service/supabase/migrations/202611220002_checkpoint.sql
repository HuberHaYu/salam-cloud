CREATE EXTENSION IF NOT EXISTS pg_cron;
CREATE EXTENSION IF NOT EXISTS pg_net WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS supabase_vault WITH SCHEMA vault;
-- First configure vault secret salam_id_cron to match the function CRON_SECRET.

SELECT cron.schedule('salam-id-checkpoint','* * * * *',$job$
 SELECT net.http_post(
  url:='https://lnzisnmpmtqfplncfugn.supabase.co/functions/v1/salam-id/internal/checkpoint',
  headers:=jsonb_build_object('Content-Type','application/json','Authorization','Bearer '||(SELECT decrypted_secret FROM vault.decrypted_secrets WHERE name='salam_id_cron')),
  body:='{}'::jsonb,timeout_milliseconds:=120000
 ) WHERE EXISTS (SELECT 1 FROM salam_private.state WHERE key='$alarm' AND (value::text)::numeric<=extract(epoch FROM now())*1000);
$job$);
SELECT jobname,schedule,active FROM cron.job WHERE jobname='salam-id-checkpoint';
