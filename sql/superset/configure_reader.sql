-- Explicit provisioning only; never auto-run in analytical data initialization.
\set ON_ERROR_STOP on
\getenv reader_role SUPERSET_ANALYTICS_USER
\getenv reader_password SUPERSET_ANALYTICS_PASSWORD
\getenv analytics_database POSTGRES_DB
BEGIN;
SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=:'reader_role') AS role_exists,
       EXISTS (SELECT 1 FROM pg_roles WHERE rolname=:'reader_role'
          AND shobj_description(oid,'pg_authid')='DNS Security Analytics Superset read-only role') AS managed_role
\gset
\if :role_exists
  \if :managed_role
  \else
    \echo Refusing to change an existing unmanaged role. Choose a new SUPERSET_ANALYTICS_USER.
    \quit 3
  \endif
\else
  CREATE ROLE :"reader_role";
  COMMENT ON ROLE :"reader_role" IS 'DNS Security Analytics Superset read-only role';
\endif
-- Refuse surprising memberships/ownership rather than changing existing objects.
SELECT EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=:'reader_role')
    OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE r.rolname=:'reader_role') AS unsafe_role
\gset
\if :unsafe_role
  \echo Refusing a reader role with existing memberships or owned relations.
  \quit 3
\endif
ALTER ROLE :"reader_role" LOGIN PASSWORD :'reader_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
ALTER ROLE :"reader_role" SET default_transaction_read_only=on;
GRANT CONNECT ON DATABASE :"analytics_database" TO :"reader_role";
GRANT USAGE ON SCHEMA public TO :"reader_role";
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM :"reader_role";
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM :"reader_role";
GRANT SELECT ON public.dns_events,public.dns_event_features,
    public.dns_window_features,public.dns_alerts TO :"reader_role";
GRANT USAGE ON SCHEMA reporting TO :"reader_role";
REVOKE ALL ON ALL TABLES IN SCHEMA reporting FROM :"reader_role";
GRANT SELECT ON reporting.vw_dns_event_analysis,reporting.vw_dns_window_analysis,
 reporting.vw_dns_alert_analysis,reporting.vw_ctu_capture_sources,
 reporting.vw_ctu_detector_sources,reporting.vw_ctu_feature_samples TO :"reader_role";
SELECT has_schema_privilege(:'reader_role','public','CREATE')
    OR has_database_privilege(:'reader_role',current_database(),'CREATE') AS unsafe_create
\gset
\if :unsafe_create
  \echo Existing inherited PUBLIC permissions allow CREATE; refusing to provision without review.
  \quit 3
\endif
COMMIT;
