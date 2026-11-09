ALTER TABLE "api_keys" ADD COLUMN "expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN "revoked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN "session_id" text;--> statement-breakpoint
ALTER TABLE "api_keys" ADD COLUMN "endpoint_names" text[];--> statement-breakpoint
ALTER TABLE "mcp_request_audit_logs" ADD COLUMN "kcw_session_id" text;--> statement-breakpoint
CREATE INDEX "api_keys_expires_at_idx" ON "api_keys" USING btree ("expires_at");--> statement-breakpoint
CREATE UNIQUE INDEX "api_keys_session_id_idx" ON "api_keys" USING btree ("session_id") WHERE "api_keys"."session_id" IS NOT NULL AND "api_keys"."revoked_at" IS NULL;--> statement-breakpoint
CREATE INDEX "mcp_request_audit_logs_kcw_session_id_idx" ON "mcp_request_audit_logs" USING btree ("kcw_session_id");