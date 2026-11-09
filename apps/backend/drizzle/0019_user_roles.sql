ALTER TABLE "users" ADD COLUMN "role" text DEFAULT 'user' NOT NULL;
--> statement-breakpoint
-- Keep existing installs usable: if there is no admin yet, promote the earliest-created user.
UPDATE "users" SET "role" = 'admin'
WHERE "id" = (SELECT "id" FROM "users" ORDER BY "created_at" ASC, "id" ASC LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM "users" WHERE "role" = 'admin');
