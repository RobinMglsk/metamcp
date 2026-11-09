ALTER TABLE "api_keys" ADD COLUMN "key_prefix" text DEFAULT '' NOT NULL;
--> statement-breakpoint
-- Replace stored plaintext keys by their SHA-256 hex hash (existing keys keep working: the
-- presented key is hashed before lookup). Keep a short clear prefix for display.
UPDATE "api_keys"
SET "key_prefix" = left("key", 12),
    "key" = encode(sha256(convert_to("key", 'UTF8')), 'hex')
WHERE "key_prefix" = '';
