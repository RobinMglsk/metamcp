import logger from "@/utils/logger";

import { ApiKeysRepository } from "../db/repositories/api-keys.repo";

const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
// Expired and revoked keys stay for a day, for troubleshooting
export const RETENTION_MS = 24 * 60 * 60 * 1000;

export async function sweepExpiredSessionKeys(
  repo: Pick<ApiKeysRepository, "deleteExpiredSessionKeys">,
  now: number = Date.now(),
): Promise<number> {
  try {
    const deleted = await repo.deleteExpiredSessionKeys(
      new Date(now - RETENTION_MS),
    );
    if (deleted > 0) logger.info(`Removed ${deleted} expired kcw session keys`);
    return deleted;
  } catch (error) {
    logger.error("Error removing expired kcw session keys:", error);
    return 0;
  }
}

/** Starts the hourly sweep; a no-op unless the kcw routes are enabled. */
export function startKcwKeySweeper(
  repo: Pick<
    ApiKeysRepository,
    "deleteExpiredSessionKeys"
  > = new ApiKeysRepository(),
): void {
  if (!process.env.KCW_SERVICE_TOKEN) return;
  void sweepExpiredSessionKeys(repo);
  setInterval(
    () => void sweepExpiredSessionKeys(repo),
    SWEEP_INTERVAL_MS,
  ).unref();
}
