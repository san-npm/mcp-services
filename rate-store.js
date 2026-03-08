// ─── Shared rate-limit store (Redis optional, memory fallback) ───

const REDIS_URL = process.env.REDIS_URL || '';
let redis = null;
const memoryStore = new Map(); // key -> { count, resetAt }

async function getRedis() {
  if (!REDIS_URL) return null;
  if (redis) return redis;
  try {
    const { default: IORedis } = await import('ioredis');
    redis = new IORedis(REDIS_URL, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableReadyCheck: true,
      tls: REDIS_URL.startsWith('rediss://') ? {} : undefined,
    });
    await redis.connect();
    redis.on('error', (e) => console.error('[rate-store] redis error:', e.message));
    console.log('[rate-store] using Redis backend');
    return redis;
  } catch (e) {
    console.error('[rate-store] redis init failed, falling back to memory:', e.message);
    redis = null;
    return null;
  }
}

export async function checkAndMaybeIncrement(key, limit, windowMs, increment = true) {
  const r = await getRedis();
  if (r) {
    if (!increment) {
      const cur = parseInt((await r.get(key)) || '0', 10);
      return { allowed: cur < limit, count: cur, remaining: Math.max(0, limit - cur) };
    }
    const cur = await r.incr(key);
    if (cur === 1) await r.pexpire(key, windowMs);
    return { allowed: cur <= limit, count: cur, remaining: Math.max(0, limit - cur) };
  }

  const now = Date.now();
  const existing = memoryStore.get(key);
  if (!existing || existing.resetAt <= now) {
    const fresh = { count: increment ? 1 : 0, resetAt: now + windowMs };
    memoryStore.set(key, fresh);
    return { allowed: fresh.count < limit || (increment && fresh.count <= limit), count: fresh.count, remaining: Math.max(0, limit - fresh.count) };
  }

  if (increment) existing.count += 1;
  return { allowed: existing.count < limit || (increment && existing.count <= limit), count: existing.count, remaining: Math.max(0, limit - existing.count) };
}

export function cleanupMemoryRateStore() {
  const now = Date.now();
  for (const [k, v] of memoryStore) {
    if (v.resetAt <= now) memoryStore.delete(k);
  }
}
