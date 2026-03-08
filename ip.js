// ─── Client IP and proxy trust utilities ───

function normalizeIp(ip) {
  if (!ip || typeof ip !== 'string') return 'unknown';
  const trimmed = ip.trim();
  if (!trimmed) return 'unknown';
  if (trimmed.startsWith('::ffff:')) return trimmed.slice(7);
  return trimmed;
}

export function parseTrustProxyConfig(value) {
  if (value === undefined || value === null || value === '') {
    return { expressValue: false, enabled: false, source: 'default(false)' };
  }

  const raw = String(value).trim();
  const lowered = raw.toLowerCase();

  if (['false', '0', 'no', 'off'].includes(lowered)) {
    return { expressValue: false, enabled: false, source: raw };
  }

  if (['true', 'yes', 'on'].includes(lowered)) {
    return { expressValue: true, enabled: true, source: raw };
  }

  if (/^\d+$/.test(raw)) {
    return { expressValue: Number(raw), enabled: Number(raw) > 0, source: raw };
  }

  // Supports values accepted by proxy-addr: loopback, linklocal, uniquelocal, CIDR, CSV
  return { expressValue: raw, enabled: true, source: raw };
}

export function getClientIp(req) {
  const trustProxyEnabled = req?.app?.locals?.trustProxyEnabled === true;

  if (trustProxyEnabled) {
    return normalizeIp(req?.ip || req?.socket?.remoteAddress || req?.connection?.remoteAddress);
  }

  return normalizeIp(req?.socket?.remoteAddress || req?.connection?.remoteAddress || req?.ip);
}

export function shouldWarnOnForwardedFor(req) {
  const trustProxyEnabled = req?.app?.locals?.trustProxyEnabled === true;
  const forwardedFor = req?.headers?.['x-forwarded-for'];
  return !trustProxyEnabled && typeof forwardedFor === 'string' && forwardedFor.trim().length > 0;
}
