import http from 'k6/http';

const target = __ENV.SHANNON_TARGET_URL;
if (!target) throw new Error('SHANNON_TARGET_URL is required');

export const options = {
  stages: JSON.parse(__ENV.SHANNON_K6_STAGES || '[]'),
  thresholds: JSON.parse(__ENV.SHANNON_K6_THRESHOLDS || '{}'),
  rps: Number(__ENV.SHANNON_MAX_REQUESTS_PER_SECOND || '1'),
  gracefulStop: '5s',
  noConnectionReuse: false,
};

export default function () {
  const cookie = __ENV.SHANNON_AUTH_COOKIE;
  http.get(target, cookie ? { headers: { Cookie: cookie } } : undefined);
}
