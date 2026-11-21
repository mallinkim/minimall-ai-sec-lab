// Mission 4-B — 한도 (docs/SEC_CONTRACT.md §4.2)
//   createLimiter(cfg) → { check(userId, tokens, now) → { allow: true } | { allow: false, code } }
//   code: TOO_LARGE | RATE_LIMIT | BUDGET
const MINUTE_MS = 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

function createLimiter(cfg) {
  const requestsByUser = new Map();
  let currentDay;
  let dailyTokensUsed = 0;

  return {
    check(userId, tokens, now) {
      if (tokens > cfg.maxTokensPerRequest) {
        return { allow: false, code: "TOO_LARGE" };
      }

      const windowStart = now - MINUTE_MS;
      const userRequests = requestsByUser.get(userId) || [];
      const recentRequests = userRequests.filter(
        timestamp => timestamp > windowStart
      );
      const requestCount = recentRequests.filter(
        timestamp => timestamp <= now
      ).length;

      if (requestCount >= cfg.maxRequestsPerMin) {
        return { allow: false, code: "RATE_LIMIT" };
      }

      const day = Math.floor(now / DAY_MS);
      if (day !== currentDay) {
        currentDay = day;
        dailyTokensUsed = 0;
      }

      if (dailyTokensUsed + tokens > cfg.dailyTokenBudget) {
        return { allow: false, code: "BUDGET" };
      }

      requestsByUser.set(userId, recentRequests.concat(now));
      dailyTokensUsed += tokens;
      return { allow: true };
    },
  };
}

module.exports = { createLimiter };
