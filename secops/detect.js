// secops/detect.js
const CFG = require("../config/sec.json");

function isInWindow(event, windowSec, now) {
  const windowMs = windowSec * 1000;
  return event.ts > now - windowMs && event.ts <= now;
}

function countByUser(events, windowSec, now, matches) {
  const counts = new Map();

  for (const event of events) {
    if (!isInWindow(event, windowSec, now) || !matches(event)) continue;
    counts.set(event.userId, (counts.get(event.userId) || 0) + 1);
  }

  return counts;
}

function addUserAlerts(alerts, counts, threshold, id, severity) {
  for (const [userId, count] of counts) {
    if (count >= threshold) {
      alerts.push({ id, severity, userId });
    }
  }
}

function detect(events, now) {
  const alerts = [];

  const injectionCounts = countByUser(
    events,
    CFG.detect.injectionProbe.windowSec,
    now,
    event =>
      event.type === "INPUT_BLOCKED" || event.type === "DOC_QUARANTINED"
  );
  addUserAlerts(
    alerts,
    injectionCounts,
    CFG.detect.injectionProbe.count,
    "INJECTION_PROBE",
    "medium"
  );

  const enumerationCounts = countByUser(
    events,
    CFG.detect.orderEnumeration.windowSec,
    now,
    event => event.type === "AUTHZ_DENY" && event.code === "NOT_OWNER"
  );
  addUserAlerts(
    alerts,
    enumerationCounts,
    CFG.detect.orderEnumeration.count,
    "ORDER_ENUMERATION",
    "high"
  );

  const bruteForceCounts = countByUser(
    events,
    CFG.detect.bruteForce.windowSec,
    now,
    event => event.type === "LOGIN_FAIL"
  );
  addUserAlerts(
    alerts,
    bruteForceCounts,
    CFG.detect.bruteForce.count,
    "BRUTE_FORCE",
    "high"
  );

  if (
    events.some(
      event =>
        event.type === "SECRET_IN_OUTPUT" &&
        isInWindow(event, CFG.detect.secretInOutput.windowSec, now)
    )
  ) {
    alerts.push({ id: "SECRET_IN_OUTPUT", severity: "critical" });
  }

  const budgetWindowSec = CFG.detect.budget.windowSec;
  const tokenTotal = events.reduce((total, event) => {
    if (
      event.type === "TOKENS_USED" &&
      isInWindow(event, budgetWindowSec, now) &&
      typeof event.tokens === "number"
    ) {
      return total + event.tokens;
    }
    return total;
  }, 0);

  const dailyBudget = CFG.limiter.dailyTokenBudget;
  if (tokenTotal >= dailyBudget) {
    alerts.push({ id: "BUDGET_100", severity: "critical" });
  } else if (tokenTotal >= dailyBudget * CFG.detect.budget.warnRatio) {
    alerts.push({ id: "BUDGET_80", severity: "medium" });
  }

  return alerts;
}

module.exports = { detect };
