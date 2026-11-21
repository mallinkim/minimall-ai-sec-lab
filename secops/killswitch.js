// Mission 4-C — 킬스위치 (docs/SEC_CONTRACT.md §4.3)
//   createKillSwitch() → { isEnabled(feature), disable(feature, { reason, actor, now }), enable(feature, { actor, now }), audit() }
//   기능 이름: "assistant"(도우미 전체), "assistant.write_tools"(쓰기 도구)
function createKillSwitch() {
  const disabledFeatures = new Set();
  const auditEntries = [];

  function isEnabled(feature) {
    const parts = feature.split(".");
    let prefix = "";

    for (const part of parts) {
      prefix = prefix ? `${prefix}.${part}` : part;
      if (disabledFeatures.has(prefix)) return false;
    }

    return true;
  }

  return {
    isEnabled,

    disable(feature, opts) {
      if (!opts || !opts.reason || !opts.actor) {
        throw new Error("reason and actor are required");
      }

      const entry = {
        ts: opts.now,
        feature,
        action: "disable",
        reason: opts.reason,
        actor: opts.actor,
      };

      disabledFeatures.add(feature);
      auditEntries.push(entry);
    },

    enable(feature, opts) {
      if (!opts || !opts.actor) {
        throw new Error("actor is required");
      }

      const entry = {
        ts: opts.now,
        feature,
        action: "enable",
        actor: opts.actor,
      };

      disabledFeatures.delete(feature);
      auditEntries.push(entry);
    },

    audit() {
      return auditEntries.map(entry => ({ ...entry }));
    },
  };
}

module.exports = { createKillSwitch };
