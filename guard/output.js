// Mission 3-B — 출력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   redactPII(text)       : 휴대전화 · 주민등록번호 · 카드번호 · 이메일을 가린다 (주문번호 · 금액 · 날짜는 그대로)
//   redactSecrets(text)   : API 키 · 접속 문자열 · 비공개 키 · 내부 주소 등을 [SECRET] 으로 바꾼다
//   sanitizeOutput(text)  : 사용자에게 보낼 최종 문자열 (HTML 이스케이프 + 위 두 가지)
//   validateAction(raw, ctx): LLM 이 낸 문자열(raw)을 검증한다.
//        통과 → { ok: true, text, calls: [{ name, args }] } / 거절 → { ok: false, code }
//   LLM 출력은 '신뢰할 수 없는 입력'이다. 허용 목록 · 형식 · 범위를 코드로 확인한다.

function redactPII(text) {
  const redactSegment = (segment) => {
    let result = segment.replace(
      /(?<![A-Za-z0-9_-])(010)(?:[- .]?)(\d{4})(?:[- .]?)(\d{4})(?![A-Za-z0-9_-])/g,
      (_match, prefix, _middle, last) => `${prefix}-****-${last}`,
    );
    result = result.replace(
      /(?<![A-Za-z0-9_-])(\d{6})-(\d)(\d{6})(?![A-Za-z0-9_-])/g,
      (_match, date, first) => `${date}-${first}******`,
    );

    const passesLuhn = (digits) => {
      let sum = 0;
      const parity = digits.length % 2;
      for (let i = 0; i < digits.length; i++) {
        let digit = Number(digits[i]);
        if (i % 2 === parity) {
          digit *= 2;
          if (digit > 9) digit -= 9;
        }
        sum += digit;
      }
      return sum % 10 === 0;
    };
    result = result.replace(
      /(?<![A-Za-z0-9_-])(?:\d{13,19}|\d{4}([ -])\d{4}(?:\1\d{4}){1,2}(?:\1\d{1,4})?)(?![A-Za-z0-9_-])/g,
      (candidate) => {
        const digits = candidate.replace(/[ -]/g, "");
        return digits.length >= 13 && digits.length <= 19 && passesLuhn(digits)
          ? `****-****-****-${digits.slice(-4)}`
          : candidate;
      },
    );
    return result.replace(
      /(?<![\p{L}\p{N}._%+-])([\p{L}\p{N}._%+-]+)@([\p{L}\p{N}-]+(?:\.[\p{L}\p{N}-]+)+)(?![\p{L}\p{N}-])/gu,
      (_match, local, domain) => `${local[0]}***@${domain}`,
    );
  };

  const value = String(text);
  const protectedPattern =
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)|(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g;
  let result = "";
  let lastIndex = 0;
  for (const match of value.matchAll(protectedPattern)) {
    result += redactSegment(value.slice(lastIndex, match.index));
    result += match[0];
    lastIndex = match.index + match[0].length;
  }
  return result + redactSegment(value.slice(lastIndex));
}

function redactSecrets(text) {
  const isPlaceholder = (value) => {
    const candidate = value.trim();
    return (
      /^\[[A-Z0-9_]+\]$/i.test(candidate) ||
      /^<[\s\S]*>$/.test(candidate) ||
      /^x{4,}$/i.test(candidate) ||
      /^\*{4,}$/.test(candidate) ||
      /^\.\.\.+$/.test(candidate) ||
      /^\$\{[\s\S]*\}$/.test(candidate) ||
      /^(?:changeme|dummy|placeholder)$/i.test(candidate) ||
      /^your-/i.test(candidate) ||
      /^(?:process\.env(?:\.|$)|os\.environ(?:\.|$)|env\.)/i.test(candidate) ||
      /^(.)\1{3,}$/s.test(candidate)
    );
  };

  let result = String(text);
  result = result.replace(
    /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----[\s\S]*?(?:-----END \1-----|$)/g,
    "[SECRET]",
  );
  result = result.replace(
    /(?<![A-Za-z0-9])AKIA([A-Z0-9]{16})(?![A-Za-z0-9])/g,
    (match, value) => (isPlaceholder(value) ? match : "[SECRET]"),
  );
  result = result.replace(
    /(?<![A-Za-z0-9_])sk(?:-live-|_live_)([A-Za-z0-9]{12,})(?![A-Za-z0-9])/gi,
    (match, value) => (isPlaceholder(value) ? match : "[SECRET]"),
  );
  result = result.replace(
    /(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{5,})\.(eyJ[A-Za-z0-9_-]{5,})\.([A-Za-z0-9_-]{8,})(?![A-Za-z0-9_-])/g,
    (match, first, second, signature) =>
      [first, second, signature].some(isPlaceholder) ? match : "[SECRET]",
  );
  result = result.replace(
    /\b([A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s:@]+:)([^@/\s?#]+)(@[^/\s?#]*)/g,
    (match, prefix, password, suffix) =>
      isPlaceholder(password) ? match : `${prefix}[SECRET]${suffix}`,
  );
  result = result.replace(
    /(?<![A-Za-z0-9_-])INTERNAL-KEY-([A-Za-z0-9_-]+)(?![A-Za-z0-9_-])/g,
    (match, value) => (isPlaceholder(value) ? match : "[SECRET]"),
  );
  result = result.replace(/(?<![A-Za-z0-9_-])ADMIN-\d+(?![A-Za-z0-9_-])/g, "[SECRET]");
  return result.replace(
    /(?<![A-Za-z0-9_-])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.internal(?![A-Za-z0-9_-])/gi,
    "[INTERNAL]",
  );
}

function sanitizeOutput(text) {
  return redactSecrets(redactPII(String(text)))
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function validateAction(raw, ctx) {
  const fail = (code) => ({ ok: false, code });
  const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

  if (typeof raw !== "string") return fail("FORMAT");

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return fail("FORMAT");
  }

  if (!isRecord(parsed)) return fail("FORMAT");
  const topKeys = Object.keys(parsed);
  if (topKeys.some((key) => key !== "text" && key !== "tool_calls")) return fail("FORMAT");
  if (typeof parsed.text !== "string" || Array.from(parsed.text).length > 2000) return fail("FORMAT");
  if (Object.prototype.hasOwnProperty.call(parsed, "tool_calls") && !Array.isArray(parsed.tool_calls)) {
    return fail("FORMAT");
  }

  const toolCalls = Object.prototype.hasOwnProperty.call(parsed, "tool_calls") ? parsed.tool_calls : [];
  if (toolCalls.length > 3) return fail("TOO_MANY_CALLS");

  const calls = [];
  for (const call of toolCalls) {
    if (!isRecord(call)) return fail("FORMAT");
    const callKeys = Object.keys(call);
    if (
      !callKeys.includes("name") ||
      typeof call.name !== "string" ||
      call.name.trim() === "" ||
      callKeys.some((key) => key !== "name" && key !== "args")
    ) {
      return fail("FORMAT");
    }

    let argKeys;
    switch (call.name) {
      case "search_product":
        argKeys = ["query"];
        break;
      case "get_order_status":
      case "refund_order":
        argKeys = ["order_id"];
        break;
      case "apply_coupon":
        argKeys = ["code", "percent"];
        break;
      default:
        return fail("TOOL_NOT_ALLOWED");
    }

    if (!Object.prototype.hasOwnProperty.call(call, "args") || !isRecord(call.args)) {
      return fail("ARG_INVALID");
    }
    const actualArgKeys = Object.keys(call.args);
    if (
      actualArgKeys.length !== argKeys.length ||
      actualArgKeys.some((key) => !argKeys.includes(key))
    ) {
      return fail("ARG_INVALID");
    }

    if (call.name === "search_product") {
      const query = call.args.query;
      if (
        typeof query !== "string" ||
        Array.from(query).length < 1 ||
        Array.from(query).length > 50 ||
        !/^[\p{L}\p{N} -]+$/u.test(query) ||
        query.includes("--")
      ) {
        return fail("ARG_INVALID");
      }
    } else if (call.name === "get_order_status" || call.name === "refund_order") {
      const orderId = call.args.order_id;
      const match = typeof orderId === "string" ? /^ORD-[0-9]{4}$/.exec(orderId) : null;
      if (!match || match[0] !== orderId) return fail("ARG_INVALID");
    } else if (call.name === "apply_coupon") {
      const { code, percent } = call.args;
      const match = typeof code === "string" ? /^[A-Z0-9]{4,12}$/.exec(code) : null;
      if (
        !match ||
        match[0] !== code ||
        !Number.isInteger(percent) ||
        percent < 1 ||
        percent > 100
      ) {
        return fail("ARG_INVALID");
      }
    }

    const args = {};
    for (const key of argKeys) args[key] = call.args[key];
    calls.push({ name: call.name, args });
  }

  return { ok: true, text: parsed.text, calls };
}

module.exports = { redactPII, redactSecrets, sanitizeOutput, validateAction };
