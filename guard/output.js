// Mission 3-B — 출력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   redactPII(text)       : 휴대전화 · 주민등록번호 · 카드번호 · 이메일을 가린다 (주문번호 · 금액 · 날짜는 그대로)
//   redactSecrets(text)   : API 키 · 접속 문자열 · 비공개 키 · 내부 주소 등을 [SECRET] 으로 바꾼다
//   sanitizeOutput(text)  : 사용자에게 보낼 최종 문자열 (HTML 이스케이프 + 위 두 가지)
//   validateAction(raw, ctx): LLM 이 낸 문자열(raw)을 검증한다.
//        통과 → { ok: true, text, calls: [{ name, args }] } / 거절 → { ok: false, code }
//   LLM 출력은 '신뢰할 수 없는 입력'이다. 허용 목록 · 형식 · 범위를 코드로 확인한다.

function redactPII(text) {
  // TODO
  return String(text);
}

function redactSecrets(text) {
  // TODO
  return String(text);
}

function sanitizeOutput(text) {
  // TODO
  return String(text);
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
