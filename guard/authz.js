// Mission 3-C — 도구 호출 인가 (docs/SEC_CONTRACT.md §3.4 의 표)
//   authorizeTool(call, ctx) → { decision: "allow" | "confirm" | "approve" | "deny", reason }
//   call = { name, args }, ctx = { user: { id }, orders: { ownerOf(orderId) }, tainted, callIndex }
//   allow: 바로 실행 / confirm: 사용자 확인 후 실행 / approve: 사용자 확인 + 담당자 승인 / deny: 거부
//   소유자 · 한도 같은 '권한 규칙'은 프롬프트가 아니라 여기서 코드로 집행한다.

function deny(reason) {
  return { decision: "deny", reason };
}

function isRequesterOrder(orderId, ctx) {
  if (typeof orderId !== "string" || typeof ctx.orders?.ownerOf !== "function") return false;
  const ownerId = ctx.orders.ownerOf(orderId);
  return ownerId !== null && ownerId !== undefined && ownerId === ctx.user.id;
}

function authorizeTool(call, ctx) {
  if (!call || typeof call.name !== "string" || call.name.trim() === "") {
    return deny("TOOL_NOT_ALLOWED");
  }
  if (!call.args || typeof call.args !== "object" || Array.isArray(call.args)) {
    return deny("ARG_INVALID");
  }
  if (!ctx?.user || ctx.user.id === undefined || ctx.user.id === null) {
    return deny("INVALID_CONTEXT");
  }

  switch (call.name) {
    case "search_product":
      return { decision: "allow", reason: "PUBLIC_READ" };
    case "get_order_status":
      return isRequesterOrder(call.args.order_id, ctx)
        ? { decision: "allow", reason: "OWNER" }
        : deny("NOT_OWNER");
    case "apply_coupon":
      if (ctx.tainted === true) return deny("TAINTED_CONTEXT");
      return Number.isInteger(call.args.percent) && call.args.percent >= 1 && call.args.percent <= 20
        ? { decision: "confirm", reason: "WITHIN_LIMIT" }
        : deny("LIMIT");
    case "refund_order":
      if (ctx.tainted === true) return deny("TAINTED_CONTEXT");
      return isRequesterOrder(call.args.order_id, ctx)
        ? { decision: "approve", reason: "STAFF_APPROVAL_REQUIRED" }
        : deny("NOT_OWNER");
    default:
      return deny("TOOL_NOT_ALLOWED");
  }
}

module.exports = { authorizeTool };
