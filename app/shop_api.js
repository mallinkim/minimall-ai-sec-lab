// MiniMall API 초안 — AI 코딩 도구가 만들어 준 코드라고 가정한다. (수업용)
// 데모는 잘 돌아가고 테스트도 통과한다. 하지만 안전한가?  → Mission 2 에서 취약점을 찾아 고친다.
const crypto = require("crypto");

function createApi({ db, env = {}, clock = { now: () => Date.now() }, gateway }) {
  if (!env.PAYMENT_API_KEY || !env.TOKEN_SECRET) {
    throw new Error("Missing required API configuration");
  }

  const md5 = (s) => crypto.createHash("md5").update(String(s)).digest("hex");
  const json = (status, body) => ({ status, body });

  function authUser(req) {
    const h = (req.headers && req.headers.authorization) || "";
    const tok = h.replace(/^Bearer\s+/i, "");
    if (!tok) return null;
    try {
      const id = Buffer.from(tok, "base64").toString().split(":")[0]; // 토큰 = base64("사용자ID:만료시각")
      return db.query("SELECT * FROM users WHERE id = ?", [id])[0] || null;
    } catch (e) { return null; }
  }

  function route(req) {
    const { method, path, query = {}, body } = req;
    if (method === "POST" && path === "/register") {
      const id = "u" + (db.count("users") + 1);
      db.insert("users", { id, email: body.email, pwhash: md5(body.password), name: body.name, phone: body.phone, role: "customer" });
      return json(201, { id });
    }
    if (method === "POST" && path === "/login") {
      const rows = db.query("SELECT * FROM users WHERE email = ? AND pwhash = ?", [body.email, md5(body.password)]);
      if (!rows.length) return json(401, { error: "INVALID_CREDENTIALS" });
      const exp = clock.now() + 24 * 3600 * 1000;
      return json(200, { token: Buffer.from(`${rows[0].id}:${exp}`).toString("base64") });
    }
    if (method === "GET" && path === "/products") {
      const q = query.q || "";
      const rows = db.query("SELECT * FROM products WHERE status = 'ON_SALE' AND name LIKE ?", ["%" + q + "%"]);
      return json(200, { items: rows.map((r) => ({ id: r.id, name: r.name, price: r.price })) });
    }
    const user = authUser(req);
    if (!user) return json(401, { error: "UNAUTHORIZED" });
    let m;
    if (method === "GET" && (m = path.match(/^\/orders\/(.+)$/))) {
      const rows = db.query("SELECT * FROM orders WHERE id = ? AND user_id = ?", [m[1], user.id]);
      if (!rows.length) return json(404, { error: "NOT_FOUND" });
      const o = rows[0];
      return json(200, { id: o.id, status: o.status, total: o.total, items: o.items, address: o.address });
    }
    if (method === "POST" && path === "/orders") {
      const items = body && body.items;
      const address = body && body.address;
      if (!Array.isArray(items) || items.length === 0 || typeof address !== "string" || !address.trim()) {
        return json(400, { error: "INVALID_ORDER" });
      }

      let total = 0;
      const pricedItems = [];
      for (const item of items) {
        if (!item || item.productId == null || !Number.isInteger(item.quantity) || item.quantity < 1 || item.quantity > 99) {
          return json(400, { error: "INVALID_ORDER" });
        }
        const product = db.query("SELECT * FROM products WHERE id = ? AND status = 'ON_SALE'", [item.productId])[0];
        if (!product) return json(400, { error: "INVALID_ORDER" });

        const price = product.price;
        total += price * item.quantity;
        pricedItems.push({ productId: product.id, quantity: item.quantity, price });
      }

      const id = "ORD-" + (1001 + db.count("orders"));
      db.insert("orders", { id, user_id: user.id, status: "PENDING_PAYMENT", total, address, phone: user.phone, items: pricedItems });
      return json(201, { id, total, status: "PENDING_PAYMENT" });
    }
    if (method === "POST" && path === "/payments") {
      const order = db.query("SELECT * FROM orders WHERE id = ? AND user_id = ?", [body.orderId, user.id])[0];
      if (!order) return json(404, { error: "NOT_FOUND" });
      gateway.charge({ apiKey: env.PAYMENT_API_KEY, amount: order.total, orderId: order.id });
      db.update("orders", (r) => r.id === order.id, { status: "PAID" });
      return json(200, { paid: true, amount: order.total });
    }
    return json(404, { error: "NOT_FOUND" });
  }

  return {
    handle(req) {
      try { return route(req); }
      catch (e) {
        console.error("API request failed:", e);
        return json(500, { error: "INTERNAL_ERROR" });
      }
    },
  };
}
module.exports = { createApi };
