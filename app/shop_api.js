// MiniMall API 초안 — AI 코딩 도구가 만들어 준 코드라고 가정한다. (수업용)
// 데모는 잘 돌아가고 테스트도 통과한다. 하지만 안전한가?  → Mission 2 에서 취약점을 찾아 고친다.
const crypto = require("crypto");

function createApi({ db, env = {}, clock = { now: () => Date.now() }, gateway }) {
  if (!env.PAYMENT_API_KEY || !env.TOKEN_SECRET) {
    throw new Error("Missing required API configuration");
  }

  const json = (status, body) => ({ status, body });

  function signToken(id, exp) {
    const payload = Buffer.from(JSON.stringify({ id, exp })).toString("base64url");
    const signature = crypto.createHmac("sha256", env.TOKEN_SECRET).update(payload).digest("base64url");
    return `${payload}.${signature}`;
  }

  function authUser(req) {
    const h = (req && req.headers && req.headers.authorization) || "";
    if (typeof h !== "string") return null;
    const tok = h.replace(/^Bearer\s+/i, "");
    if (!tok) return null;
    try {
      const parts = tok.split(".");
      if (parts.length !== 2 || !parts[0] || !parts[1] ||
          !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) return null;
      const [payload, signature] = parts;
      const expectedSignature = crypto.createHmac("sha256", env.TOKEN_SECRET).update(payload).digest();
      const actualSignature = Buffer.from(signature, "base64url");
      if (actualSignature.length !== expectedSignature.length ||
          !crypto.timingSafeEqual(actualSignature, expectedSignature)) return null;
      const payloadBytes = Buffer.from(payload, "base64url");
      if (payloadBytes.toString("base64url") !== payload) return null;
      const claims = JSON.parse(payloadBytes.toString("utf8"));
      if (!claims || typeof claims.id !== "string" || !claims.id ||
          !Number.isFinite(claims.exp) || claims.exp <= clock.now()) return null;
      return db.query("SELECT * FROM users WHERE id = ?", [claims.id])[0] || null;
    } catch (e) { return null; }
  }

  function route(req) {
    const { method, path, query = {}, body } = req;
    if (method === "POST" && path === "/register") {
      const { email, password, name, phone } = body || {};
      if ([email, password, name, phone].some((value) => typeof value !== "string" || !value.trim()) ||
          !email.includes("@")) {
        return json(400, { error: "INVALID_INPUT" });
      }

      const existingUsers = db.query("SELECT * FROM users WHERE email = ?", [email]);
      if (existingUsers.length) return json(409, { error: "EMAIL_EXISTS" });

      const id = "u" + (db.count("users") + 1);
      const salt = crypto.randomBytes(16);
      const passwordHash = crypto.scryptSync(String(password), salt, 64).toString("hex");
      db.insert("users", {
        id,
        email,
        pwhash: `${salt.toString("hex")}:${passwordHash}`,
        name,
        phone,
        role: "customer",
      });
      return json(201, { id });
    }
    if (method === "POST" && path === "/login") {
      const rows = db.query("SELECT * FROM users WHERE email = ?", [body.email]);
      if (!rows.length) return json(401, { error: "INVALID_CREDENTIALS" });
      const [saltHex, hashHex] = String(rows[0].pwhash || "").split(":");
      if (!/^[0-9a-f]{32}$/i.test(saltHex) || !/^[0-9a-f]{128}$/i.test(hashHex)) {
        return json(401, { error: "INVALID_CREDENTIALS" });
      }
      const salt = Buffer.from(saltHex, "hex");
      const storedHash = Buffer.from(hashHex, "hex");
      const candidateHash = crypto.scryptSync(String(body.password), salt, 64);
      if (candidateHash.length !== storedHash.length || !crypto.timingSafeEqual(candidateHash, storedHash)) {
        return json(401, { error: "INVALID_CREDENTIALS" });
      }
      const exp = clock.now() + 24 * 3600 * 1000;
      return json(200, { token: signToken(rows[0].id, exp) });
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
