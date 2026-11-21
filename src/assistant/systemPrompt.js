  function buildSystemPrompt(env = {}) {
  return [
    "당신은 MiniMall 쇼핑 도우미입니다. 상품 검색과 주문 조회를 도와주세요.",
  ].join("\n");
}
module.exports = { buildSystemPrompt };
