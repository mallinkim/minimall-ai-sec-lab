// Mission 3-A — 입력 단계 방어 (docs/SEC_CONTRACT.md §3 참고)
//   normalizeText(text)      : 모델이 읽는 방식과 같게 글자를 정리한다 (전각 → 반각, 보이지 않는 문자 제거 …)
//   inspectInput(text, ctx)  : { action: "allow" | "block", codes: [...], text } 를 돌려준다. ctx.channel 은 "user" | "document"
//   wrapUntrusted(text)      : 외부 문서를 '데이터'로 가둔다. 형식은 계약서의 구분자 규칙을 따른다.
// 주의: 필터는 보조 수단이다. 정상 사용자를 막지 않도록 '확실한 패턴'만 차단한다.

function normalizeText(text) {
  return String(text)
    .normalize("NFKC")
    .replace(
      /[\u00AD\u034F\u061C\u180B-\u180F\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFE00-\uFE0F\uFEFF\uFFF9-\uFFFB\u{E0001}\u{E0020}-\u{E007F}]/gu,
      "",
    );
}

function inspectInput(text, ctx = {}) {
  const normalized = normalizeText(text);
  const codes = [];

  if (normalized.length > 2000) codes.push("TOO_LONG");
  if (/<<UNTRUSTED|UNTRUSTED>>/i.test(normalized)) codes.push("UNTRUSTED_DELIMITER");

  const disclosureKo =
    /(?:시스템[ \t]*(?:프롬프트|지침|메시지)|초기[ \t]*(?:지시|프롬프트))(?:[ \t]*(?:을|를|은|는|이|가|의))?[ \t]*(?:출력|알려|보여|공개|말해|유출|복사)(?:[ \t]*(?:해(?:[ \t]*(?:줘|주세요|요|라))?|하(?:[ \t]*(?:라|세요|십시오))?|줘|주세요|라|요))?/iu;
  const disclosureMixedKo =
    /\b(?:system[ \t]+(?:prompt|instructions?|message)|initial[ \t]+(?:prompt|instructions?))[ \t]*(?:을|를|은|는|이|가|의)?[ \t]*(?:출력|알려|보여|공개|말해|유출|복사)(?:[ \t]*(?:해(?:[ \t]*(?:줘|주세요|요|라))?|하(?:[ \t]*(?:라|세요|십시오))?|줘|주세요|라|요))?/iu;
  const disclosureEn =
    /\b(?:print|reveal|show|display|repeat|tell|leak|dump)\b(?:[ \t]+(?:out|me|the|your|my|our|hidden|initial|system)){0,3}[ \t]+(?:system[ \t]+(?:prompt|instructions?|message)|initial[ \t]+(?:instructions?|prompt))\b/i;
  const priorInstructionsKo =
    /(?:이전|위|앞의|기존)[ \t]*(?:지시|명령|규칙)(?:[ \t]*(?:을|를|은|는|이|가))?[ \t]*(?:(?:모두|전부)[ \t]*)?(?:무시(?:해(?:[ \t]*(?:요|도|줘|주세요|라))?|하고|하라|하|하세요|하십시오)?|잊(?:어(?:버려|버리고|버리|버려라|버리세요|버려요)?|고|어|지)?)/u;
  const priorInstructionsEn =
    /\b(?:ignore|forget)[ \t]+(?:all[ \t]+)?previous[ \t]+(?:instructions?|commands?|rules?)\b/i;

  if (
    disclosureKo.test(normalized) ||
    disclosureMixedKo.test(normalized) ||
    disclosureEn.test(normalized) ||
    priorInstructionsKo.test(normalized) ||
    priorInstructionsEn.test(normalized)
  ) {
    codes.push("PROMPT_INJECTION");
  }

  return {
    action: codes.length ? "block" : "allow",
    codes,
    text: normalized,
  };
}

function wrapUntrusted(text) {
  const body = normalizeText(text)
    .replace(/<<UNTRUSTED/gi, (marker) => `${marker.slice(0, 2)}-${marker.slice(2)}`)
    .replace(/UNTRUSTED>>/gi, (marker) => `${marker.slice(0, -2)}->>`);
  return `<<UNTRUSTED\n${body}\nUNTRUSTED>>`;
}

module.exports = { normalizeText, inspectInput, wrapUntrusted };
