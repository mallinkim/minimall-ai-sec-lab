#!/usr/bin/env node
// Mission 5 — 보안 CI 게이트. 사용: node scripts/sec-ci.js [--dir ai_sec]
//   우리 팀 산출물에서는 통과(종료 코드 0), AI 가 만든 산출물(--dir ai_sec)에서는 실패(종료 코드 1)해야 한다.
//   임계값은 THRESHOLDS 에 한 곳으로 모은다. 아래 TODO 세 가지를 완성하세요.
const fs = require("fs"), path = require("path");
const root = path.resolve(__dirname, "..");
const di = process.argv.indexOf("--dir");
const DIR = di >= 0 ? process.argv[di + 1] : null;
const THRESHOLDS = {
  // 계약 §2.2는 시크릿 하드코딩을 금지하고 §2.1 V3은 소스에 비밀 값이 없어야 한다.
  // 따라서 탐지 결과 1건이라도 허용하지 않는다.
  maxSecretFindings: 0,
  // 계약 §2.3은 위험 의존성 코드(NOT_FOUND·TYPOSQUAT 등)를 별도 위험으로 정의한다.
  // 패키지 위험이 하나라도 발견되면 위험을 승인 없이 통과시키지 않는다.
  maxRiskyDeps: 0,
  // 계약 §1은 우리 방어가 자신 공격을 막아야 하며 피해가 발생한 공격을 회귀 실패로 본다.
  // 따라서 실제 피해가 한 건이라도 생기면 병합을 막는다.
  maxRegressionHarms: 0,
};

const FILES = DIR
  ? { secrets: "secrets.js", deps: "deps.js", guard: "guard.js", prompt: "prompt.js", attacks: "attacks.json", manifest: "package.json", scan: [""] }
  : { secrets: "scanner/secrets.js", deps: "scanner/deps.js", guard: ["guard/input.js", "guard/output.js", "guard/authz.js"], prompt: "src/assistant/systemPrompt.js", attacks: "redteam/attacks.json", manifest: "package.json", scan: ["app", "src", "guard", "secops", "scanner", "config"] };
const rel = (f) => path.resolve(root, DIR ? path.join(DIR, f) : f);
const load = (f) => (Array.isArray(f) ? Object.assign({}, ...f.map((x) => require(rel(x)))) : require(rel(f)));
function listFiles() {
  const out = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/\.(js|json|md|env)$/.test(e.name)) out.push({ path: path.relative(root, p), text: fs.readFileSync(p, "utf8") }); } };
  for (const s of FILES.scan) walk(path.resolve(root, DIR ? DIR : s));
  return out;
}

// ---- 검사 1: 저장소의 시크릿 (우리 scanner/secrets.js 사용)
function checkSecrets() {
  if (!Number.isInteger(THRESHOLDS.maxSecretFindings) || THRESHOLDS.maxSecretFindings < 0) {
    return { name: "시크릿 스캔", ok: false, detail: "임계값이 유효한 음이 아닌 정수가 아니다" };
  }

  try {
    const { scanSecrets } = require(rel(FILES.secrets));
    const files = listFiles();
    const rawFindings = scanSecrets(files);
    const findings = rawFindings.filter((finding) => {
      if (finding.type !== "PRIVATE_KEY") return true;

      const file = files.find((candidate) => candidate.path === finding.path);
      const line = file ? file.text.split(/\r?\n/)[finding.line - 1] || "" : "";
      const isRegexDefinition =
        /^\s*(?:(?:(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=|[A-Za-z_$][A-Za-z0-9_$]*\s*:)\s*)?\/(?:\\.|[^/\r\n])+\/[a-z]*\s*[,;]\s*$/.test(line);
      const quoteFree = !/["'`]/.test(line);
      const headerMatch = line.match(/-----BEGIN[^\r\n]*PRIVATE KEY-----/);
      const base64FollowsHeader =
        headerMatch !== null &&
        /^[A-Za-z0-9+/=]{20,}/.test(line.slice(headerMatch.index + headerMatch[0].length));
      // 한계: 정규식 형태로 위장한 키는 이 규칙만으로는 탐지할 수 없을 수 있다.
      const isRegexDefinitionWithoutBase64 =
        isRegexDefinition && quoteFree && !base64FollowsHeader;
      return !isRegexDefinitionWithoutBase64;
    });

    if (findings.length > THRESHOLDS.maxSecretFindings) {
      const locations = findings
        .map((finding) => `${finding.path}:${finding.line}:${finding.type}`)
        .join(", ");
      return {
        name: "시크릿 스캔",
        ok: false,
        detail: `발견=${findings.length}; 제한=${THRESHOLDS.maxSecretFindings}; ${locations}`,
      };
    }

    return {
      name: "시크릿 스캔",
      ok: true,
      detail: `발견=${findings.length}; 제한=${THRESHOLDS.maxSecretFindings}`,
    };
  } catch (error) {
    return { name: "시크릿 스캔", ok: false, detail: `예외 또는 파일 없음: ${error.message}` };
  }
}
// ---- 검사 2: 의존성 (package.json 의 dependencies 를 scanner/deps.js 로 검사)
function checkDeps() {
  if (!Number.isInteger(THRESHOLDS.maxRiskyDeps) || THRESHOLDS.maxRiskyDeps < 0) {
    return { name: "의존성 검사", ok: false, detail: "임계값이 유효한 음이 아닌 정수가 아니다" };
  }

  try {
    const pkg = require(rel(FILES.manifest));
    if (pkg === null || typeof pkg !== "object" || Array.isArray(pkg)) {
      throw new Error("package.json이 객체가 아니다");
    }
    const pkgInput = { ...pkg };
    if (!Object.prototype.hasOwnProperty.call(pkg, "dependencies")) {
      pkgInput.dependencies = {};
    } else if (
      typeof pkg.dependencies !== "object" ||
      pkg.dependencies === null ||
      Array.isArray(pkg.dependencies)
    ) {
      throw new Error("dependencies 키가 객체가 아니다");
    }
    const lock = {};
    const registry = require(path.resolve(root, "sim/registry.json"));
    const cfg = require(path.resolve(root, "config/sec.json"));
    const depsModule = load(FILES.deps);
    const checkDependencies = depsModule.checkDependencies;
    if (typeof checkDependencies !== "function") {
      throw new Error("checkDependencies 함수를 찾을 수 없다");
    }

    const findings = checkDependencies(pkgInput, lock, registry, cfg);
    if (findings.length > THRESHOLDS.maxRiskyDeps) {
      const details = findings
        .map((finding) => `${finding.name}:${finding.codes.join("/")}`)
        .join(", ");
      return {
        name: "의존성 검사",
        ok: false,
        detail: `위험 패키지=${findings.length}; 제한=${THRESHOLDS.maxRiskyDeps}; ${details}`,
      };
    }

    return {
      name: "의존성 검사",
      ok: true,
      detail: `위험 패키지=${findings.length}; 제한=${THRESHOLDS.maxRiskyDeps}`,
    };
  } catch (error) {
    return { name: "의존성 검사", ok: false, detail: `예외 또는 파일 없음: ${error.message}` };
  }
}
// ---- 검사 3: 공격 회귀 (redteam/attacks.json 을 우리 방어로 돌려 피해가 없는지)
function checkRegression() {
  if (!Number.isInteger(THRESHOLDS.maxRegressionHarms) || THRESHOLDS.maxRegressionHarms < 0) {
    return { name: "공격 회귀", ok: false, detail: "임계값이 유효한 음이 아닌 정수가 아니다" };
  }

  try {
    const attacks = require(rel(FILES.attacks));
    if (!Array.isArray(attacks)) {
      throw new Error("공격 목록이 배열이 아니다");
    }

    const guard = load(FILES.guard);
    const promptModule = load(FILES.prompt);
    const buildSystemPrompt = promptModule.buildSystemPrompt;
    if (typeof buildSystemPrompt !== "function") {
      throw new Error("buildSystemPrompt 함수를 찾을 수 없다");
    }

    const { run } = require(path.resolve(root, "sim/runner"));
    let harmCount = 0;

    for (const attack of attacks) {
      const isDocument = attack.channel === "document";
      const scenario = {
        user: attack.user || "u1",
        text: isDocument
          ? (attack.userRequest || "이 내용을 요약해줘")
          : attack.payload,
        kind: "attack",
        docs: isDocument
          ? [{ source: "external", text: attack.payload }]
          : [],
        confirmed: [],
      };
      const result = run(scenario, { guard, buildSystemPrompt });

      if (result.error) {
        throw new Error(`공격 실행 예외: ${result.error}`);
      }
      if (!Array.isArray(result.harms)) {
        throw new Error("result.harms가 배열이 아니다");
      }
      if (result.harms.length > 0) {
        harmCount += 1;
      }
    }

    if (harmCount > THRESHOLDS.maxRegressionHarms) {
      return {
        name: "공격 회귀",
        ok: false,
        detail: `피해 발생 공격=${harmCount}; 제한=${THRESHOLDS.maxRegressionHarms}`,
      };
    }

    return {
      name: "공격 회귀",
      ok: true,
      detail: `피해 발생 공격=${harmCount}; 제한=${THRESHOLDS.maxRegressionHarms}`,
    };
  } catch (error) {
    return { name: "공격 회귀", ok: false, detail: `예외 또는 파일 없음: ${error.message}` };
  }
}

const results = [checkSecrets(), checkDeps(), checkRegression()];
console.log(`보안 CI 게이트${DIR ? ` (--dir ${DIR})` : ""}`);
for (const r of results) console.log(`  ${r.ok ? "✔" : "✘"} ${r.name} — ${r.detail}`);
const ok = results.every((r) => r.ok);
console.log(ok ? "\n결과: 통과" : "\n결과: 실패 — 병합 · 배포를 막습니다");
process.exit(ok ? 0 : 1);
