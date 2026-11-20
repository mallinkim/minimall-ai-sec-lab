// Mission 2-B — 시크릿 탐지기 (docs/SEC_CONTRACT.md §2.2)
//   scanSecrets(files) : files = [{ path, text }] → [{ path, line, type }]  (줄 번호는 1부터, 한 줄에 한 건)
//   type: PRIVATE_KEY | AWS_ACCESS_KEY | API_KEY_LIVE | JWT | DB_URL_CREDENTIALS | HARDCODED_SECRET
//   오탐(자리표시자 · 환경 변수 참조 · 형식 설명)이 많으면 팀이 경보를 무시하게 된다.
const HARDCODED_SECRET_REGEX = new RegExp(
  String.raw`["']?[A-Za-z0-9_$.-]*` +
    String.raw`(?:secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key)` +
    String.raw`[A-Za-z0-9_$.-]*["']?\s*[:=]\s*` +
    String.raw`(["'])([^'"\r\n]{8,})\1`,
  'gi'
);

const SECRET_PATTERNS = [
  {
    type: 'PRIVATE_KEY',
    regex: /-----BEGIN[ \t]+[^\r\n]*?\bPRIVATE KEY-----/gi,
  },
  {
    type: 'AWS_ACCESS_KEY',
    regex: /\bAKIA([A-Z0-9]{16})\b/g,
    valueGroup: 1,
  },
  {
    type: 'API_KEY_LIVE',
    regex: /\bsk[-_]live[-_]([A-Za-z0-9]{12,})\b/gi,
    valueGroup: 1,
  },
  {
    type: 'JWT',
    regex: /\b(eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,})\b/g,
    valueGroup: 1,
  },
  {
    type: 'DB_URL_CREDENTIALS',
    regex: /\b[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s:@]+:([^@\s/]+)@[^/\s]+/g,
    valueGroup: 1,
  },
  {
    type: 'HARDCODED_SECRET',
    regex: HARDCODED_SECRET_REGEX,
    valueGroup: 2,
  },
];

const PLACEHOLDER_PATTERNS = [
  /\[[A-Z][A-Z0-9_]*\]/,
  /<[^<>]+>/,
  /x{4,}/i,
  /\*{4,}/,
  /\.{3,}/,
  /\$\{[^}]*\}/,
  /changeme/i,
  /your-/i,
  /dummy/i,
  /placeholder/i,
  /(?:process\.env|os\.environ|env\.)/i,
];

function isPlaceholder(value) {
  const text = value.trim();

  return (
    PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(text)) ||
    /^([\s\S])\1+$/.test(text)
  );
}

function isExplicitlyNonSecret(value) {
  const text = value.trim();

  return (
    /^sk_test_/i.test(text) ||
    /^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$/.test(text)
  );
}

function hasNonPlaceholderMatch(pattern, line) {
  pattern.regex.lastIndex = 0;
  let match;

  while ((match = pattern.regex.exec(line)) !== null) {
    if (
      pattern.valueGroup === undefined ||
      (!isPlaceholder(match[pattern.valueGroup]) &&
        !isExplicitlyNonSecret(match[pattern.valueGroup]))
    ) {
      return true;
    }
  }

  return false;
}

function scanSecrets(files) {
  const findings = [];

  for (const file of files) {
    const lines = file.text.split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      for (const pattern of SECRET_PATTERNS) {
        if (hasNonPlaceholderMatch(pattern, lines[index])) {
          findings.push({
            path: file.path,
            line: index + 1,
            type: pattern.type,
          });
          break;
        }
      }
    }
  }

  return findings;
}

module.exports = { scanSecrets };
