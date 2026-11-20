// Mission 2-C — 의존성 위험 검사 (docs/SEC_CONTRACT.md §2.3)
//   checkDependencies(pkg, lock, registry, cfg) → [{ name, codes: [...] }]  (위험이 있는 패키지만, 이름순)
//   codes: NOT_FOUND | TYPOSQUAT | LOW_TRUST | VULNERABLE | INSTALL_SCRIPT | DEPRECATED | UNPINNED
//   registry = sim/registry.json 형식, cfg = config/sec.json
const INSTALL_SCRIPT_NAMES = ['preinstall', 'install', 'postinstall'];

function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function isExactVersion(value) {
  return typeof value === 'string' && /^\d+\.\d+\.\d+$/.test(value);
}

function parseVersion(value) {
  if (!isExactVersion(value)) {
    return null;
  }

  return value.split('.').map(Number);
}

function compareVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] < right[index]) {
      return -1;
    }
    if (left[index] > right[index]) {
      return 1;
    }
  }

  return 0;
}

function editDistance(left, right) {
  const a = left.toLowerCase();
  const b = right.toLowerCase();
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);

  for (let row = 1; row <= a.length; row += 1) {
    const current = [row];

    for (let column = 1; column <= b.length; column += 1) {
      const substitutionCost = a[row - 1] === b[column - 1] ? 0 : 1;

      current[column] = Math.min(
        current[column - 1] + 1,
        previous[column] + 1,
        previous[column - 1] + substitutionCost
      );
    }

    previous = current;
  }

  return previous[b.length];
}

function getInstalledVersion(name, spec, lock) {
  if (
    hasOwn(lock, name) &&
    lock[name] &&
    typeof lock[name].version === 'string'
  ) {
    return lock[name].version;
  }

  return isExactVersion(spec) ? spec : null;
}

function isUnpinned(spec, hasLockEntry) {
  if (typeof spec !== 'string') {
    return false;
  }

  const value = spec.trim();
  const lowerValue = value.toLowerCase();

  return (
    value === '' ||
    lowerValue === '*' ||
    lowerValue === 'latest' ||
    lowerValue === 'x' ||
    /^git/i.test(value) ||
    /^http/i.test(value) ||
    /^file:/i.test(value) ||
    (!hasLockEntry && /[\^~><]/.test(value))
  );
}

function checkDependencies(pkg, lock, registry, cfg) {
  const packages = registry.packages;
  const dependencies = pkg.dependencies;
  const results = [];

  for (const [name, spec] of Object.entries(dependencies)) {
    const codes = [];
    const isRegistered = hasOwn(packages, name);
    const packageInfo = isRegistered ? packages[name] : null;
    const hasLockEntry = hasOwn(lock, name);
    const installedVersion = getInstalledVersion(name, spec, lock);

    if (!isRegistered) {
      codes.push('NOT_FOUND');
    } else {
      const downloads = packageInfo.weeklyDownloads;

      if (typeof downloads === 'number' && downloads < 5000) {
        const isTypoSquat = Object.entries(packages).some(
          ([otherName, otherInfo]) =>
            otherName !== name &&
            typeof otherInfo.weeklyDownloads === 'number' &&
            otherInfo.weeklyDownloads >= 1000000 &&
            editDistance(name, otherName) <= 2
        );

        if (isTypoSquat) {
          codes.push('TYPOSQUAT');
        }
      }

      if (
        typeof packageInfo.ageDays === 'number' &&
        packageInfo.ageDays < 30 &&
        typeof downloads === 'number' &&
        downloads < 1000
      ) {
        codes.push('LOW_TRUST');
      }

      const installedParts = parseVersion(installedVersion);
      const advisories = packageInfo.advisories || [];
      const isVulnerable =
        installedParts !== null &&
        advisories.some((advisory) => {
          const severity =
            typeof advisory.severity === 'string'
              ? advisory.severity.toLowerCase()
              : '';
          const belowParts = parseVersion(advisory.below);

          return (
            (severity === 'high' || severity === 'critical') &&
            belowParts !== null &&
            compareVersions(installedParts, belowParts) < 0
          );
        });

      if (isVulnerable) {
        codes.push('VULNERABLE');
      }

      const versions = packageInfo.versions || {};
      const versionInfo =
        installedVersion !== null && hasOwn(versions, installedVersion)
          ? versions[installedVersion]
          : null;
      const scripts = versionInfo && versionInfo.scripts;
      const hasInstallScript =
        scripts &&
        INSTALL_SCRIPT_NAMES.some((scriptName) => hasOwn(scripts, scriptName));
      const allowedScripts = cfg.allowInstallScripts || [];

      if (
        hasInstallScript &&
        !allowedScripts.includes(name)
      ) {
        codes.push('INSTALL_SCRIPT');
      }

      if (packageInfo.deprecated === true) {
        codes.push('DEPRECATED');
      }
    }

    if (isUnpinned(spec, hasLockEntry)) {
      codes.push('UNPINNED');
    }

    if (codes.length > 0) {
      results.push({ name, codes: codes.sort() });
    }
  }

  return results.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0
  );
}

module.exports = { checkDependencies };
