// Mission 2-D — SBOM 생성 (CycloneDX 축약형, docs/SEC_CONTRACT.md §2.4)
//   generateSbom(pkg, lock, registry) → { bomFormat, specVersion, version, metadata, components, dependencies }
function hasOwn(object, key) {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function packagePurl(name, version) {
  return `pkg:npm/${name}@${version}`;
}

function generateSbom(pkg, lock, registry) {
  const names = Object.keys(lock).sort();

  const components = names.map((name) => {
    const lockedPackage = lock[name];
    const registryPackage = registry.packages[name];
    const license =
      registryPackage &&
      registryPackage.license !== undefined &&
      registryPackage.license !== null
        ? registryPackage.license
        : 'NOASSERTION';

    const component = {
      type: 'library',
      name,
      version: lockedPackage.version,
      purl: packagePurl(name, lockedPackage.version),
      licenses: [{ license: { id: license } }],
    };

    if (
      hasOwn(lockedPackage, 'integrity') &&
      lockedPackage.integrity !== undefined &&
      lockedPackage.integrity !== null
    ) {
      component.hashes = [
        { alg: 'SHA-512', content: lockedPackage.integrity },
      ];
    }

    return component;
  });

  const dependencies = [];

  for (const name of names) {
    const lockedPackage = lock[name];
    const requires =
      lockedPackage.requires &&
      typeof lockedPackage.requires === 'object'
        ? lockedPackage.requires
        : {};
    const requiredNames = Object.keys(requires);

    if (requiredNames.length === 0) {
      continue;
    }

    const dependsOn = requiredNames
      .filter((requiredName) => hasOwn(lock, requiredName))
      .map((requiredName) =>
        packagePurl(requiredName, lock[requiredName].version)
      )
      .sort();

    dependencies.push({
      ref: packagePurl(name, lockedPackage.version),
      dependsOn,
    });
  }

  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      component: {
        type: 'application',
        name: pkg.name,
        version: pkg.version,
      },
    },
    components,
    dependencies,
  };
}

module.exports = { generateSbom };
