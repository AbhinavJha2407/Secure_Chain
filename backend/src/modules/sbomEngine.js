/**
 * SBOM Engine
 * Resolves the full transitive dependency graph for a Node.js project from
 * package.json by querying the real npm registry, then serializes the
 * result as CycloneDX 1.5 JSON and SPDX 2.3.
 *
 * This hits https://registry.npmjs.org for real — no mocking.
 */

const axios = require('axios');
const crypto = require('crypto');

const NPM_REGISTRY = 'https://registry.npmjs.org';
const registryCache = new Map(); // name -> metadata (per-process cache)

async function fetchPackageMetadata(name) {
  if (registryCache.has(name)) return registryCache.get(name);
  try {
    const { data } = await axios.get(`${NPM_REGISTRY}/${encodeURIComponent(name)}`, {
      timeout: 8000,
    });
    registryCache.set(name, data);
    return data;
  } catch (err) {
    registryCache.set(name, null);
    return null;
  }
}

function resolveVersion(meta) {
  if (!meta) return null;
  const latest = meta['dist-tags'] && meta['dist-tags'].latest;
  if (latest && meta.versions && meta.versions[latest]) return latest;
  const versions = meta.versions ? Object.keys(meta.versions) : [];
  return versions.length ? versions[versions.length - 1] : null;
}

/**
 * Regex fallback extractor to extract "package": "version" pairs from corrupt or malformed JSON text.
 */
function extractDependenciesFromCorruptJson(rawContent) {
  if (typeof rawContent !== 'string') return {};
  const deps = {};
  const regex = /["'](@?[a-zA-Z0-9_.\-]+(?:\/[a-zA-Z0-9_.\-]+)?)["']\s*:\s*["']([^"'\r\n]+)["']/g;
  const ignoreKeys = new Set([
    'name', 'version', 'description', 'main', 'scripts', 'author', 'license',
    'repository', 'bugs', 'homepage', 'type', 'private', 'keywords', 'module'
  ]);
  let match;
  while ((match = regex.exec(rawContent)) !== null) {
    const pkg = match[1].trim();
    const ver = match[2].trim();
    if (!ignoreKeys.has(pkg)) {
      deps[pkg] = ver;
    }
  }
  return deps;
}

function cleanSemanticVersion(ver) {
  if (!ver || typeof ver !== 'string') return '0.0.0';
  const trimmed = ver.trim();
  const match = trimmed.match(/^[\^~v=><\s]*([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9.]+)?)/);
  if (match) return match[1];
  return trimmed.replace(/[^0-9a-zA-Z.\-+]/g, '') || '0.0.0';
}

/**
 * Recursively walks dependencies starting from a manifest's
 * `dependencies` + `devDependencies` + `peerDependencies` + `optionalDependencies` map,
 * querying the npm registry for each package and its own declared dependencies.
 */
async function resolveDependencyTree(rootDeps, opts = {}) {
  const maxDepth = opts.maxDepth ?? 4;
  const components = new Map(); // key: name@version -> component record
  const edges = [];
  const safeRootDeps = {};

  // Validate dependency entries
  if (rootDeps && typeof rootDeps === 'object') {
    for (const [rawKey, rawVal] of Object.entries(rootDeps)) {
      let isCorrupt = false;
      const name = typeof rawKey === 'string' ? rawKey.trim() : String(rawKey || '');
      if (!name || typeof rawKey !== 'string') {
        isCorrupt = true;
      }

      let rawVer = rawVal;
      const rawStr = String(rawVal != null ? rawVal : '');
      const strippedVersion = rawStr.replace(/[^0-9a-zA-Z.\-+]/g, '').trim() || '0.0.0';
      const cleanVer = cleanSemanticVersion(rawStr);

      if (
        typeof rawVal !== 'string' ||
        /[;{}()$"'\r\n\t]|\b(drop|table|select|insert|delete|curl|bash)\b/i.test(rawStr)
      ) {
        isCorrupt = true;
        rawVer = rawVal != null ? (typeof rawVal === 'string' ? rawVal : JSON.stringify(rawVal)) : '';
      }

      if (isCorrupt) {
        const corruptKey = `${name || 'corrupt-entry'}@${strippedVersion}`;
        components.set(corruptKey, {
          name: name || 'corrupt-entry',
          version: strippedVersion,
          rawVersion: String(rawVal),
          corruptEntry: true,
          resolved: false,
          purl: `pkg:npm/${name || 'corrupt-entry'}@${strippedVersion}`,
          licence: 'UNKNOWN',
          maintainers: [],
          description: `Malformed manifest dependency entry (${rawKey}: ${rawVer})`,
        });
      }

      if (name) {
        safeRootDeps[name] = cleanVer;
      }
    }
  }

  async function walk(name, depth, parent, targetVersion = null) {
    if (depth > maxDepth) return;
    const meta = await fetchPackageMetadata(name);
    let version = targetVersion && targetVersion !== '*' && targetVersion !== 'latest' ? targetVersion : null;
    if (!version && meta) {
      version = resolveVersion(meta);
    }
    if (!version) {
      version = targetVersion || 'unresolved';
    }

    const key = `${name}@${version}`;
    const existing = components.get(key);
    if (existing && !existing.corruptEntry) {
      if (parent) edges.push({ from: parent, to: key });
      return;
    }

    if (!meta && version === 'unresolved') {
      components.set(key, {
        name,
        version: 'unresolved',
        resolved: false,
        purl: `pkg:npm/${name}`,
        licence: null,
        maintainers: [],
        publishDate: null,
        description: null,
      });
      return;
    }

    const versionData = (meta?.versions && meta.versions[version]) || {};
    components.set(key, {
      name,
      version,
      resolved: version !== 'unresolved',
      corruptEntry: existing?.corruptEntry || false,
      purl: `pkg:npm/${name}@${version}`,
      licence: versionData.license || meta?.license || 'UNKNOWN',
      maintainers: (meta?.maintainers || []).map((m) => m.name),
      publishDate: (meta?.time && meta.time[version]) || null,
      description: meta?.description || versionData.description || '',
      hasInstallScripts: !!(versionData.scripts && (versionData.scripts.postinstall || versionData.scripts.preinstall)),
    });
    if (parent) edges.push({ from: parent, to: key });

    const childDeps = {
      ...(versionData.dependencies || {}),
      ...(versionData.peerDependencies || {}),
      ...(versionData.optionalDependencies || {}),
    };
    const childEntries = Object.entries(childDeps);
    // Bound fan-out so a single scan doesn't explode into thousands of calls
    await Promise.all(
      childEntries.slice(0, 25).map(([childName, childVerSpec]) =>
        walk(childName, depth + 1, key, cleanSemanticVersion(childVerSpec))
      )
    );
  }

  const rootNames = Object.keys(safeRootDeps);
  await Promise.all(rootNames.map((name) => walk(name, 0, null, safeRootDeps[name])));

  return { components: Array.from(components.values()), edges };
}

function toCycloneDX(projectName, projectVersion, { components }) {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: { type: 'application', name: projectName, version: projectVersion || '0.0.0' },
    },
    components: components
      .filter((c) => c.resolved)
      .map((c) => ({
        type: 'library',
        name: c.name,
        version: c.version,
        purl: c.purl,
        licenses: c.licence ? [{ license: { id: c.licence } }] : [],
        description: c.description,
        properties: [
          { name: 'securechain:hasInstallScripts', value: String(!!c.hasInstallScripts) },
          { name: 'securechain:publishDate', value: c.publishDate || 'unknown' },
        ],
      })),
  };
}

function toSPDX(projectName, projectVersion, { components }) {
  const created = new Date().toISOString();
  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${projectName}-sbom`,
    documentNamespace: `https://securechain.local/spdx/${projectName}-${Date.now()}`,
    creationInfo: { created, creators: ['Tool: SecureChain-SBOM-Engine-1.0'] },
    packages: [
      {
        SPDXID: 'SPDXRef-Package-root',
        name: projectName,
        versionInfo: projectVersion || '0.0.0',
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
      },
      ...components
        .filter((c) => c.resolved)
        .map((c, i) => ({
          SPDXID: `SPDXRef-Package-${i}`,
          name: c.name,
          versionInfo: c.version,
          downloadLocation: `https://registry.npmjs.org/${c.name}/-/${c.name}-${c.version}.tgz`,
          licenseDeclared: c.licence || 'NOASSERTION',
          filesAnalyzed: false,
          externalRefs: [{ referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: c.purl }],
        })),
    ],
  };
}

/** Diff two SBOMs (by component list) to find added/removed/changed packages. */
function diffSBOMs(previousComponents = [], currentComponents = []) {
  const prevMap = new Map(previousComponents.map((c) => [c.name, c]));
  const currMap = new Map(currentComponents.map((c) => [c.name, c]));

  const added = [];
  const removed = [];
  const changed = [];

  for (const [name, comp] of currMap) {
    if (!prevMap.has(name)) {
      added.push(comp);
    } else if (prevMap.get(name).version !== comp.version) {
      changed.push({ name, from: prevMap.get(name).version, to: comp.version });
    }
  }
  for (const [name, comp] of prevMap) {
    if (!currMap.has(name)) removed.push(comp);
  }

  return { added, removed, changed };
}

/**
 * Generate full SBOM from manifest content (string or object)
 */
async function generateSBOM(manifestContent, projectName = 'app', opts = {}) {
  let parsedManifest = null;
  let manifestCorrupted = false;
  let parseError = null;

  try {
    parsedManifest = typeof manifestContent === 'string' ? JSON.parse(manifestContent) : manifestContent;
  } catch (err) {
    manifestCorrupted = true;
    parseError = err.message;
  }

  let rootDeps = {};
  if (!manifestCorrupted && parsedManifest && typeof parsedManifest === 'object') {
    const deps = typeof parsedManifest.dependencies === 'object' && parsedManifest.dependencies !== null ? parsedManifest.dependencies : {};
    const devDeps = typeof parsedManifest.devDependencies === 'object' && parsedManifest.devDependencies !== null ? parsedManifest.devDependencies : {};
    const peerDeps = typeof parsedManifest.peerDependencies === 'object' && parsedManifest.peerDependencies !== null ? parsedManifest.peerDependencies : {};
    const optDeps = typeof parsedManifest.optionalDependencies === 'object' && parsedManifest.optionalDependencies !== null ? parsedManifest.optionalDependencies : {};
    rootDeps = { ...deps, ...devDeps, ...peerDeps, ...optDeps };
  }

  if (manifestCorrupted || Object.keys(rootDeps).length === 0) {
    const rawText = typeof manifestContent === 'string' ? manifestContent : JSON.stringify(manifestContent);
    const fallbackDeps = extractDependenciesFromCorruptJson(rawText);
    if (Object.keys(fallbackDeps).length > 0) {
      rootDeps = { ...rootDeps, ...fallbackDeps };
      manifestCorrupted = true;
      if (!parseError) parseError = 'Manifest dependency structure invalid or unparseable';
    }
  }

  const tree = await resolveDependencyTree(rootDeps, opts);
  const cycloneDX = toCycloneDX(parsedManifest?.name || projectName, parsedManifest?.version, tree);
  const spdx = toSPDX(parsedManifest?.name || projectName, parsedManifest?.version, tree);

  return {
    manifest: parsedManifest,
    manifestCorrupted,
    parseError,
    tree,
    components: tree.components,
    cycloneDX,
    spdx,
  };
}

module.exports = {
  fetchPackageMetadata,
  cleanSemanticVersion,
  resolveDependencyTree,
  extractDependenciesFromCorruptJson,
  generateSBOM,
  toCycloneDX,
  toSPDX,
  diffSBOMs,
};
