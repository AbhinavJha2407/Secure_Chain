/**
 * Multi-Ecosystem SBOM Resolvers
 * Extends sbomEngine.js with real registry queries for:
 *   - PyPI       (pip / requirements.txt / pyproject.toml)
 *   - Maven      (pom.xml → Maven Central search API)
 *   - Go modules (go.mod → proxy.golang.org)
 *   - NuGet      (.csproj / packages.config → api.nuget.org)
 *
 * Each resolver returns the same component shape as sbomEngine.js so the
 * Vulnerability Correlation Engine and Malicious Package Analyzer work
 * identically across ecosystems.
 */

'use strict';

const axios = require('axios');
const xml2js = require('xml2js');

const DEFAULT_TIMEOUT = 8000;

// ── PyPI ──────────────────────────────────────────────────────────────────────

/**
 * Parses requirements.txt or pyproject.toml [tool.poetry.dependencies] lines.
 * Returns { packageName: versionSpec } map.
 */
function parseRequirementsTxt(content) {
  const deps = {};
  for (const raw of content.split('\n')) {
    const line = raw.split('#')[0].trim(); // strip comments
    if (!line || line.startsWith('-')) continue;
    // Handle: requests>=2.28.0, flask==2.3.0, numpy, boto3~=1.26
    const match = line.match(/^([A-Za-z0-9_.\-]+)\s*([><=!~^,\s0-9.*]+)?$/);
    if (match) deps[match[1].toLowerCase()] = (match[2] || '*').trim();
  }
  return deps;
}

async function fetchPyPIMetadata(name) {
  try {
    const { data } = await axios.get(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { timeout: DEFAULT_TIMEOUT });
    return data;
  } catch { return null; }
}

async function resolvePyPIDependencies(deps, opts = {}) {
  const maxDepth = opts.maxDepth ?? 2;
  const components = new Map();

  async function walk(name, depth) {
    if (depth > maxDepth || components.has(name)) return;
    const meta = await fetchPyPIMetadata(name);
    if (!meta) {
      components.set(name, { name, version: 'unresolved', resolved: false, purl: `pkg:pypi/${name}`, ecosystem: 'PyPI' });
      return;
    }
    const version = meta.info.version;
    const releaseInfo = meta.releases?.[version]?.[0] || {};
    components.set(name, {
      name,
      version,
      resolved: true,
      purl: `pkg:pypi/${name}@${version}`,
      licence: meta.info.license || 'UNKNOWN',
      maintainers: meta.info.author ? [meta.info.author] : [],
      publishDate: releaseInfo.upload_time || null,
      description: meta.info.summary || '',
      hasInstallScripts: false, // PyPI doesn't expose this in the JSON API
      ecosystem: 'PyPI',
      homepage: meta.info.home_page || meta.info.project_url,
    });

    const requires = meta.info.requires_dist || [];
    const childNames = requires
      .filter(r => !r.includes(';')) // skip environment markers
      .map(r => r.split(/[\s><=!~\[]/)[0].toLowerCase().trim())
      .filter(Boolean);
    await Promise.all(childNames.slice(0, 20).map(n => walk(n, depth + 1)));
  }

  await Promise.all(Object.keys(deps).map(n => walk(n.toLowerCase(), 0)));
  return { components: Array.from(components.values()), edges: [] };
}

// ── Maven ─────────────────────────────────────────────────────────────────────

async function parsePomXml(content) {
  const parsed = await xml2js.parseStringPromise(content, { explicitArray: false });
  const project = parsed.project || {};
  const deps = {};

  const rawDeps = project.dependencies?.dependency;
  if (!rawDeps) return deps;
  const depList = Array.isArray(rawDeps) ? rawDeps : [rawDeps];

  for (const dep of depList) {
    if (!dep.groupId || !dep.artifactId) continue;
    const scope = dep.scope || 'compile';
    if (['test', 'provided'].includes(scope)) continue; // skip test/provided
    const key = `${dep.groupId}:${dep.artifactId}`;
    deps[key] = dep.version || '*';
  }
  return deps;
}

async function fetchMavenMetadata(groupId, artifactId, version) {
  try {
    // Maven Central search API — free, no key required
    const searchUrl = version && version !== '*'
      ? `https://search.maven.org/solrsearch/select?q=g:"${groupId}"+AND+a:"${artifactId}"+AND+v:"${version}"&rows=1&wt=json`
      : `https://search.maven.org/solrsearch/select?q=g:"${groupId}"+AND+a:"${artifactId}"&rows=1&wt=json`;
    const { data } = await axios.get(searchUrl, { timeout: DEFAULT_TIMEOUT });
    const doc = data?.response?.docs?.[0];
    return doc || null;
  } catch { return null; }
}

async function resolveMavenDependencies(pomContent, opts = {}) {
  const deps = await parsePomXml(pomContent);
  const components = new Map();

  await Promise.all(
    Object.entries(deps).map(async ([key, version]) => {
      const [groupId, artifactId] = key.split(':');
      const meta = await fetchMavenMetadata(groupId, artifactId, version);
      const resolvedVersion = meta?.latestVersion || meta?.v || version;
      components.set(key, {
        name: artifactId,
        groupId,
        version: resolvedVersion === '*' ? 'unresolved' : resolvedVersion,
        resolved: resolvedVersion !== '*' && resolvedVersion !== 'unresolved',
        purl: `pkg:maven/${groupId}/${artifactId}@${resolvedVersion}`,
        licence: meta?.ec?.includes('.pom') ? 'SEE POM' : 'UNKNOWN',
        maintainers: [],
        publishDate: meta?.timestamp ? new Date(meta.timestamp).toISOString() : null,
        description: meta?.id || key,
        hasInstallScripts: false,
        ecosystem: 'Maven',
      });
    })
  );

  return { components: Array.from(components.values()), edges: [] };
}

// ── Go modules ────────────────────────────────────────────────────────────────

function parseGoMod(content) {
  const deps = {};
  let inRequire = false;
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (trimmed === 'require (') { inRequire = true; continue; }
    if (inRequire && trimmed === ')') { inRequire = false; continue; }
    const singleRequire = trimmed.match(/^require\s+(\S+)\s+(v[\d.]+\S*)/);
    if (singleRequire) { deps[singleRequire[1]] = singleRequire[2]; continue; }
    if (inRequire) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 2 && parts[1].startsWith('v')) deps[parts[0]] = parts[1];
    }
  }
  return deps;
}

async function fetchGoModuleInfo(modulePath, version) {
  try {
    // Go module proxy — public, no key required
    const { data } = await axios.get(
      `https://proxy.golang.org/${encodeURIComponent(modulePath)}/@v/${version}.info`,
      { timeout: DEFAULT_TIMEOUT }
    );
    return data;
  } catch { return null; }
}

async function resolveGoDependencies(goModContent, opts = {}) {
  const deps = parseGoMod(goModContent);
  const components = new Map();

  await Promise.all(
    Object.entries(deps).map(async ([modulePath, version]) => {
      const info = await fetchGoModuleInfo(modulePath, version);
      const name = modulePath.split('/').pop();
      components.set(modulePath, {
        name,
        modulePath,
        version,
        resolved: info != null,
        purl: `pkg:golang/${modulePath}@${version}`,
        licence: 'UNKNOWN', // Go proxy doesn't expose license in the info endpoint
        maintainers: [],
        publishDate: info?.Time || null,
        description: modulePath,
        hasInstallScripts: false,
        ecosystem: 'Go',
      });
    })
  );

  return { components: Array.from(components.values()), edges: [] };
}

// ── NuGet ─────────────────────────────────────────────────────────────────────

function parsePackagesConfig(content) {
  // <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net462" />
  const deps = {};
  const matches = content.matchAll(/<package\s+id="([^"]+)"\s+version="([^"]+)"/gi);
  for (const m of matches) deps[m[1]] = m[2];
  return deps;
}

function parseCsproj(content) {
  // <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  const deps = {};
  const matches = content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/gi);
  for (const m of matches) deps[m[1]] = m[2];
  return deps;
}

async function fetchNuGetMetadata(packageId, version) {
  try {
    const url = version && version !== '*'
      ? `https://api.nuget.org/v3/registration5-gz-semver2/${packageId.toLowerCase()}/${version}.json`
      : `https://api.nuget.org/v3/registration5-gz-semver2/${packageId.toLowerCase()}/index.json`;
    const { data } = await axios.get(url, { timeout: DEFAULT_TIMEOUT });
    return data;
  } catch { return null; }
}

async function resolveNuGetDependencies(manifestContent, manifestType = 'packages.config', opts = {}) {
  const deps = manifestType === 'csproj'
    ? parseCsproj(manifestContent)
    : parsePackagesConfig(manifestContent);

  const components = new Map();

  await Promise.all(
    Object.entries(deps).map(async ([packageId, version]) => {
      const meta = await fetchNuGetMetadata(packageId, version);
      const catalogEntry = meta?.catalogEntry || meta?.items?.[0]?.items?.slice(-1)[0]?.catalogEntry;
      components.set(packageId, {
        name: packageId,
        version,
        resolved: meta != null,
        purl: `pkg:nuget/${packageId}@${version}`,
        licence: catalogEntry?.licenseExpression || 'UNKNOWN',
        maintainers: catalogEntry?.authors ? [catalogEntry.authors] : [],
        publishDate: catalogEntry?.published || null,
        description: catalogEntry?.description || packageId,
        hasInstallScripts: false,
        ecosystem: 'NuGet',
      });
    })
  );

  return { components: Array.from(components.values()), edges: [] };
}

// ── Unified resolver — detects ecosystem from manifest filename / content ─────

/**
 * Auto-detect ecosystem and resolve dependencies from a raw manifest string.
 * filename:   'package.json' | 'requirements.txt' | 'pom.xml' | 'go.mod' |
 *             'packages.config' | '*.csproj'
 */
async function resolveFromManifest(filename, content, opts = {}) {
  const name = filename.toLowerCase();

  if (name === 'package.json') {
    const { resolveDependencyTree, extractDependenciesFromCorruptJson } = require('./sbomEngine');
    let manifest = null;
    let manifestCorrupted = false;
    let parseError = null;

    try {
      manifest = typeof content === 'string' ? JSON.parse(content) : content;
    } catch (err) {
      manifestCorrupted = true;
      parseError = err.message;
    }

    let rootDeps = {};
    if (!manifestCorrupted && manifest && typeof manifest === 'object') {
      const deps = typeof manifest.dependencies === 'object' && manifest.dependencies !== null ? manifest.dependencies : {};
      const devDeps = typeof manifest.devDependencies === 'object' && manifest.devDependencies !== null ? manifest.devDependencies : {};
      const peerDeps = typeof manifest.peerDependencies === 'object' && manifest.peerDependencies !== null ? manifest.peerDependencies : {};
      const optDeps = typeof manifest.optionalDependencies === 'object' && manifest.optionalDependencies !== null ? manifest.optionalDependencies : {};
      rootDeps = { ...deps, ...devDeps, ...peerDeps, ...optDeps };
    }

    if (manifestCorrupted || Object.keys(rootDeps).length === 0) {
      const fallback = extractDependenciesFromCorruptJson(typeof content === 'string' ? content : JSON.stringify(content));
      if (Object.keys(fallback).length > 0) {
        rootDeps = { ...rootDeps, ...fallback };
        manifestCorrupted = true;
        if (!parseError) parseError = 'Invalid or unparseable dependency structure in manifest';
      }
    }

    const tree = await resolveDependencyTree(rootDeps, opts);
    return {
      ecosystem: 'npm',
      manifest,
      manifestCorrupted,
      parseError,
      ...tree,
    };
  }

  if (name === 'requirements.txt' || name === 'requirements.in') {
    const deps = parseRequirementsTxt(content);
    return { ecosystem: 'PyPI', ...(await resolvePyPIDependencies(deps, opts)) };
  }

  if (name === 'pom.xml') {
    return { ecosystem: 'Maven', ...(await resolveMavenDependencies(content, opts)) };
  }

  if (name === 'go.mod') {
    return { ecosystem: 'Go', ...(await resolveGoDependencies(content, opts)) };
  }

  if (name === 'packages.config') {
    return { ecosystem: 'NuGet', ...(await resolveNuGetDependencies(content, 'packages.config', opts)) };
  }

  if (name.endsWith('.csproj')) {
    return { ecosystem: 'NuGet', ...(await resolveNuGetDependencies(content, 'csproj', opts)) };
  }

  throw new Error(`Unsupported manifest file: ${filename}. Supported: package.json, requirements.txt, pom.xml, go.mod, packages.config, *.csproj`);
}

/** Maps ecosystem name to OSV ecosystem identifier used in vulnerability queries */
function ecosystemToOSV(ecosystem) {
  return { npm: 'npm', PyPI: 'PyPI', Maven: 'Maven', Go: 'Go', NuGet: 'NuGet' }[ecosystem] || ecosystem;
}

module.exports = {
  parseRequirementsTxt,
  resolvePyPIDependencies,
  parsePomXml,
  resolveMavenDependencies,
  parseGoMod,
  resolveGoDependencies,
  parsePackagesConfig,
  parseCsproj,
  resolveNuGetDependencies,
  resolveFromManifest,
  ecosystemToOSV,
};
