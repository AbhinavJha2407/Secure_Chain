/**
 * Real GitHub OAuth (web application flow).
 * Requires a GitHub OAuth App: https://github.com/settings/developers
 *   Authorization callback URL must match GITHUB_CALLBACK_URL in .env
 */

const axios = require('axios');
const jwt = require('jsonwebtoken');

function buildAuthorizeUrl() {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: process.env.GITHUB_CALLBACK_URL,
    scope: 'read:user user:email repo', // 'repo' needed to read private repo manifests for SBOM scanning
    state: jwt.sign({ ts: Date.now() }, process.env.JWT_SECRET, { expiresIn: '10m' }),
  });
  return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

async function exchangeCodeForToken(code) {
  const { data } = await axios.post(
    'https://github.com/login/oauth/access_token',
    {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: process.env.GITHUB_CALLBACK_URL,
    },
    { headers: { Accept: 'application/json' }, timeout: 10000 }
  );
  if (data.error) throw new Error(data.error_description || data.error);
  return data.access_token;
}

async function fetchGitHubUser(accessToken) {
  const { data } = await axios.get('https://api.github.com/user', {
    headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'SecureChain' },
    timeout: 10000,
  });
  return data;
}

async function listUserRepos(accessToken, page = 1) {
  const { data } = await axios.get('https://api.github.com/user/repos', {
    headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'SecureChain' },
    params: { per_page: 50, page, sort: 'updated' },
    timeout: 10000,
  });
  return data;
}

/**
 * Fetches a manifest file (e.g. package.json) from a repo's default branch
 * via the GitHub Contents API and decodes it.
 */
async function fetchManifest(accessToken, owner, repo, manifestPath = 'package.json') {
  const { data } = await axios.get(
    `https://api.github.com/repos/${owner}/${repo}/contents/${manifestPath}`,
    { headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'SecureChain' }, timeout: 10000 }
  );
  const content = Buffer.from(data.content, data.encoding).toString('utf-8');
  return JSON.parse(content);
}

function issueSessionToken(user) {
  const role = (user.role || 'admin').toLowerCase();
  return jwt.sign(
    { sub: String(user.githubId || user.id), login: user.login, avatar: user.avatar || user.avatar_url, role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

module.exports = { buildAuthorizeUrl, exchangeCodeForToken, fetchGitHubUser, listUserRepos, fetchManifest, issueSessionToken };
