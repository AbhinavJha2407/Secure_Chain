/**
 * Google OAuth 2.0 (web application flow)
 * Create credentials at https://console.cloud.google.com/apis/credentials
 * Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL to .env
 */

'use strict';

const axios = require('axios');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

function buildAuthorizeUrl() {
  const state = jwt.sign({ ts: Date.now(), provider: 'google' }, process.env.JWT_SECRET, { expiresIn: '10m' });
  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_CALLBACK_URL,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    access_type: 'offline',
    prompt: 'select_account',
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

async function exchangeCodeForTokens(code) {
  const { data } = await axios.post('https://oauth2.googleapis.com/token', new URLSearchParams({
    code,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: process.env.GOOGLE_CALLBACK_URL,
    grant_type: 'authorization_code',
  }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, timeout: 10000 });
  if (data.error) throw new Error(data.error_description || data.error);
  return data; // { access_token, id_token, refresh_token, ... }
}

async function fetchGoogleUser(accessToken) {
  const { data } = await axios.get('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
    timeout: 10000,
  });
  return data; // { id, email, name, picture, verified_email }
}

function issueSessionToken(googleUser) {
  const role = (googleUser.role || 'developer').toLowerCase();
  return jwt.sign(
    { sub: googleUser.googleId || `google:${googleUser.id}`, email: googleUser.email, name: googleUser.name, picture: googleUser.picture || googleUser.avatar, provider: 'google', role },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

module.exports = { buildAuthorizeUrl, exchangeCodeForTokens, fetchGoogleUser, issueSessionToken };
