/**
 * AI Threat Engine
 *
 * Powered by Google Gemini API (with optional Anthropic Claude fallback):
 *   1. explainVulnerability   — plain-English explanation of a CVE
 *   2. classifyThreat         — structured threat classification + MITRE ATT&CK mapping
 *   3. recommendRemediation   — step-by-step fix guidance with code snippets
 *   4. analyseRootCause       — why this component became vulnerable; supply-chain angle
 *   5. predictRisk            — forward-looking risk score with reasoning
 *   6. streamExplainVulnerability — streaming SSE explanation for typing effect
 *   7. chat                   — conversational multi-turn security assistant
 *
 * Configured via GEMINI_API_KEY in backend/.env
 * Get your key at: https://aistudio.google.com/app/apikey
 */

const axios = require('axios');

const GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

function getProvider() {
  if (process.env.GEMINI_API_KEY) return 'gemini';
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
  throw new Error('GEMINI_API_KEY is not set — add it to .env to enable AI features');
}

/**
 * Execute Gemini generateContent request with automatic model fallback.
 */
async function callGeminiWithModel(model, { prompt, systemInstruction, responseMimeType, maxOutputTokens = 1024, temperature = 0.2, contents }) {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) throw new Error('GEMINI_API_KEY is not set in .env');

  const url = `${GEMINI_BASE_URL}/${model}:generateContent?key=${apiKey}`;

  const payload = {
    contents: contents || [
      {
        role: 'user',
        parts: [{ text: prompt }],
      },
    ],
    generationConfig: {
      temperature,
      maxOutputTokens,
      ...(responseMimeType ? { responseMimeType } : {}),
    },
  };

  if (systemInstruction) {
    payload.systemInstruction = {
      parts: [{ text: systemInstruction }],
    };
  }

  const res = await axios.post(url, payload, {
    headers: { 'Content-Type': 'application/json' },
    timeout: 35000,
  });

  const candidate = res.data?.candidates?.[0];
  if (!candidate) {
    throw new Error('No candidate content returned from Gemini API');
  }

  const text = candidate.content?.parts?.map(p => p.text).join('') || '';
  return text;
}

async function callGemini(params) {
  const models = [
    process.env.GEMINI_MODEL || 'gemini-2.5-flash',
    'gemini-flash-latest',
    'gemini-2.5-pro',
    'gemini-2.0-flash',
    'gemini-1.5-flash',
  ].filter((v, i, a) => a.indexOf(v) === i);

  let lastError;
  for (const model of models) {
    try {
      return await callGeminiWithModel(model, params);
    } catch (err) {
      lastError = err;
      const status = err.response?.status;
      // If 404 (model not found), try the next candidate model
      if (status === 404) {
        continue;
      }
      const errMsg = err.response?.data?.error?.message || err.message;
      throw new Error(`Gemini API error: ${errMsg}`);
    }
  }
  throw lastError;
}

/**
 * Anthropic fallback client if only ANTHROPIC_API_KEY is provided
 */
function getAnthropicClient() {
  const Anthropic = require('@anthropic-ai/sdk');
  return new Anthropic();
}

function parseJsonSafe(text) {
  const clean = text
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
  return JSON.parse(clean);
}

// ── 1. Plain-English CVE explanation ────────────────────────────────────────

async function explainVulnerability(finding) {
  const prompt = `You are a senior application security engineer briefing a development team.

Explain this vulnerability clearly and concisely for a developer who understands code but is not a security specialist:

CVE / ID:     ${finding.cveId || finding.id || 'N/A'}
Component:    ${finding.component}@${finding.version}
Summary:      ${finding.summary || 'No summary available'}
CVSS Score:   ${finding.severity ?? 'N/A'}
EPSS Score:   ${finding.epss != null ? `${(finding.epss * 100).toFixed(1)}%` : 'N/A'} (probability of exploitation in next 30 days)
Priority:     ${finding.priorityLabel || 'N/A'}
Fix versions: ${(finding.fixedVersions || []).join(', ') || 'None published yet'}

Provide:
1. What the vulnerability actually does (not just a restatement of the summary)
2. How an attacker would realistically exploit it
3. What the impact would be on a typical web application
4. One sentence on why the EPSS score is meaningful here

Keep the total response under 250 words. Be direct — no filler.`;

  const provider = getProvider();
  if (provider === 'gemini') {
    return await callGemini({ prompt, maxOutputTokens: 600, temperature: 0.2 });
  } else {
    const ai = getAnthropicClient();
    const msg = await ai.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: prompt }],
    });
    return msg.content[0].text;
  }
}

// ── 2. Threat classification ─────────────────────────────────────────────────

async function classifyThreat(finding) {
  const prompt = `You are a threat intelligence analyst. Classify this supply chain security finding and respond ONLY with a valid JSON object — no markdown fences, no extra text.

Finding:
${JSON.stringify(finding, null, 2)}

Return this exact schema:
{
  "threatCategory": "one of: Dependency Confusion | Typosquatting | Known CVE | Backdoor | Malicious Maintainer | Build Tampering | Data Exfiltration | Cryptojacking | Unknown",
  "mitreAttack": ["array of relevant MITRE ATT&CK technique IDs, e.g. T1195.001"],
  "supplyChainStage": "one of: Source | Build | Dependency | Deployment | Runtime",
  "exploitabilityRating": "one of: Critical | High | Medium | Low",
  "confidenceScore": "number 0-100",
  "reasoning": "2-3 sentence justification"
}`;

  const provider = getProvider();
  if (provider === 'gemini') {
    const text = await callGemini({
      prompt,
      responseMimeType: 'application/json',
      maxOutputTokens: 600,
      temperature: 0.1,
    });
    return parseJsonSafe(text);
  } else {
    const ai = getAnthropicClient();
    const msg = await ai.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: prompt }],
    });
    return parseJsonSafe(msg.content[0].text);
  }
}

// ── 3. Remediation recommendation ────────────────────────────────────────────

async function recommendRemediation(finding, sbomContext) {
  const prompt = `You are a DevSecOps engineer. Provide specific, actionable remediation steps for this finding.

Finding:
- CVE/ID: ${finding.cveId || finding.id || 'N/A'}
- Component: ${finding.component}@${finding.version}
- Summary: ${finding.summary || 'N/A'}
- Fix version(s): ${(finding.fixedVersions || []).join(', ') || 'None published'}
- Priority: ${finding.priorityLabel}

${sbomContext ? `Project context: ${sbomContext.totalComponents} total dependencies, ecosystem: npm` : ''}

Respond with:
## Immediate fix
[Exact command(s) to run to update the dependency]

## Verify the fix
[How to confirm the vulnerable version is gone]

## If no fix is available
[Specific mitigations — feature flags, WAF rules, environment isolation, etc.]

## Prevent recurrence
[One concrete process change — a CI gate rule, a dependency policy, etc.]

Be specific: include real package manager commands, not placeholders. Keep each section under 60 words.`;

  const provider = getProvider();
  if (provider === 'gemini') {
    return await callGemini({ prompt, maxOutputTokens: 800, temperature: 0.2 });
  } else {
    const ai = getAnthropicClient();
    const msg = await ai.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 768,
      messages: [{ role: 'user', content: prompt }],
    });
    return msg.content[0].text;
  }
}

// ── 4. Root cause analysis ────────────────────────────────────────────────────

async function analyseRootCause(finding, dependencyChain) {
  const prompt = `You are a software supply chain security researcher.

A vulnerability was found in a project's dependency graph:

Vulnerable component: ${finding.component}@${finding.version}
CVE: ${finding.cveId || 'N/A'} — ${finding.summary || ''}
${dependencyChain ? `Dependency chain: ${dependencyChain.join(' → ')}` : ''}

Analyse the root cause from a supply chain perspective. Address:

1. **Why this component?** — What properties of this package make it a high-value target or commonly exploited?
2. **How it entered the graph** — Direct dep or transitive? What does that tell us about oversight?
3. **What failed upstream** — Maintainer, registry, or ecosystem-level failure?
4. **Supply chain pattern** — Does this match a known attack pattern (typosquatting, dependency confusion, compromised maintainer, etc.)?

Maximum 200 words. Be analytical, not generic.`;

  const provider = getProvider();
  if (provider === 'gemini') {
    return await callGemini({ prompt, maxOutputTokens: 600, temperature: 0.2 });
  } else {
    const ai = getAnthropicClient();
    const msg = await ai.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: prompt }],
    });
    return msg.content[0].text;
  }
}

// ── 5. Risk prediction ────────────────────────────────────────────────────────

async function predictRisk(repoContext) {
  const prompt = `You are a security risk analyst. Given a repository's current security state, predict near-term risk and respond ONLY with valid JSON — no markdown, no extra text.

Repository state:
${JSON.stringify(repoContext, null, 2)}

Return this exact schema:
{
  "overallRiskLevel": "one of: Critical | High | Medium | Low",
  "predictedRiskScore": "integer 0-100 (100 = completely secure)",
  "topRisks": [
    { "risk": "description", "likelihood": "High|Medium|Low", "impact": "High|Medium|Low" }
  ],
  "trendDirection": "one of: Improving | Stable | Degrading",
  "recommendedActions": ["array of 3 prioritised action strings"],
  "reasoning": "3-4 sentence overall risk narrative"
}`;

  const provider = getProvider();
  if (provider === 'gemini') {
    const text = await callGemini({
      prompt,
      responseMimeType: 'application/json',
      maxOutputTokens: 800,
      temperature: 0.1,
    });
    return parseJsonSafe(text);
  } else {
    const ai = getAnthropicClient();
    const msg = await ai.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 768,
      messages: [{ role: 'user', content: prompt }],
    });
    return parseJsonSafe(msg.content[0].text);
  }
}

// ── 6. Streaming variant for dashboard "typing" effect ─────────────────────────

async function streamExplainVulnerability(finding, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const prompt = `Explain ${finding.cveId || finding.id} in ${finding.component}@${finding.version} to a developer in under 200 words. What does it do, how is it exploited, what's the real-world impact? CVSS: ${finding.severity}. EPSS: ${finding.epss != null ? `${(finding.epss * 100).toFixed(1)}%` : 'unknown'}.`;

  const provider = getProvider();
  if (provider === 'gemini') {
    const apiKey = process.env.GEMINI_API_KEY;
    const model = process.env.GEMINI_MODEL || 'gemini-1.5-flash';
    const url = `${GEMINI_BASE_URL}/${model}:streamGenerateContent?alt=sse&key=${apiKey}`;

    const payload = {
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { maxOutputTokens: 512, temperature: 0.2 },
    };

    try {
      const response = await axios({
        method: 'post',
        url,
        data: payload,
        headers: { 'Content-Type': 'application/json' },
        responseType: 'stream',
        timeout: 25000,
      });

      let buffer = '';
      response.data.on('data', chunk => {
        buffer += chunk.toString();
        const lines = buffer.split('\n');
        buffer = lines.pop();

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              const text = data.candidates?.[0]?.content?.parts?.[0]?.text;
              if (text) {
                res.write(`data: ${JSON.stringify({ type: 'delta', text })}\n\n`);
              }
            } catch {}
          }
        }
      });

      response.data.on('end', () => {
        res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
        res.end();
      });

      response.data.on('error', () => {
        res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
        res.end();
      });
    } catch {
      // Fallback: non-streaming call then emit
      const text = await explainVulnerability(finding);
      res.write(`data: ${JSON.stringify({ type: 'delta', text })}\n\n`);
      res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
      res.end();
    }
  } else {
    const ai = getAnthropicClient();
    const stream = await ai.messages.stream({
      model: 'claude-sonnet-4-6',
      max_tokens: 512,
      messages: [{ role: 'user', content: prompt }],
    });

    for await (const chunk of stream) {
      if (chunk.type === 'content_block_delta' && chunk.delta?.type === 'text_delta') {
        res.write(`data: ${JSON.stringify({ type: 'delta', text: chunk.delta.text })}\n\n`);
      }
    }

    res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
    res.end();
  }
}

// ── 7. Multi-turn Chat ────────────────────────────────────────────────────────

async function chat(messages, systemContext) {
  const provider = getProvider();
  if (provider === 'gemini') {
    const contents = messages.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content || '' }],
    }));

    return await callGemini({
      contents,
      systemInstruction: systemContext,
      maxOutputTokens: 1024,
      temperature: 0.3,
    });
  } else {
    const ai = getAnthropicClient();
    const response = await ai.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      system: systemContext,
      messages: messages.map(m => ({ role: m.role, content: m.content })),
    });
    return response.content[0].text;
  }
}

module.exports = {
  explainVulnerability,
  classifyThreat,
  recommendRemediation,
  analyseRootCause,
  predictRisk,
  streamExplainVulnerability,
  chat,
};
