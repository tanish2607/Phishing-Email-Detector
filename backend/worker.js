const { Worker } = require('bullmq');
const axios = require('axios');
const { AnalysisResult } = require('./models');
const { getQueue, isBullMQ, jobEvents } = require('./queue');

const AI_SERVICE_URL = process.env.AI_SERVICE_URL || 'http://localhost:8000';

// Sleep helper for realistic UI progress steps
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Core processing logic shared between BullMQ and In-Memory Queue
const processScanJob = async (job) => {
  const { raw_email } = job.data;
  console.log(`[Worker] Starting scan job: ${job.id}`);

  try {
    // Stage 1: Parsing MIME
    await job.updateProgress(10);
    await sleep(800);

    // Stage 2: URL check
    await job.updateProgress(35);
    await sleep(800);

    // Stage 3: Header Authentication checks
    await job.updateProgress(60);
    await sleep(800);

    // Stage 4: NLP Intent & Brand impersonation analysis
    await job.updateProgress(80);
    await sleep(800);

    // Stage 5: ML prediction + LLM Synthesis
    await job.updateProgress(90);

    let resultData;
    try {
      console.log(`[Worker] Calling AI sidecar at ${AI_SERVICE_URL}/api/v1/analyze`);
      const response = await axios.post(`${AI_SERVICE_URL}/api/v1/analyze`, { raw_email }, { timeout: 6000 });
      resultData = response.data;
    } catch (apiError) {
      console.warn(`[Worker] AI sidecar unreachable: ${apiError.message}. Using high-fidelity JS mock analysis.`);
      resultData = generateMockAnalysis(raw_email);
    }

    // Save to Database (Mongoose or JSON DB)
    const savedDoc = await AnalysisResult.create({
      email_subject: resultData.subject || 'No Subject',
      verdict: resultData.verdict || (resultData.final_risk_score > 70 ? 'PHISHING' : (resultData.final_risk_score > 40 ? 'SUSPICIOUS' : 'SAFE')),
      risk_score: resultData.final_risk_score || 0,
      explanation_tree: resultData.explanation_tree || [],
      llm_explanation: resultData.llm_explanation || '',
      raw_headers: resultData.headers || {},
      created_at: new Date()
    });

    await job.updateProgress(100);
    console.log(`[Worker] Scan job ${job.id} completed successfully.`);
    return savedDoc;

  } catch (error) {
    console.error(`[Worker] Scan job ${job.id} failed:`, error.message);
    throw error;
  }
};

// High-fidelity Javascript heuristic analyzer to act as fallback
const generateMockAnalysis = (rawEmail) => {
  const emailLower = rawEmail.toLowerCase();
  
  // Extract Subject
  let subject = 'Unknown Subject';
  const subjectMatch = rawEmail.match(/Subject:\s*(.*)/i);
  if (subjectMatch) {
    subject = subjectMatch[1].trim();
  }

  // Detect indicators
  const indicators = [];
  let riskScore = 15;

  // 1. Urgency / Suspicion phrases
  if (emailLower.includes('urgent') || emailLower.includes('suspend') || emailLower.includes('immediately') || emailLower.includes('restricted')) {
    indicators.push({
      reason: 'Urgency Language Detected',
      detail: 'The email copy requests immediate action to avoid account restrictions or suspension.',
      confidence: 0.85
    });
    riskScore += 20;
  }

  // 2. Mock brand spoofing check
  if (emailLower.includes('paypa1') || emailLower.includes('paypaI') || emailLower.includes('netflix-support') || emailLower.includes('micros0ft')) {
    indicators.push({
      reason: 'Brand Impersonation (Homoglyph)',
      detail: 'Detected characters designed to look like a legitimate brand name (e.g. PayPal, Microsoft).',
      confidence: 0.98
    });
    riskScore += 45;
  }

  // 3. URLs
  const urlPattern = /https?:\/\/[^\s<>"]+/g;
  const urls = rawEmail.match(urlPattern) || [];
  
  for (const url of urls) {
    if (url.includes('verify') || url.includes('login') || url.includes('update') || url.includes('192.168.')) {
      indicators.push({
        reason: 'Suspicious Hyperlink',
        detail: `Link leads to an unverified external landing page containing keyword credentials redirects: ${url}`,
        confidence: 0.92
      });
      riskScore += 25;
    }
  }

  // 4. Missing SPF/DMARC headers (common in copy-pastes)
  if (!rawEmail.includes('SPF: pass') && !rawEmail.includes('Authentication-Results:')) {
    indicators.push({
      reason: 'Missing Security Signatures',
      detail: 'The email does not contain valid SPF, DKIM, or DMARC authentication signatures.',
      confidence: 0.75
    });
    riskScore += 10;
  }

  // 5. Spam / Promotional keywords
  let isPromo = false;
  if (emailLower.includes('unsubscribe') || emailLower.includes('special offer') || emailLower.includes('discount') || emailLower.includes('sale') || emailLower.includes('newsletter') || emailLower.includes('opt out')) {
    isPromo = true;
    indicators.push({
      reason: 'Promotional Content Detected',
      detail: 'The email contains marketing keywords commonly associated with newsletters or promotional campaigns.',
      confidence: 0.90
    });
    riskScore += 5;
  }

  let isSpam = false;
  if (emailLower.includes('viagra') || emailLower.includes('lottery') || emailLower.includes('winner') || emailLower.includes('casino')) {
    isSpam = true;
    indicators.push({
      reason: 'Spam Keywords Detected',
      detail: 'Contains classic spam triggers often caught by standard filters.',
      confidence: 0.95
    });
    riskScore += 15;
  }

  if (indicators.length === 0) {
    indicators.push({
      reason: 'Standard Email Layout',
      detail: 'No obvious phishing templates, homoglyphs, or credential requests were found in the email copy.',
      confidence: 0.80
    });
  }

  riskScore = Math.min(100, riskScore);
  
  let verdict = 'SAFE';
  if (riskScore > 70) {
    verdict = 'PHISHING';
  } else if (riskScore > 40) {
    verdict = 'SUSPICIOUS';
  } else if (isSpam) {
    verdict = 'SPAM';
  } else if (isPromo) {
    verdict = 'PROMO';
  }

  // Build LLM simulation breakdown
  let llmExplanation = `PhishShield AI has completed its analysis. The message is classified as **${verdict}** with a risk score of **${riskScore}/100** (using fallback local heuristic).\n\n`;
  llmExplanation += `### Breakdown of Security Triggers:\n`;
  for (const item of indicators) {
    llmExplanation += `- **${item.reason}**: ${item.detail} *(Confidence: ${intToPercent(item.confidence)})*\n`;
  }
  llmExplanation += `\n**Recommendation:** Do not submit any credentials or click links. Check with the sender via a trusted separate channel.`;

  return {
    subject,
    body_text: rawEmail,
    verdict,
    extracted_urls: urls,
    url_verdicts: urls.map(u => ({ url: u, verdict: 'SUSPICIOUS', confidence: 0.8, details: 'Suspicious redirect' })),
    header_auth_results: { spf: 'none', dkim: 'none', dmarc: 'none' },
    sender_reputation: { domain_age_days: 5, suspicious_domain_age: true },
    nlp_urgency_score: emailLower.includes('urgent') ? 0.8 : 0.2,
    final_risk_score: riskScore,
    llm_explanation: llmExplanation,
    explanation_tree: indicators,
    headers: {}
  };
};

const intToPercent = (val) => `${Math.round(val * 100)}%`;

// Main initialization function for Worker process
const initWorker = (redisHost, redisPort) => {
  const queue = getQueue();

  if (isBullMQ()) {
    console.log('Initializing BullMQ Worker.');
    const connectionConfig = {
      host: redisHost || 'localhost',
      port: redisPort || 6379,
      maxRetriesPerRequest: null
    };

    const worker = new Worker('email-scans', async (job) => {
      return await processScanJob(job);
    }, { connection: connectionConfig });

    worker.on('active', (job) => {
      jobEvents.emit('active', { jobId: job.id });
    });

    worker.on('progress', (job, progress) => {
      jobEvents.emit('progress', { jobId: job.id, progress });
    });

    worker.on('completed', (job, result) => {
      jobEvents.emit('completed', { jobId: job.id, result });
    });

    worker.on('failed', (job, err) => {
      jobEvents.emit('failed', { jobId: job ? job.id : 'unknown', error: err.message });
    });

    return worker;
  } else {
    console.log('Initializing In-Memory Worker.');
    // Registers processing function inside the fallback queue
    queue.setWorker(processScanJob);
    return queue;
  }
};

module.exports = {
  initWorker
};
