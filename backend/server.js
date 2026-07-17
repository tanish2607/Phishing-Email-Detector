require('dotenv').config();

const OpenAI = require("openai");
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');

const { connectDB, AnalysisResult } = require('./models');
const { initQueue, getQueue, jobEvents } = require('./queue');
const { initWorker } = require('./worker');

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Setup health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', service: 'phishshield-backend' });
});

// GET /api/v1/scans - Fetch scan history
app.get('/api/v1/scans', async (req, res) => {
  try {
    const list = await AnalysisResult.find();
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/v1/scans/:id - Fetch single analysis record
app.get('/api/v1/scans/:id', async (req, res) => {
  try {
    const record = await AnalysisResult.findById(req.params.id);
    if (!record) {
      return res.status(404).json({ error: 'Analysis result not found' });
    }
    res.json(record);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/v1/scan/paste - Main scan entry point
app.post('/api/v1/scan/paste', async (req, res) => {
  const { raw_email } = req.body;
  if (!raw_email || !raw_email.trim()) {
    return res.status(400).json({ error: 'raw_email body is required and cannot be empty' });
  }

  try {
    const queue = getQueue();
    // Add job to BullMQ / In-Memory Queue
    const job = await queue.add('analyze-email', { raw_email });
    console.log(`[Server] Created job ID: ${job.id}`);

    // Return 202 Accepted per spec
    res.status(202).json({ job_id: job.id });
  } catch (err) {
    console.error('[Server] Failed to create job:', err.message);
    res.status(500).json({ error: 'Failed to process email scan job' });
  }
});

// POST /api/v1/ai/chat - RAG-powered analyst assistant
app.post('/api/v1/ai/chat', async (req, res) => {
  const { analysis_id, query } = req.body;
  if (!analysis_id || !query) {
    return res.status(400).json({ error: 'analysis_id and query are required fields' });
  }

  try {
    const record = await AnalysisResult.findById(analysis_id);
    if (!record) {
      return res.status(404).json({ error: 'Analysis record not found' });
    }

    let chatReply;
    try {
      const completion = await openai.chat.completions.create({
        model: "gpt-4.1-mini",
        messages: [
          {
            role: "system",
            content:
              "You are a cybersecurity expert who explains phishing analysis in simple language."
          },
          {
            role: "user",
            content: `
Email Analysis:
${JSON.stringify(record, null, 2)}

User Question:
${query}
`
          }
        ],
        temperature: 0.2
      });

      chatReply = completion.choices[0].message.content;
    } catch (apiError) {
      chatReply = generateMockChatReply(record, query);
    }

    res.json({ reply: chatReply });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function generateMockChatReply(record, query) {
  const q = query.toLowerCase();

  if (q.includes('why') || q.includes('reason') || q.includes('suspicious')) {
    let reply = `Based on the forensic scan of this email, the threat score is ${record.risk_score}/100. The key flags are:\n\n`;
    record.explanation_tree.forEach((t, i) => {
      reply += `${i + 1}. **${t.reason}**: ${t.detail} (Confidence: ${Math.round(t.confidence * 100)}%)\n`;
    });
    if (record.risk_score > 70) {
      reply += `\nThis critical combination indicates a high probability of credential phishing.`;
    } else {
      reply += `\nThese signals suggest caution is advised before interacting with any content.`;
    }
    return reply;
  }

  if (q.includes('link') || q.includes('url') || q.includes('href')) {
    const urls = record.explanation_tree.filter(t => t.reason.toLowerCase().includes('url') || t.reason.toLowerCase().includes('link'));
    if (urls.length > 0) {
      return `The email contains links that match phishing signatures:\n\n` +
        urls.map(u => `- **${u.reason}**: ${u.detail}`).join('\n') +
        `\n\nWe advise against clicking them as they may lead to spoofed credential harvesting portals.`;
    } else {
      return `No highly suspicious links were flagged, but there could be hidden trackers. Always inspect URLs manually before clicking.`;
    }
  }

  if (q.includes('spf') || q.includes('dmarc') || q.includes('auth') || q.includes('dkim')) {
    const authList = record.explanation_tree.filter(t => t.reason.toLowerCase().includes('auth') || t.reason.toLowerCase().includes('spf') || t.reason.toLowerCase().includes('dmarc'));
    if (authList.length > 0) {
      return `The email failed critical sender authentication checks:\n\n` +
        authList.map(a => `- **${a.reason}**: ${a.detail}`).join('\n') +
        `\n\nThis means the sender's identity cannot be cryptographically verified.`;
    } else {
      return `The basic SPF/DKIM/DMARC headers appear to align, but this does not rule out compromised sender accounts or lookalike domain impersonation.`;
    }
  }

  return `I've analyzed the email "${record.email_subject}" (Risk Score: ${record.risk_score}%). It is flagged for: ${record.explanation_tree.map(t => t.reason).join(', ')}. Let me know if you have questions about specific elements like SPF headers, URLs, or language cues!`;
}


// WebSocket Connection & Event Relay
io.on('connection', (socket) => {
  console.log(`[Socket] Client connected: ${socket.id}`);

  // Subscribe to specific job updates
  socket.on('subscribe', ({ jobId }) => {
    console.log(`[Socket] Client ${socket.id} subscribed to job: ${jobId}`);
    socket.join(`job_${jobId}`);
  });

  socket.on('disconnect', () => {
    console.log(`[Socket] Client disconnected: ${socket.id}`);
  });
});

// Relay job events to the appropriate room & track state for polling
const jobTracker = new Map();

jobEvents.on('active', ({ jobId }) => {
  jobTracker.set(jobId, { status: 'processing', progress: 0 });
  io.to(`job_${jobId}`).emit('active', { jobId });
});

jobEvents.on('progress', ({ jobId, progress }) => {
  const t = jobTracker.get(jobId) || { status: 'processing' };
  t.progress = progress;
  jobTracker.set(jobId, t);
  io.to(`job_${jobId}`).emit('progress', { jobId, progress });
});

jobEvents.on('completed', ({ jobId, result }) => {
  jobTracker.set(jobId, { status: 'completed', result });
  io.to(`job_${jobId}`).emit('completed', { jobId, result });
});

jobEvents.on('failed', ({ jobId, error }) => {
  jobTracker.set(jobId, { status: 'error', error });
  io.to(`job_${jobId}`).emit('failed', { jobId, error });
});

// GET /api/v1/scan/status/:id - Poll job status
app.get('/api/v1/scan/status/:id', (req, res) => {
  const info = jobTracker.get(req.params.id);
  if (!info) return res.json({ status: 'waiting', progress: 0 });
  res.json(info);
});

// Startup Orchestration
const startServer = async () => {
  const PORT = process.env.PORT || 5000;
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/phishshield';
  const REDIS_HOST = process.env.REDIS_HOST || 'localhost';
  const REDIS_PORT = process.env.REDIS_PORT || 6379;

  // 1. Connect DB (fails gracefully to local file fallback)
  await connectDB(MONGO_URI);

  // 2. Connect Queue Redis (fails gracefully to In-Memory Queue fallback)
  await initQueue(REDIS_HOST, REDIS_PORT);

  // 3. Initialize Worker
  initWorker(REDIS_HOST, REDIS_PORT);

  // 4. Start HTTP Server
  server.listen(PORT, () => {
    console.log(`=================================================`);
    console.log(`PhishShield Express Backend running on port ${PORT}`);
    console.log(`=================================================`);
  });
};

startServer();
