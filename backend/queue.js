const { Queue } = require('bullmq');
const IORedis = require('ioredis');
const EventEmitter = require('events');

// Global event bus for tracking job progress and completions across queue types
const jobEvents = new EventEmitter();

let useBullMQ = false;
let scanQueue = null;

// In-Memory Queue Fallback
class InMemoryQueue {
  constructor(name) {
    this.name = name;
    this.jobs = new Map();
    this.workerFn = null;
  }

  async add(jobName, data, opts = {}) {
    const jobId = opts.jobId || `job_${Math.random().toString(36).substr(2, 9)}`;
    
    const job = {
      id: jobId,
      name: jobName,
      data: data,
      progressValue: 0,
      status: 'waiting',
      updateProgress: async (value) => {
        job.progressValue = value;
        jobEvents.emit('progress', { jobId, progress: value });
        console.log(`[Queue Fallback] Job ${jobId} progress: ${value}%`);
        return;
      }
    };

    this.jobs.set(jobId, job);
    
    // Trigger processing asynchronously
    setImmediate(() => this.processJob(jobId));

    return { id: jobId, data };
  }

  setWorker(workerFn) {
    this.workerFn = workerFn;
  }

  async processJob(jobId) {
    const job = this.jobs.get(jobId);
    if (!job || !this.workerFn) return;

    job.status = 'active';
    jobEvents.emit('active', { jobId });

    try {
      const result = await this.workerFn(job);
      job.status = 'completed';
      job.result = result;
      jobEvents.emit('completed', { jobId, result });
    } catch (err) {
      job.status = 'failed';
      job.error = err.message;
      jobEvents.emit('failed', { jobId, error: err.message });
    }
  }

  async getJob(jobId) {
    return this.jobs.get(jobId) || null;
  }
}

// Function to initialize the Queue
const initQueue = async (redisHost, redisPort) => {
  const redisConfig = {
    host: redisHost || 'localhost',
    port: redisPort || 6379,
    maxRetriesPerRequest: null,
    connectTimeout: 1000 // fail fast if Redis is down
  };

  const connection = new IORedis(redisConfig);

  return new Promise((resolve) => {
    connection.on('connect', () => {
      console.log('Redis connected. Initializing BullMQ.');
      useBullMQ = true;
      scanQueue = new Queue('email-scans', { connection });
      resolve({ scanQueue, useBullMQ });
    });

    connection.on('error', (err) => {
      console.warn(`Redis connection failed: ${err.message}. Falling back to In-Memory Queue.`);
      connection.disconnect();
      useBullMQ = false;
      scanQueue = new InMemoryQueue('email-scans-fallback');
      resolve({ scanQueue, useBullMQ });
    });
  });
};

// Simple helper to get the active queue
const getQueue = () => {
  if (!scanQueue) {
    console.warn('Queue not initialized yet, returning temporary In-Memory Queue.');
    scanQueue = new InMemoryQueue('email-scans-fallback');
  }
  return scanQueue;
};

module.exports = {
  initQueue,
  getQueue,
  jobEvents,
  isBullMQ: () => useBullMQ
};
