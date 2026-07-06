const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

let useMongoose = false;
const DB_FILE_PATH = path.join(__dirname, 'data', 'db.json');

// Ensure data folder exists for JSON file database fallback
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}
if (!fs.existsSync(DB_FILE_PATH)) {
  fs.writeFileSync(DB_FILE_PATH, JSON.stringify({ analysis_results: [] }, null, 2));
}

// Define Mongoose Schema
const AnalysisResultSchema = new mongoose.Schema({
  user_id: { type: String, default: null },
  email_subject: { type: String, required: true },
  verdict: { type: String, required: true },
  risk_score: { type: Number, required: true },
  explanation_tree: [
    {
      reason: { type: String, required: true },
      detail: { type: String, required: true },
      confidence: { type: Number, required: true }
    }
  ],
  llm_explanation: { type: String, default: '' },
  raw_headers: { type: mongoose.Schema.Types.Mixed, default: {} },
  created_at: { type: Date, default: Date.now }
});

const MongooseAnalysisResult = mongoose.model('AnalysisResult', AnalysisResultSchema);

// JSON File Database Fallback Implementation
class JsonFileDB {
  static read() {
    try {
      const content = fs.readFileSync(DB_FILE_PATH, 'utf8');
      return JSON.parse(content);
    } catch (e) {
      return { analysis_results: [] };
    }
  }

  static write(data) {
    fs.writeFileSync(DB_FILE_PATH, JSON.stringify(data, null, 2));
  }

  static async create(data) {
    const db = this.read();
    const newRecord = {
      _id: uuidv4(),
      user_id: data.user_id || null,
      email_subject: data.email_subject || 'No Subject',
      verdict: data.verdict || 'SAFE',
      risk_score: data.risk_score || 0,
      explanation_tree: data.explanation_tree || [],
      llm_explanation: data.llm_explanation || '',
      raw_headers: data.raw_headers || {},
      created_at: new Date().toISOString()
    };
    db.analysis_results.push(newRecord);
    this.write(db);
    return newRecord;
  }

  static async find(query = {}) {
    const db = this.read();
    // Return all sorted by date desc
    return db.analysis_results.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  }

  static async findById(id) {
    const db = this.read();
    return db.analysis_results.find(item => item._id === id) || null;
  }
}

// Connect to MongoDB
const connectDB = async (uri) => {
  try {
    mongoose.set('strictQuery', false);
    await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 2000 // Quick timeout to fail fast and trigger fallback
    });
    useMongoose = true;
    console.log('MongoDB connected successfully.');
  } catch (error) {
    console.warn(`MongoDB connection failed: ${error.message}. Falling back to Local JSON File DB.`);
    useMongoose = false;
  }
};

// Export unified Model interface
const AnalysisResult = {
  create: async (data) => {
    if (useMongoose) {
      return await MongooseAnalysisResult.create(data);
    } else {
      return await JsonFileDB.create(data);
    }
  },
  find: async (query) => {
    if (useMongoose) {
      return await MongooseAnalysisResult.find(query).sort({ created_at: -1 });
    } else {
      return await JsonFileDB.find(query);
    }
  },
  findById: async (id) => {
    if (useMongoose) {
      return await MongooseAnalysisResult.findById(id);
    } else {
      return await JsonFileDB.findById(id);
    }
  }
};

module.exports = {
  connectDB,
  AnalysisResult
};
