const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  username: {
    type: String,
    required: true,
    trim: true,
    minlength: 1,
    maxlength: 100
  },
  usageCount: {
    type: Number,
    required: true,
    min: 1,
    max: 1000,
    default: 1
  },
  uses: {
    type: Number,
    default: 0,
    min: 0
  },
  active: {
    type: Boolean,
    default: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastUsed: {
    type: Date,
    default: null
  },
  userData: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  // Dodatkowe pola dla zarządzania sesjami
  sessions: [{
    sessionId: String,
    createdAt: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now },
    userAgent: String,
    ipAddress: String
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Virtual dla sprawdzenia czy token jest wyczerpany
tokenSchema.virtual('isExhausted').get(function() {
  return this.uses >= this.usageCount;
});

// Virtual dla pozostałych użyć
tokenSchema.virtual('remainingUses').get(function() {
  return Math.max(0, this.usageCount - this.uses);
});

// Index dla lepszej wydajności
tokenSchema.index({ token: 1 });
tokenSchema.index({ active: 1 });
tokenSchema.index({ createdAt: -1 });
tokenSchema.index({ username: 1 });

// Middleware przed zapisem
tokenSchema.pre('save', function(next) {
  // Automatycznie dezaktywuj token jeśli został wyczerpany
  if (this.uses >= this.usageCount) {
    this.active = false;
  }
  next();
});

// Metoda do użycia tokenu
tokenSchema.methods.useToken = function(sessionData = {}) {
  if (!this.active) {
    throw new Error('Token jest nieaktywny');
  }
  
  if (this.uses >= this.usageCount) {
    throw new Error('Token został wyczerpany');
  }
  
  this.uses += 1;
  this.lastUsed = new Date();
  
  // Dodaj sesję jeśli podano dane
  if (sessionData.sessionId) {
    this.sessions.push({
      sessionId: sessionData.sessionId,
      userAgent: sessionData.userAgent,
      ipAddress: sessionData.ipAddress,
      createdAt: new Date(),
      lastActivity: new Date()
    });
  }
  
  // Automatycznie dezaktywuj jeśli wyczerpany
  if (this.uses >= this.usageCount) {
    this.active = false;
  }
  
  return this.save();
};

// Metoda do aktualizacji aktywności sesji
tokenSchema.methods.updateSessionActivity = function(sessionId) {
  const session = this.sessions.find(s => s.sessionId === sessionId);
  if (session) {
    session.lastActivity = new Date();
    return this.save();
  }
  return Promise.resolve(this);
};

// Metoda do usuwania starych sesji
tokenSchema.methods.cleanupOldSessions = function(maxAge = 24 * 60 * 60 * 1000) { // 24 godziny
  const cutoff = new Date(Date.now() - maxAge);
  this.sessions = this.sessions.filter(session => session.lastActivity > cutoff);
  return this.save();
};

// Statyczna metoda do znajdowania aktywnych tokenów
tokenSchema.statics.findActiveTokens = function() {
  return this.find({ active: true }).sort({ createdAt: -1 });
};

// Statyczna metoda do znajdowania nieaktywnych tokenów
tokenSchema.statics.findInactiveTokens = function() {
  return this.find({ active: false }).sort({ createdAt: -1 });
};

module.exports = mongoose.model('Token', tokenSchema);
