const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    minlength: 1,
    maxlength: 100
  },
  token: {
    type: String,
    required: true,
    ref: 'Token'
  },
  // Dane osobowe dla dowodu
  personalData: {
    firstName: {
      type: String,
      trim: true,
      maxlength: 100
    },
    lastName: {
      type: String,
      trim: true,
      maxlength: 100
    },
    birthDate: {
      type: Date
    },
    pesel: {
      type: String,
      trim: true,
      match: /^\d{11}$/
    },
    idNumber: {
      type: String,
      trim: true,
      maxlength: 20
    },
    address: {
      street: { type: String, trim: true, maxlength: 200 },
      city: { type: String, trim: true, maxlength: 100 },
      postalCode: { type: String, trim: true, maxlength: 10 },
      country: { type: String, trim: true, maxlength: 100, default: 'Polska' }
    },
    photo: {
      type: String, // Base64 encoded image lub URL
      maxlength: 5000000 // 5MB limit
    }
  },
  // Dokumenty użytkownika
  documents: [{
    type: {
      type: String,
      enum: ['id', 'passport', 'driving_license', 'other'],
      default: 'id'
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200
    },
    data: {
      type: mongoose.Schema.Types.Mixed
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  // Ustawienia użytkownika
  settings: {
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'auto'
    },
    language: {
      type: String,
      enum: ['pl', 'en'],
      default: 'pl'
    },
    notifications: {
      type: Boolean,
      default: true
    }
  },
  // Statystyki
  stats: {
    loginCount: {
      type: Number,
      default: 0
    },
    lastLogin: {
      type: Date,
      default: Date.now
    },
    documentsCreated: {
      type: Number,
      default: 0
    }
  },
  // Sesje
  sessions: [{
    sessionId: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now
    },
    lastActivity: {
      type: Date,
      default: Date.now
    },
    userAgent: String,
    ipAddress: String,
    isActive: {
      type: Boolean,
      default: true
    }
  }],
  isActive: {
    type: Boolean,
    default: true
  }
}, {
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      // Nie zwracaj wrażliwych danych w JSON
      delete ret.__v;
      return ret;
    }
  },
  toObject: { virtuals: true }
});

// Virtual dla pełnego imienia
userSchema.virtual('fullName').get(function() {
  if (this.personalData.firstName && this.personalData.lastName) {
    return `${this.personalData.firstName} ${this.personalData.lastName}`;
  }
  return this.username;
});

// Virtual dla aktywnych dokumentów
userSchema.virtual('activeDocuments').get(function() {
  return this.documents.filter(doc => doc.isActive);
});

// Index dla lepszej wydajności
userSchema.index({ username: 1 });
userSchema.index({ token: 1 });
userSchema.index({ 'personalData.pesel': 1 });
userSchema.index({ 'personalData.idNumber': 1 });
userSchema.index({ createdAt: -1 });

// Metoda do dodawania dokumentu
userSchema.methods.addDocument = function(documentData) {
  this.documents.push(documentData);
  this.stats.documentsCreated += 1;
  return this.save();
};

// Metoda do aktualizacji statystyk logowania
userSchema.methods.updateLoginStats = function() {
  this.stats.loginCount += 1;
  this.stats.lastLogin = new Date();
  return this.save();
};

// Metoda do dodawania sesji
userSchema.methods.addSession = function(sessionData) {
  // Usuń stare nieaktywne sesje (starsze niż 30 dni)
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  this.sessions = this.sessions.filter(session => 
    session.isActive && session.lastActivity > thirtyDaysAgo
  );
  
  // Dodaj nową sesję
  this.sessions.push({
    sessionId: sessionData.sessionId,
    userAgent: sessionData.userAgent,
    ipAddress: sessionData.ipAddress,
    createdAt: new Date(),
    lastActivity: new Date(),
    isActive: true
  });
  
  return this.save();
};

// Metoda do aktualizacji aktywności sesji
userSchema.methods.updateSessionActivity = function(sessionId) {
  const session = this.sessions.find(s => s.sessionId === sessionId && s.isActive);
  if (session) {
    session.lastActivity = new Date();
    return this.save();
  }
  return Promise.resolve(this);
};

// Metoda do dezaktywacji sesji
userSchema.methods.deactivateSession = function(sessionId) {
  const session = this.sessions.find(s => s.sessionId === sessionId);
  if (session) {
    session.isActive = false;
    return this.save();
  }
  return Promise.resolve(this);
};

// Metoda do dezaktywacji wszystkich sesji
userSchema.methods.deactivateAllSessions = function() {
  this.sessions.forEach(session => {
    session.isActive = false;
  });
  return this.save();
};

// Statyczna metoda do znajdowania użytkownika po tokenie
userSchema.statics.findByToken = function(token) {
  return this.findOne({ token, isActive: true });
};

module.exports = mongoose.model('User', userSchema);
