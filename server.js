const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Import routes
const authRoutes = require('./routes/auth');
const tokenRoutes = require('./routes/tokens');
const userRoutes = require('./routes/users');

// Security middleware
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 5 * 60 * 1000, // 5 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 500, // limit each IP to 500 requests per windowMs
  message: {
    error: 'Zbyt wiele żądań z tego IP, spróbuj ponownie później.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: function (req) {
    // Skip rate limiting for OPTIONS requests and ping endpoint
    return req.method === 'OPTIONS' || req.path === '/ping';
  }
});

app.use(limiter);

// Compression middleware
app.use(compression());

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      'https://xyzobywatel404.netlify.app',
      'http://xyzobywatel404.netlify.app',
      'https://www.xyzobywatel404.netlify.app',
      'http://www.xyzobywatel404.netlify.app',
      'https://fancy-meerkat-331f14.netlify.app',
      'http://localhost:3000',
      'http://localhost:8080',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:8080',
      'https://localhost:3000',
      'https://127.0.0.1:3000',
      'https://backendm-9np8.onrender.com',
      'http://backendm-9np8.onrender.com'
    ].filter(Boolean);
    
    // For development, allow all local origins
    if (process.env.NODE_ENV !== 'production') {
      if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
        return callback(null, true);
      }
    }
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`Rejected CORS request from origin: ${origin}`);
      callback(new Error('Nie dozwolone przez CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin', 'X-Requested-With'],
  exposedHeaders: ['Set-Cookie'],
  maxAge: 86400 // 24 hours in seconds
};

app.use(cors(corsOptions));

// Additional security headers
app.use((req, res, next) => {
  const origin = req.headers.origin;
  
  // Explicitly handle CORS for all routes
  if (origin) {
    corsOptions.origin(origin, (err, allowed) => {
      if (allowed) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Auth-Token');
        res.header('Access-Control-Expose-Headers', 'Set-Cookie');
      }
    });
  }

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  next();
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// MongoDB connection
const connectDB = async () => {
  try {
    if (!process.env.MONGODB_URI) {
      throw new Error('MONGODB_URI is not defined in environment variables');
    }
    
    const mongoURI = process.env.MONGODB_URI.trim();
    console.log('Attempting to connect to MongoDB with URI:', 
      mongoURI.replace(/\/\/([^:]+):([^@]+)@/, '//[HIDDEN_CREDENTIALS]@')
    );
    
    const conn = await mongoose.connect(mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
};

// Log environment configuration (safely)
console.log('Environment Configuration:', {
  NODE_ENV: process.env.NODE_ENV,
  PORT: process.env.PORT,
  MONGODB_URI: process.env.MONGODB_URI ? '[HIDDEN]' : 'undefined',
  JWT_SECRET: process.env.JWT_SECRET ? '[HIDDEN]' : 'undefined',
  FRONTEND_URL: process.env.FRONTEND_URL,
  RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS,
  RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS
});

// Connect to database
connectDB();

// Health check endpoints
app.get('/', cors(corsOptions), (req, res) => {
  res.json({
    message: 'Obywtel Backend API',
    status: 'running',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    origin: req.headers.origin || 'unknown'
  });
});

app.get('/api/health', cors(corsOptions), (req, res) => {
  const origin = req.headers.origin;
  let allowed = false;
  
  if (origin) {
    corsOptions.origin(origin, (err, result) => {
      allowed = !err && result;
    });
  }
  
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    server: 'online',
    cors: {
      origin: origin || 'unknown',
      allowed: allowed
    }
  });
});

// JSONP compatible ping endpoint
app.get('/ping', cors(corsOptions), (req, res) => {
  const callback = req.query.callback;
  const response = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    origin: req.headers.origin || 'unknown'
  };
  
  if (callback) {
    res.type('application/javascript');
    res.set('X-Content-Type-Options', 'nosniff');
    res.send(`${callback}(${JSON.stringify(response)})`);
  } else {
    res.json(response);
  }
});

// Enable pre-flight requests for all routes
app.options('*', cors(corsOptions));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/tokens', tokenRoutes);
app.use('/api/users', userRoutes);
app.use('/api', authRoutes); // For backward compatibility

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      error: 'Błąd walidacji danych',
      details: err.message
    });
  }
  
  if (err.name === 'CastError') {
    return res.status(400).json({
      success: false,
      error: 'Nieprawidłowy format ID'
    });
  }
  
  if (err.code === 11000) {
    return res.status(400).json({
      success: false,
      error: 'Duplikat danych - rekord już istnieje'
    });
  }
  
  res.status(500).json({
    success: false,
    error: 'Wewnętrzny błąd serwera',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Coś poszło nie tak'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint nie został znaleziony'
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed.');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('MongoDB connection closed.');
    process.exit(0);
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
