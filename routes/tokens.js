const express = require('express');
const { body, validationResult } = require('express-validator');
const Token = require('../models/token');
const { generateToken } = require('../utils/helpers');

const router = express.Router();

// Middleware do sprawdzania uprawnień administratora
const requireAdmin = (req, res, next) => {
  const adminPassword = req.headers['x-admin-password'] || req.body.adminPassword;
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({
      success: false,
      error: 'Brak uprawnień administratora'
    });
  }
  
  next();
};

// GET /api/tokens - Pobierz wszystkie tokeny (tylko admin)
router.get('/', async (req, res) => {
  try {
    const tokens = await Token.find({})
      .sort({ createdAt: -1 })
      .select('-__v');
    
    res.json(tokens);
    
  } catch (error) {
    console.error('Get tokens error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// POST /api/tokens - Stwórz nowy token (tylko admin)
router.post('/', [
  body('username')
    .notEmpty()
    .withMessage('Nazwa użytkownika jest wymagana')
    .isLength({ min: 1, max: 100 })
    .withMessage('Nazwa użytkownika musi mieć od 1 do 100 znaków')
    .trim(),
  body('usageCount')
    .isInt({ min: 1, max: 1000 })
    .withMessage('Liczba użyć musi być liczbą całkowitą od 1 do 1000'),
  body('token')
    .optional()
    .isLength({ min: 3, max: 50 })
    .withMessage('Token musi mieć od 3 do 50 znaków')
    .trim()
], async (req, res) => {
  try {
    // Sprawdź błędy walidacji
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Błąd walidacji',
        details: errors.array()
      });
    }

    const { username, usageCount, token } = req.body;
    
    // Użyj podanego tokenu lub wygeneruj nowy
    const tokenValue = token || generateToken();
    
    // Sprawdź czy token już istnieje
    const existingToken = await Token.findOne({ token: tokenValue });
    if (existingToken) {
      return res.status(400).json({
        success: false,
        error: 'Token już istnieje'
      });
    }
    
    // Stwórz nowy token
    const newToken = new Token({
      token: tokenValue,
      username,
      usageCount,
      uses: 0,
      active: true
    });
    
    await newToken.save();
    
    res.status(201).json({
      success: true,
      message: 'Token został utworzony',
      token: newToken
    });
    
  } catch (error) {
    console.error('Create token error:', error);
    
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        error: 'Token już istnieje'
      });
    }
    
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/tokens/active - Pobierz aktywne tokeny
router.get('/active', async (req, res) => {
  try {
    const tokens = await Token.findActiveTokens();
    
    res.json({
      success: true,
      tokens
    });
    
  } catch (error) {
    console.error('Get active tokens error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/tokens/inactive - Pobierz nieaktywne tokeny
router.get('/inactive', async (req, res) => {
  try {
    const tokens = await Token.findInactiveTokens();
    
    res.json({
      success: true,
      tokens
    });
    
  } catch (error) {
    console.error('Get inactive tokens error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/tokens/:id - Pobierz konkretny token
router.get('/:id', async (req, res) => {
  try {
    const token = await Token.findById(req.params.id);
    
    if (!token) {
      return res.status(404).json({
        success: false,
        error: 'Token nie został znaleziony'
      });
    }
    
    res.json({
      success: true,
      token
    });
    
  } catch (error) {
    console.error('Get token error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// PATCH /api/tokens/:id/activate - Aktywuj token (tylko admin)
router.patch('/:id/activate', async (req, res) => {
  try {
    const token = await Token.findById(req.params.id);
    
    if (!token) {
      return res.status(404).json({
        success: false,
        error: 'Token nie został znaleziony'
      });
    }
    
    token.active = true;
    await token.save();
    
    res.json({
      success: true,
      message: 'Token został aktywowany',
      token
    });
    
  } catch (error) {
    console.error('Activate token error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// PATCH /api/tokens/:id/deactivate - Dezaktywuj token (tylko admin)
router.patch('/:id/deactivate', async (req, res) => {
  try {
    const token = await Token.findById(req.params.id);
    
    if (!token) {
      return res.status(404).json({
        success: false,
        error: 'Token nie został znaleziony'
      });
    }
    
    token.active = false;
    await token.save();
    
    res.json({
      success: true,
      message: 'Token został dezaktywowany',
      token
    });
    
  } catch (error) {
    console.error('Deactivate token error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// PUT /api/tokens/:id - Aktualizuj token (tylko admin)
router.put('/:id', [
  body('username')
    .optional()
    .isLength({ min: 1, max: 100 })
    .withMessage('Nazwa użytkownika musi mieć od 1 do 100 znaków')
    .trim(),
  body('usageCount')
    .optional()
    .isInt({ min: 1, max: 1000 })
    .withMessage('Liczba użyć musi być liczbą całkowitą od 1 do 1000'),
  body('active')
    .optional()
    .isBoolean()
    .withMessage('Status aktywności musi być wartością boolean')
], async (req, res) => {
  try {
    // Sprawdź błędy walidacji
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: 'Błąd walidacji',
        details: errors.array()
      });
    }

    const token = await Token.findById(req.params.id);
    
    if (!token) {
      return res.status(404).json({
        success: false,
        error: 'Token nie został znaleziony'
      });
    }
    
    // Aktualizuj tylko podane pola
    const { username, usageCount, active } = req.body;
    
    if (username !== undefined) token.username = username;
    if (usageCount !== undefined) token.usageCount = usageCount;
    if (active !== undefined) token.active = active;
    
    await token.save();
    
    res.json({
      success: true,
      message: 'Token został zaktualizowany',
      token
    });
    
  } catch (error) {
    console.error('Update token error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// DELETE /api/tokens/:id - Usuń token (tylko admin)
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const token = await Token.findById(req.params.id);
    
    if (!token) {
      return res.status(404).json({
        success: false,
        error: 'Token nie został znaleziony'
      });
    }
    
    await Token.findByIdAndDelete(req.params.id);
    
    res.json({
      success: true,
      message: 'Token został usunięty'
    });
    
  } catch (error) {
    console.error('Delete token error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// POST /api/tokens/generate - Wygeneruj nowy token (pomocnicza funkcja)
router.post('/generate', (req, res) => {
  const newToken = generateToken();
  
  res.json({
    success: true,
    token: newToken
  });
});

// GET /api/tokens/stats/summary - Pobierz statystyki tokenów
router.get('/stats/summary', async (req, res) => {
  try {
    const totalTokens = await Token.countDocuments();
    const activeTokens = await Token.countDocuments({ active: true });
    const inactiveTokens = await Token.countDocuments({ active: false });
    const exhaustedTokens = await Token.countDocuments({ 
      $expr: { $gte: ['$uses', '$usageCount'] }
    });
    
    // Statystyki użycia
    const usageStats = await Token.aggregate([
      {
        $group: {
          _id: null,
          totalUses: { $sum: '$uses' },
          totalCapacity: { $sum: '$usageCount' },
          avgUsage: { $avg: '$uses' }
        }
      }
    ]);
    
    res.json({
      success: true,
      stats: {
        total: totalTokens,
        active: activeTokens,
        inactive: inactiveTokens,
        exhausted: exhaustedTokens,
        usage: usageStats[0] || { totalUses: 0, totalCapacity: 0, avgUsage: 0 }
      }
    });
    
  } catch (error) {
    console.error('Get token stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

module.exports = router;