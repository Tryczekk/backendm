const express = require('express');
const { body, validationResult } = require('express-validator');
const User = require('../models/User');
const Token = require('../models/Token');
const jwt = require('jsonwebtoken');

const router = express.Router();

// Middleware do sprawdzania tokenu JWT
const authenticateToken = (req, res, next) => {
  const token = req.cookies.authToken || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Brak tokenu autoryzacji'
    });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      error: 'Nieprawidłowy token autoryzacji'
    });
  }
};

// GET /api/users/profile - Pobierz profil użytkownika
router.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    // Aktualizuj aktywność sesji
    await user.updateSessionActivity(req.user.sessionId);
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        personalData: user.personalData,
        settings: user.settings,
        stats: user.stats,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    });
    
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// PUT /api/users/profile - Aktualizuj profil użytkownika
router.put('/profile', [
  authenticateToken,
  body('personalData.firstName')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Imię może mieć maksymalnie 100 znaków')
    .trim(),
  body('personalData.lastName')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Nazwisko może mieć maksymalnie 100 znaków')
    .trim(),
  body('personalData.pesel')
    .optional()
    .matches(/^\d{11}$/)
    .withMessage('PESEL musi składać się z 11 cyfr'),
  body('personalData.idNumber')
    .optional()
    .isLength({ max: 20 })
    .withMessage('Numer dowodu może mieć maksymalnie 20 znaków')
    .trim(),
  body('personalData.address.street')
    .optional()
    .isLength({ max: 200 })
    .withMessage('Ulica może mieć maksymalnie 200 znaków')
    .trim(),
  body('personalData.address.city')
    .optional()
    .isLength({ max: 100 })
    .withMessage('Miasto może mieć maksymalnie 100 znaków')
    .trim(),
  body('personalData.address.postalCode')
    .optional()
    .isLength({ max: 10 })
    .withMessage('Kod pocztowy może mieć maksymalnie 10 znaków')
    .trim(),
  body('personalData.photo')
    .optional()
    .isLength({ max: 5000000 })
    .withMessage('Zdjęcie jest zbyt duże (maksymalnie 5MB)')
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

    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    // Aktualizuj dane osobowe
    if (req.body.personalData) {
      user.personalData = { ...user.personalData, ...req.body.personalData };
    }
    
    // Aktualizuj ustawienia
    if (req.body.settings) {
      user.settings = { ...user.settings, ...req.body.settings };
    }
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Profil został zaktualizowany',
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        personalData: user.personalData,
        settings: user.settings
      }
    });
    
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/users/documents - Pobierz dokumenty użytkownika
router.get('/documents', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    res.json({
      success: true,
      documents: user.activeDocuments
    });
    
  } catch (error) {
    console.error('Get documents error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny b��ąd serwera'
    });
  }
});

// POST /api/users/documents - Dodaj nowy dokument
router.post('/documents', [
  authenticateToken,
  body('type')
    .isIn(['id', 'passport', 'driving_license', 'other'])
    .withMessage('Nieprawidłowy typ dokumentu'),
  body('name')
    .notEmpty()
    .withMessage('Nazwa dokumentu jest wymagana')
    .isLength({ min: 1, max: 200 })
    .withMessage('Nazwa dokumentu musi mieć od 1 do 200 znaków')
    .trim(),
  body('data')
    .optional()
    .isObject()
    .withMessage('Dane dokumentu muszą być obiektem')
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

    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    const documentData = {
      type: req.body.type,
      name: req.body.name,
      data: req.body.data || {},
      createdAt: new Date(),
      isActive: true
    };
    
    await user.addDocument(documentData);
    
    res.status(201).json({
      success: true,
      message: 'Dokument został dodany',
      document: documentData
    });
    
  } catch (error) {
    console.error('Add document error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// PUT /api/users/documents/:documentId - Aktualizuj dokument
router.put('/documents/:documentId', [
  authenticateToken,
  body('name')
    .optional()
    .isLength({ min: 1, max: 200 })
    .withMessage('Nazwa dokumentu musi mieć od 1 do 200 znaków')
    .trim(),
  body('data')
    .optional()
    .isObject()
    .withMessage('Dane dokumentu muszą być obiektem')
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

    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    const document = user.documents.id(req.params.documentId);
    
    if (!document) {
      return res.status(404).json({
        success: false,
        error: 'Dokument nie został znaleziony'
      });
    }
    
    // Aktualizuj dokument
    if (req.body.name) document.name = req.body.name;
    if (req.body.data) document.data = { ...document.data, ...req.body.data };
    
    await user.save();
    
    res.json({
      success: true,
      message: 'Dokument został zaktualizowany',
      document
    });
    
  } catch (error) {
    console.error('Update document error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// DELETE /api/users/documents/:documentId - Usuń dokument
router.delete('/documents/:documentId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    const document = user.documents.id(req.params.documentId);
    
    if (!document) {
      return res.status(404).json({
        success: false,
        error: 'Dokument nie został znaleziony'
      });
    }
    
    // Dezaktywuj dokument zamiast go usuwać
    document.isActive = false;
    await user.save();
    
    res.json({
      success: true,
      message: 'Dokument został usunięty'
    });
    
  } catch (error) {
    console.error('Delete document error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/users/sessions - Pobierz aktywne sesje użytkownika
router.get('/sessions', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    const activeSessions = user.sessions.filter(session => session.isActive);
    
    res.json({
      success: true,
      sessions: activeSessions.map(session => ({
        id: session.sessionId,
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
        isCurrent: session.sessionId === req.user.sessionId
      }))
    });
    
  } catch (error) {
    console.error('Get sessions error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// DELETE /api/users/sessions/:sessionId - Usuń konkretną sesję
router.delete('/sessions/:sessionId', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    // Nie pozwól na usunięcie bieżącej sesji
    if (req.params.sessionId === req.user.sessionId) {
      return res.status(400).json({
        success: false,
        error: 'Nie można usunąć bieżącej sesji'
      });
    }
    
    await user.deactivateSession(req.params.sessionId);
    
    res.json({
      success: true,
      message: 'Sesja została usunięta'
    });
    
  } catch (error) {
    console.error('Delete session error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/users/stats - Pobierz statystyki użytkownika
router.get('/stats', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (!user || !user.isActive) {
      return res.status(404).json({
        success: false,
        error: 'Użytkownik nie został znaleziony'
      });
    }
    
    // Pobierz informacje o tokenie
    const tokenDoc = await Token.findOne({ token: user.token });
    
    res.json({
      success: true,
      stats: {
        ...user.stats,
        documentsCount: user.activeDocuments.length,
        sessionsCount: user.sessions.filter(s => s.isActive).length,
        token: {
          remainingUses: tokenDoc ? tokenDoc.remainingUses : 0,
          totalUses: tokenDoc ? tokenDoc.usageCount : 0,
          used: tokenDoc ? tokenDoc.uses : 0
        }
      }
    });
    
  } catch (error) {
    console.error('Get user stats error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

module.exports = router;