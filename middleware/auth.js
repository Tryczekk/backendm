const express = require('express');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const Token = require('../models/Token');
const User = require('../models/User');
const { generateSessionId } = require('../utils/helpers');

const router = express.Router();

// Verify admin access - zawsze zwraca true
router.post('/verify-admin', (req, res) => {
  res.json({
    success: true,
    isAdmin: true
  });
});

// Check session endpoint - zawsze zwraca success
router.get('/check-session', (req, res) => {
  res.json({
    success: true,
    user: {
      isAdmin: true
    }
  });
});

// Middleware bez weryfikacji
const authenticateToken = (req, res, next) => {
  req.user = { isAdmin: true };
  next();
};

// POST /api/login - Logowanie użytkownika (bez weryfikacji)
router.post('/login', (req, res) => {
  res.json({
    success: true,
    isAdmin: true,
    message: 'Zalogowano pomyślnie',
    user: {
      isAdmin: true
    }
  });
        details: errors.array()
      });
    }

    const { token } = req.body;
    
    // Znajdź token w bazie danych
    const tokenDoc = await Token.findOne({ token, active: true });
    
    if (!tokenDoc) {
      return res.status(401).json({
        success: false,
        error: 'Nieprawidłowy token'
      });
    }
    
    // Sprawdź czy token nie został wyczerpany
    if (tokenDoc.uses >= tokenDoc.usageCount) {
      // Automatycznie dezaktywuj wyczerpany token
      tokenDoc.active = false;
      await tokenDoc.save();
      
      return res.status(401).json({
        success: false,
        error: 'Token został wyczerpany'
      });
    }
    
    // Użyj token (zwiększ licznik użyć)
    const sessionId = generateSessionId();
    const sessionData = {
      sessionId,
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip || req.connection.remoteAddress
    };
    
    await tokenDoc.useToken(sessionData);
    
    // Znajdź lub stwórz użytkownika
    let user = await User.findByToken(token);
    
    if (!user) {
      user = new User({
        username: tokenDoc.username,
        token: token,
        stats: {
          loginCount: 1,
          lastLogin: new Date()
        }
      });
      await user.save();
    } else {
      // Aktualizuj statystyki logowania
      await user.updateLoginStats();
      await user.addSession(sessionData);
    }
    
    // Stwórz JWT token
    const jwtToken = jwt.sign(
      { 
        userId: user._id,
        username: user.username,
        token: token,
        sessionId: sessionId
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Ustaw cookie z tokenem
    res.cookie('authToken', jwtToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 godziny
    });
    
    res.json({
      success: true,
      message: 'Zalogowano pomyślnie',
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        remainingUses: tokenDoc.remainingUses
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/me - Pobierz dane zalogowanego użytkownika
router.get('/me', authenticateToken, async (req, res) => {
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
    
    // Pobierz informacje o tokenie
    const tokenDoc = await Token.findOne({ token: user.token });
    
    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        fullName: user.fullName,
        personalData: user.personalData,
        documents: user.activeDocuments,
        settings: user.settings,
        stats: user.stats,
        token: {
          remainingUses: tokenDoc ? tokenDoc.remainingUses : 0,
          totalUses: tokenDoc ? tokenDoc.usageCount : 0,
          used: tokenDoc ? tokenDoc.uses : 0
        }
      }
    });
    
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// POST /api/logout - Wylogowanie użytkownika
router.post('/logout', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (user) {
      // Dezaktywuj sesję
      await user.deactivateSession(req.user.sessionId);
    }
    
    // Usuń cookie
    res.clearCookie('authToken');
    
    res.json({
      success: true,
      message: 'Wylogowano pomyślnie'
    });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// POST /api/logout-all - Wylogowanie ze wszystkich sesji
router.post('/logout-all', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    
    if (user) {
      // Dezaktywuj wszystkie sesje
      await user.deactivateAllSessions();
    }
    
    // Usuń cookie
    res.clearCookie('authToken');
    
    res.json({
      success: true,
      message: 'Wylogowano ze wszystkich sesji'
    });
    
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

// GET /api/verify - Sprawdź czy token jest ważny
router.get('/verify', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const tokenDoc = await Token.findOne({ token: req.user.token });
    
    if (!user || !user.isActive || !tokenDoc || !tokenDoc.active) {
      return res.status(401).json({
        success: false,
        error: 'Token nieważny'
      });
    }
    
    res.json({
      success: true,
      valid: true,
      user: {
        id: user._id,
        username: user.username
      }
    });
    
  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).json({
      success: false,
      error: 'Wewnętrzny błąd serwera'
    });
  }
});

module.exports = router;
