const jwt = require('jsonwebtoken');
const User = require('../models/user');
const Token = require('../models/token');

/**
 * Middleware do sprawdzania tokenu JWT
 */
const authenticateToken = async (req, res, next) => {
  try {
    const token = req.cookies.authToken || 
                  req.headers.authorization?.split(' ')[1] ||
                  req.headers['x-auth-token'];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Brak tokenu autoryzacji'
      });
    }
    
    // Weryfikuj JWT token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Sprawdź czy użytkownik nadal istnieje
    const user = await User.findById(decoded.userId);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        error: 'Użytkownik nie został znaleziony lub jest nieaktywny'
      });
    }
    
    // Sprawdź czy token użytkownika nadal jest aktywny
    const userToken = await Token.findOne({ token: decoded.token });
    if (!userToken || !userToken.active) {
      return res.status(401).json({
        success: false,
        error: 'Token użytkownika jest nieaktywny'
      });
    }
    
    // Sprawdź czy sesja jest aktywna
    const session = user.sessions.find(s => 
      s.sessionId === decoded.sessionId && s.isActive
    );
    
    if (!session) {
      return res.status(401).json({
        success: false,
        error: 'Sesja wygasła lub jest nieaktywna'
      });
    }
    
    // Aktualizuj aktywność sesji
    await user.updateSessionActivity(decoded.sessionId);
    
    // Dodaj dane użytkownika do request
    req.user = {
      ...decoded,
      userData: user
    };
    
    next();
    
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(403).json({
        success: false,
        error: 'Nieprawidłowy token autoryzacji'
      });
    }
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token autoryzacji wygasł'
      });
    }
    
    return res.status(500).json({
      success: false,
      error: 'Błąd weryfikacji tokenu'
    });
  }
};

/**
 * Middleware do sprawdzania uprawnień administratora
 */
const requireAdmin = (req, res, next) => {
  const adminPassword = req.headers['x-admin-password'] || 
                       req.body.adminPassword ||
                       req.query.adminPassword;
  
  if (!adminPassword) {
    return res.status(401).json({
      success: false,
      error: 'Brak hasła administratora'
    });
  }
  
  if (adminPassword !== process.env.ADMIN_PASSWORD) {
    return res.status(403).json({
      success: false,
      error: 'Nieprawidłowe hasło administratora'
    });
  }
  
  req.isAdmin = true;
  next();
};

/**
 * Middleware opcjonalnej autoryzacji (nie wymaga tokenu, ale jeśli jest to go weryfikuje)
 */
const optionalAuth = async (req, res, next) => {
  try {
    const token = req.cookies.authToken || 
                  req.headers.authorization?.split(' ')[1] ||
                  req.headers['x-auth-token'];
    
    if (!token) {
      req.user = null;
      return next();
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (user && user.isActive) {
      const userToken = await Token.findOne({ token: decoded.token });
      if (userToken && userToken.active) {
        const session = user.sessions.find(s => 
          s.sessionId === decoded.sessionId && s.isActive
        );
        
        if (session) {
          await user.updateSessionActivity(decoded.sessionId);
          req.user = {
            ...decoded,
            userData: user
          };
        }
      }
    }
    
    next();
    
  } catch (error) {
    // W przypadku błędu, po prostu kontynuuj bez autoryzacji
    req.user = null;
    next();
  }
};

/**
 * Middleware do sprawdzania czy użytkownik ma dostęp do zasobu
 */
const checkResourceAccess = (resourceField = 'userId') => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Wymagana autoryzacja'
      });
    }
    
    // Admin ma dostęp do wszystkiego
    if (req.isAdmin) {
      return next();
    }
    
    // Sprawdź czy użytkownik ma dostęp do zasobu
    const resourceUserId = req.params[resourceField] || req.body[resourceField];
    
    if (resourceUserId && resourceUserId !== req.user.userId) {
      return res.status(403).json({
        success: false,
        error: 'Brak uprawnień do tego zasobu'
      });
    }
    
    next();
  };
};

/**
 * Middleware do sprawdzania czy token nie został wyczerpany
 */
const checkTokenUsage = async (req, res, next) => {
  try {
    if (!req.user) {
      return next();
    }
    
    const userToken = await Token.findOne({ token: req.user.token });
    
    if (!userToken) {
      return res.status(401).json({
        success: false,
        error: 'Token nie został znaleziony'
      });
    }
    
    if (userToken.uses >= userToken.usageCount) {
      // Automatycznie dezaktywuj wyczerpany token
      userToken.active = false;
      await userToken.save();
      
      return res.status(401).json({
        success: false,
        error: 'Token został wyczerpany'
      });
    }
    
    req.tokenInfo = {
      remainingUses: userToken.remainingUses,
      totalUses: userToken.usageCount,
      used: userToken.uses
    };
    
    next();
    
  } catch (error) {
    console.error('Token usage check error:', error);
    res.status(500).json({
      success: false,
      error: 'Błąd sprawdzania tokenu'
    });
  }
};

/**
 * Middleware do logowania aktywności użytkownika
 */
const logUserActivity = (action) => {
  return async (req, res, next) => {
    try {
      if (req.user && req.user.userData) {
        // Tutaj można dodać logowanie do bazy danych lub pliku
        console.log(`User activity: ${req.user.username} performed ${action} at ${new Date().toISOString()}`);
        
        // Opcjonalnie: zapisz do bazy danych
        // await ActivityLog.create({
        //   userId: req.user.userId,
        //   action: action,
        //   timestamp: new Date(),
        //   ipAddress: req.ip,
        //   userAgent: req.headers['user-agent']
        // });
      }
      
      next();
      
    } catch (error) {
      console.error('Activity logging error:', error);
      // Nie blokuj żądania z powodu błędu logowania
      next();
    }
  };
};

module.exports = {
  authenticateToken,
  requireAdmin,
  optionalAuth,
  checkResourceAccess,
  checkTokenUsage,
  logUserActivity
};