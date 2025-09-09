const crypto = require('crypto');

/**
 * Generuje losowy token o określonej długości
 * @param {number} length - Długość tokenu (domyślnie 4)
 * @returns {string} - Wygenerowany token
 */
function generateToken(length = 4) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  
  return result;
}

/**
 * Generuje bezpieczny token kryptograficzny
 * @param {number} length - Długość tokenu w bajtach (domyślnie 16)
 * @returns {string} - Wygenerowany token w formacie hex
 */
function generateSecureToken(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generuje unikalny identyfikator sesji
 * @returns {string} - Identyfikator sesji
 */
function generateSessionId() {
  return `sess_${Date.now()}_${generateSecureToken(8)}`;
}

/**
 * Waliduje format PESEL
 * @param {string} pesel - Numer PESEL do walidacji
 * @returns {boolean} - True jeśli PESEL jest prawidłowy
 */
function validatePesel(pesel) {
  if (!pesel || typeof pesel !== 'string' || pesel.length !== 11) {
    return false;
  }
  
  // Sprawdź czy składa się tylko z cyfr
  if (!/^\d{11}$/.test(pesel)) {
    return false;
  }
  
  // Sprawdź sumę kontrolną
  const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  let sum = 0;
  
  for (let i = 0; i < 10; i++) {
    sum += parseInt(pesel[i]) * weights[i];
  }
  
  const checksum = (10 - (sum % 10)) % 10;
  return checksum === parseInt(pesel[10]);
}

/**
 * Formatuje datę do polskiego formatu
 * @param {Date} date - Data do sformatowania
 * @returns {string} - Sformatowana data
 */
function formatPolishDate(date) {
  if (!date) return '';
  
  const d = new Date(date);
  return d.toLocaleDateString('pl-PL', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
}

/**
 * Parsuje datę urodzenia z numeru PESEL
 * @param {string} pesel - Numer PESEL
 * @returns {Date|null} - Data urodzenia lub null jeśli błąd
 */
function parseBirthDateFromPesel(pesel) {
  if (!validatePesel(pesel)) {
    return null;
  }
  
  let year = parseInt(pesel.substring(0, 2));
  let month = parseInt(pesel.substring(2, 4));
  const day = parseInt(pesel.substring(4, 6));
  
  // Określ wiek na podstawie miesiąca
  if (month > 80) {
    year += 1800;
    month -= 80;
  } else if (month > 60) {
    year += 2200;
    month -= 60;
  } else if (month > 40) {
    year += 2100;
    month -= 40;
  } else if (month > 20) {
    year += 2000;
    month -= 20;
  } else {
    year += 1900;
  }
  
  return new Date(year, month - 1, day);
}

/**
 * Sprawdza czy użytkownik jest pełnoletni na podstawie PESEL
 * @param {string} pesel - Numer PESEL
 * @returns {boolean} - True jeśli pełnoletni
 */
function isAdult(pesel) {
  const birthDate = parseBirthDateFromPesel(pesel);
  if (!birthDate) return false;
  
  const today = new Date();
  const age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    return age - 1 >= 18;
  }
  
  return age >= 18;
}

/**
 * Sanityzuje dane wejściowe usuwając potencjalnie niebezpieczne znaki
 * @param {string} input - Tekst do sanityzacji
 * @returns {string} - Sanityzowany tekst
 */
function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  
  return input
    .trim()
    .replace(/[<>\"'&]/g, '') // Usuń podstawowe znaki HTML/JS
    .substring(0, 1000); // Ogranicz długość
}

/**
 * Generuje hash z danych (dla porównań)
 * @param {string} data - Dane do zahashowania
 * @returns {string} - Hash SHA-256
 */
function generateHash(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Sprawdza siłę hasła
 * @param {string} password - Hasło do sprawdzenia
 * @returns {object} - Obiekt z oceną siły hasła
 */
function checkPasswordStrength(password) {
  if (!password) {
    return { score: 0, feedback: 'Hasło jest wymagane' };
  }
  
  let score = 0;
  const feedback = [];
  
  // Długość
  if (password.length >= 8) score += 1;
  else feedback.push('Hasło powinno mieć co najmniej 8 znaków');
  
  // Małe litery
  if (/[a-z]/.test(password)) score += 1;
  else feedback.push('Dodaj małe litery');
  
  // Wielkie litery
  if (/[A-Z]/.test(password)) score += 1;
  else feedback.push('Dodaj wielkie litery');
  
  // Cyfry
  if (/\d/.test(password)) score += 1;
  else feedback.push('Dodaj cyfry');
  
  // Znaki specjalne
  if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 1;
  else feedback.push('Dodaj znaki specjalne');
  
  const strength = ['Bardzo słabe', 'Słabe', 'Średnie', 'Dobre', 'Bardzo dobre'][score];
  
  return {
    score,
    strength,
    feedback: feedback.length > 0 ? feedback : ['Hasło jest silne']
  };
}

/**
 * Formatuje rozmiar pliku do czytelnej formy
 * @param {number} bytes - Rozmiar w bajtach
 * @returns {string} - Sformatowany rozmiar
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Sprawdza czy string jest prawidłowym URL
 * @param {string} string - String do sprawdzenia
 * @returns {boolean} - True jeśli to prawidłowy URL
 */
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

/**
 * Opóźnia wykonanie o określony czas (dla rate limiting)
 * @param {number} ms - Czas opóźnienia w milisekundach
 * @returns {Promise} - Promise który resolve'uje się po określonym czasie
 */
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Sprawdza czy adres email jest prawidłowy
 * @param {string} email - Adres email do sprawdzenia
 * @returns {boolean} - True jeśli email jest prawidłowy
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Generuje losowy kolor w formacie hex
 * @returns {string} - Kolor w formacie #RRGGBB
 */
function generateRandomColor() {
  return '#' + Math.floor(Math.random() * 16777215).toString(16).padStart(6, '0');
}

module.exports = {
  generateToken,
  generateSecureToken,
  generateSessionId,
  validatePesel,
  formatPolishDate,
  parseBirthDateFromPesel,
  isAdult,
  sanitizeInput,
  generateHash,
  checkPasswordStrength,
  formatFileSize,
  isValidUrl,
  delay,
  isValidEmail,
  generateRandomColor
};