const mongoose = require('mongoose');
const Token = require('../models/Token');
const User = require('../models/User');
require('dotenv').config();

async function initializeDatabase() {
  try {
    console.log('Łączenie z bazą danych...');
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Połączono z MongoDB');

    // Sprawdź czy istnieją już jakieś tokeny
    const existingTokens = await Token.countDocuments();
    
    if (existingTokens === 0) {
      console.log('Tworzenie przykładowych tokenów...');
      
      // Utwórz kilka przykładowych tokenów
      const sampleTokens = [
        {
          token: 'demo',
          username: 'Demo User',
          usageCount: 10,
          uses: 0,
          active: true
        },
        {
          token: 'test',
          username: 'Test User',
          usageCount: 5,
          uses: 0,
          active: true
        },
        {
          token: 'admin',
          username: 'Administrator',
          usageCount: 100,
          uses: 0,
          active: true
        }
      ];

      for (const tokenData of sampleTokens) {
        try {
          const token = new Token(tokenData);
          await token.save();
          console.log(`✓ Utworzono token: ${tokenData.token}`);
        } catch (error) {
          if (error.code === 11000) {
            console.log(`- Token ${tokenData.token} już istnieje`);
          } else {
            console.error(`✗ Błąd tworzenia tokenu ${tokenData.token}:`, error.message);
          }
        }
      }
    } else {
      console.log(`Znaleziono ${existingTokens} istniejących tokenów`);
    }

    // Sprawdź indeksy
    console.log('Sprawdzanie indeksów...');
    await Token.createIndexes();
    await User.createIndexes();
    console.log('✓ Indeksy zostały utworzone/zaktualizowane');

    console.log('✅ Inicjalizacja bazy danych zakończona pomyślnie');
    
  } catch (error) {
    console.error('❌ Błąd inicjalizacji bazy danych:', error);
    process.exit(1);
  } finally {
    await mongoose.connection.close();
    console.log('Połączenie z bazą danych zostało zamknięte');
  }
}

// Uruchom inicjalizację jeśli skrypt jest wywoływany bezpośrednio
if (require.main === module) {
  initializeDatabase();
}

module.exports = initializeDatabase;