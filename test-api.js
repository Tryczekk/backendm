const axios = require('axios');

// Konfiguracja
const API_URL = process.env.API_URL || 'http://localhost:3000';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Patrycjusz2134';

// Konfiguracja axios
const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json'
  }
});

async function testAPI() {
  console.log('🧪 Testowanie API Obywtel Backend');
  console.log(`📡 URL: ${API_URL}`);
  console.log('=' .repeat(50));

  try {
    // Test 1: Health check
    console.log('1️⃣  Test health check...');
    const healthResponse = await api.get('/');
    console.log('✅ Health check:', healthResponse.data.message);

    // Test 2: Pobierz tokeny
    console.log('\n2️⃣  Test pobierania tokenów...');
    const tokensResponse = await api.get('/api/tokens');
    console.log(`✅ Znaleziono ${tokensResponse.data.length} tokenów`);
    
    if (tokensResponse.data.length > 0) {
      const firstToken = tokensResponse.data[0];
      console.log(`   Pierwszy token: ${firstToken.token} (${firstToken.username})`);
    }

    // Test 3: Utw��rz nowy token
    console.log('\n3️⃣  Test tworzenia nowego tokenu...');
    const newTokenData = {
      username: 'Test API User',
      usageCount: 3,
      token: 'api' + Date.now().toString().slice(-4)
    };

    const createResponse = await api.post('/api/tokens', newTokenData);
    console.log('✅ Utworzono token:', createResponse.data.token.token);
    const createdTokenId = createResponse.data.token._id;

    // Test 4: Logowanie z nowym tokenem
    console.log('\n4️⃣  Test logowania...');
    const loginResponse = await api.post('/api/login', {
      token: createResponse.data.token.token
    });
    console.log('✅ Zalogowano pomyślnie:', loginResponse.data.user.username);
    
    // Zapisz cookie dla kolejnych żądań
    const cookies = loginResponse.headers['set-cookie'];
    if (cookies) {
      api.defaults.headers.Cookie = cookies.join('; ');
    }

    // Test 5: Pobierz dane użytkownika
    console.log('\n5️⃣  Test pobierania danych użytkownika...');
    const userResponse = await api.get('/api/me');
    console.log('✅ Dane użytkownika:', userResponse.data.user.username);

    // Test 6: Aktualizuj profil
    console.log('\n6️⃣  Test aktualizacji profilu...');
    const profileUpdate = {
      personalData: {
        firstName: 'Jan',
        lastName: 'Kowalski'
      }
    };
    const updateResponse = await api.put('/api/users/profile', profileUpdate);
    console.log('✅ Zaktualizowano profil:', updateResponse.data.user.fullName);

    // Test 7: Dodaj dokument
    console.log('\n7️⃣  Test dodawania dokumentu...');
    const documentData = {
      type: 'id',
      name: 'Dowód osobisty testowy',
      data: {
        number: 'ABC123456',
        issueDate: new Date().toISOString()
      }
    };
    const docResponse = await api.post('/api/users/documents', documentData);
    console.log('✅ Dodano dokument:', docResponse.data.document.name);

    // Test 8: Pobierz dokumenty
    console.log('\n8️⃣  Test pobierania dokumentów...');
    const docsResponse = await api.get('/api/users/documents');
    console.log(`✅ Znaleziono ${docsResponse.data.documents.length} dokumentów`);

    // Test 9: Wylogowanie
    console.log('\n9️⃣  Test wylogowania...');
    const logoutResponse = await api.post('/api/logout');
    console.log('✅ Wylogowano:', logoutResponse.data.message);

    // Test 10: Dezaktywuj token (wymaga uprawnień admin)
    console.log('\n🔟 Test dezaktywacji tokenu...');
    const deactivateResponse = await api.patch(`/api/tokens/${createdTokenId}/deactivate`);
    console.log('✅ Dezaktywowano token');

    // Test 11: Usuń token
    console.log('\n1️⃣1️⃣  Test usuwania tokenu...');
    const deleteResponse = await api.delete(`/api/tokens/${createdTokenId}`, {
      headers: {
        'x-admin-password': ADMIN_PASSWORD
      }
    });
    console.log('✅ Usunięto token');

    console.log('\n🎉 Wszystkie testy przeszły pomyślnie!');

  } catch (error) {
    console.error('\n❌ Błąd podczas testowania:', error.message);
    
    if (error.response) {
      console.error('Status:', error.response.status);
      console.error('Data:', error.response.data);
    }
    
    process.exit(1);
  }
}

// Uruchom testy jeśli skrypt jest wywoływany bezpośrednio
if (require.main === module) {
  testAPI();
}

module.exports = testAPI;