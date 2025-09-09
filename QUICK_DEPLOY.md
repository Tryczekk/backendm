# 🚀 Szybki Deploy - Obywtel Backend

## Twoje dane konfiguracyjne:
- **MongoDB**: `mongodb+srv://privny0:Patrycjusz2134@cluster0.gvzdl4i.mongodb.net/dowodzik`
- **Frontend**: `https://xyzobywatel404.netlify.app`
- **Admin Password**: `Patrycjusz2134`

## 1. Przygotowanie do deploymentu

### Krok 1: Sprawdź czy wszystko działa lokalnie
```bash
cd backend
npm install
npm run init-db
npm run dev
```

### Krok 2: Przetestuj API
```bash
npm run test-api
```

## 2. Deploy na Render.com

### Krok 1: Utwórz Web Service
1. Idź na https://render.com/
2. Zaloguj się/Zarejestruj
3. Kliknij "New +" → "Web Service"
4. Połącz swoje repozytorium GitHub

### Krok 2: Konfiguracja serwisu
```
Name: obywtel-backend
Environment: Node
Region: Frankfurt (EU Central)
Branch: main
Root Directory: backend
Build Command: npm install
Start Command: npm start
```

### Krok 3: Zmienne środowiskowe
Dodaj te zmienne w sekcji "Environment Variables":

```
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://privny0:Patrycjusz2134@cluster0.gvzdl4i.mongodb.net/dowodzik?retryWrites=true&w=majority
JWT_SECRET=obywtel-super-secret-jwt-key-2024-production-safe-key-min-32-chars
ADMIN_PASSWORD=Patrycjusz2134
FRONTEND_URL=https://xyzobywatel404.netlify.app
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

### Krok 4: Deploy
1. Kliknij "Create Web Service"
2. Poczekaj 5-10 minut na deployment
3. Skopiuj URL (np. `https://obywtel-backend-xyz.onrender.com`)

## 3. Aktualizacja Frontendu

Po deploymencie backendu, zaktualizuj URL API w swoich plikach HTML:

### Pliki do edycji:
- `index.html`
- `tokens.html`
- Wszystkie inne pliki zawierające `API_URL`

### Zmiana:
```javascript
// Znajdź linię:
const API_URL = 'https://backendm-9np8.onrender.com';

// Zamień na:
const API_URL = 'https://twoj-nowy-backend-url.onrender.com';
```

## 4. Test po deploymencie

### Test 1: Health Check
Otwórz w przeglądarce:
```
https://twoj-backend-url.onrender.com/
```

### Test 2: Tokeny
```
https://twoj-backend-url.onrender.com/api/tokens
```

### Test 3: Frontend
1. Otwórz `https://xyzobywatel404.netlify.app`
2. Spróbuj się zalogować
3. Sprawdź czy panel administratora działa

## 5. Inicjalizacja bazy danych

Po deploymencie zainicjalizuj baz��:

### Opcja 1: Render Shell
1. W panelu Render kliknij "Shell"
2. Uruchom: `npm run init-db`

### Opcja 2: Lokalnie
```bash
# Ustaw zmienne środowiskowe
export MONGODB_URI="mongodb+srv://privny0:Patrycjusz2134@cluster0.gvzdl4i.mongodb.net/dowodzik?retryWrites=true&w=majority"

# Uruchom inicjalizację
npm run init-db
```

## 6. Przykładowe tokeny

Po inicjalizacji będziesz miał dostępne tokeny:
- `demo` - Demo User (10 użyć)
- `test` - Test User (5 użyć)  
- `admin` - Administrator (100 użyć)

## 7. Panel administratora

Dostęp do panelu admin:
1. Idź na `https://xyzobywatel404.netlify.app`
2. Kliknij "Login administratora"
3. Wprowadź hasło: `Patrycjusz2134`
4. Lub użyj skrótu: `Ctrl+Shift+A` → kliknij "Generator Tokenu"

## 8. Rozwiązywanie problemów

### Problem: CORS error
**Rozwiązanie**: Sprawdź czy FRONTEND_URL jest ustawiony na `https://xyzobywatel404.netlify.app`

### Problem: MongoDB connection error
**Rozwiązanie**: Sprawdź czy MONGODB_URI jest poprawny i czy IP jest w whitelist MongoDB Atlas

### Problem: 503 Service Unavailable
**Rozwiązanie**: Render potrzebuje czasu na "rozgrzanie" - odczekaj 1-2 minuty

## 9. Monitoring

### Logi Render
- Panel Render → Twój serwis → "Logs"
- Monitoruj błędy i wydajność

### MongoDB Atlas
- Panel MongoDB Atlas → Monitoring
- Sprawdzaj połączenia i wydajność

## 10. Następne kroki

Po udanym deploymencie:
1. ✅ Przetestuj wszystkie funkcjonalności
2. ✅ Sprawdź logowanie użytkowników
3. ✅ Przetestuj panel administratora
4. ✅ Sprawdź tworzenie tokenów
5. ✅ Zweryfikuj zarządzanie dokumentami

## 🎉 Gotowe!

Twój backend jest teraz gotowy do użycia z frontendem na Netlify!