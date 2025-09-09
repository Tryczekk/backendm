# Instrukcja Deploymentu - Obywtel Backend

## 1. Przygotowanie MongoDB Atlas

### Krok 1: Utwórz konto MongoDB Atlas
1. Przejdź na https://cloud.mongodb.com/
2. Zarejestruj się lub zaloguj
3. Kliknij "Create a New Cluster"

### Krok 2: Konfiguracja klastra
1. Wybierz **FREE tier** (M0 Sandbox)
2. Wybierz region (najlepiej najbliższy Twojej lokalizacji)
3. Nazwij klaster np. "obywtel-cluster"
4. Kliknij "Create Cluster"

### Krok 3: Konfiguracja dostępu
1. **Database Access:**
   - Kliknij "Database Access" w menu
   - Kliknij "Add New Database User"
   - Utwórz użytkownika z hasłem
   - Nadaj uprawnienia "Read and write to any database"

2. **Network Access:**
   - Kliknij "Network Access" w menu
   - Kliknij "Add IP Address"
   - Wybierz "Allow Access from Anywhere" (0.0.0.0/0)
   - Lub dodaj konkretne IP Render.com

### Krok 4: Pobierz Connection String
1. Kliknij "Connect" przy swoim klastrze
2. Wybierz "Connect your application"
3. Skopiuj connection string:
   ```
   mongodb+srv://username:password@cluster.mongodb.net/obywtel?retryWrites=true&w=majority
   ```

## 2. Deployment na Render.com

### Krok 1: Przygotuj repozytorium
1. Utwórz repozytorium na GitHub
2. Prześlij kod backendu do folderu `backend/`
3. Upewnij się, że wszystkie pliki są w repozytorium

### Krok 2: Utwórz Web Service na Render
1. Przejdź na https://render.com/
2. Zarejestruj się i zaloguj
3. Kliknij "New +" → "Web Service"
4. Połącz swoje repozytorium GitHub

### Krok 3: Konfiguracja serwisu
Wypełnij formularz:

- **Name**: `obywtel-backend`
- **Environment**: `Node`
- **Region**: Wybierz najbliższy region
- **Branch**: `main` (lub `master`)
- **Root Directory**: `backend`
- **Build Command**: `npm install`
- **Start Command**: `npm start`

### Krok 4: Zmienne środowiskowe
W sekcji "Environment Variables" dodaj:

```
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/obywtel?retryWrites=true&w=majority
JWT_SECRET=your-super-secret-jwt-key-min-32-characters-long
ADMIN_PASSWORD=Patrycjusz2134
FRONTEND_URL=https://your-frontend-domain.com
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

**⚠️ WAŻNE:** 
- Zamień `username:password` w MONGODB_URI na swoje dane
- Wygeneruj bezpieczny JWT_SECRET (min. 32 znaki)
- Ustaw prawidłowy FRONTEND_URL

### Krok 5: Deploy
1. Kliknij "Create Web Service"
2. Poczekaj na zakończenie deploymentu (5-10 minut)
3. Skopiuj URL serwisu (np. `https://obywtel-backend.onrender.com`)

## 3. Testowanie Deploymentu

### Test 1: Health Check
Otwórz w przeglądarce:
```
https://your-backend-url.onrender.com/
```

Powinieneś zobaczyć:
```json
{
  "message": "Obywtel Backend API",
  "status": "running",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "version": "1.0.0"
}
```

### Test 2: API Endpoints
Przetestuj podstawowe endpointy:
```bash
# Pobierz tokeny
curl https://your-backend-url.onrender.com/api/tokens

# Test logowania (jeśli masz token)
curl -X POST https://your-backend-url.onrender.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"token":"your-token"}'
```

## 4. Inicjalizacja Bazy Danych

Po deploymencie zainicjalizuj bazę danych:

### Opcja 1: Przez Render Shell
1. W panelu Render kliknij "Shell" przy swoim serwisie
2. Uruchom: `npm run init-db`

### Opcja 2: Lokalnie
1. Ustaw zmienne środowiskowe lokalnie
2. Uruchom: `npm run init-db`

## 5. Aktualizacja Frontendu

Zaktualizuj URL API w plikach frontendu:

```javascript
// Zmień z:
const API_URL = 'https://backendm-9np8.onrender.com';

// Na:
const API_URL = 'https://your-backend-url.onrender.com';
```

Pliki do aktualizacji:
- `index.html`
- `tokens.html`
- Inne pliki zawierające API_URL

## 6. Monitorowanie

### Logi
- W panelu Render kliknij "Logs" aby zobaczyć logi serwera
- Monitoruj błędy i wydajność

### Metryki
- Render pokazuje metryki CPU, pamięci i ruchu
- Monitoruj wykorzystanie zasobów

## 7. Rozwiązywanie Problemów

### Problem: Serwer nie startuje
**Rozwiązanie:**
1. Sprawdź logi w panelu Render
2. Zweryfikuj zmienne środowiskowe
3. Upewnij się, że `package.json` ma prawidłowy `start` script

### Problem: Błąd połączenia z MongoDB
**Rozwiązanie:**
1. Sprawdź MONGODB_URI
2. Zweryfikuj dane logowania w MongoDB Atlas
3. Sprawdź Network Access w MongoDB Atlas

### Problem: CORS errors
**Rozwiązanie:**
1. Ustaw prawidłowy FRONTEND_URL
2. Sprawdź konfigurację CORS w `server.js`

### Problem: 503 Service Unavailable
**Rozwiązanie:**
1. Render może potrzebować czasu na "rozgrzanie"
2. Sprawdź czy serwis nie jest w trybie sleep
3. Zweryfikuj health check endpoint

## 8. Bezpieczeństwo

### Produkcja
- Zmień ADMIN_PASSWORD na bezpieczne hasło
- Wygeneruj nowy JWT_SECRET
- Ogranicz CORS do konkretnych domen
- Monitoruj logi pod kątem podejrzanej aktywności

### Backup
- MongoDB Atlas automatycznie tworzy backupy
- Rozważ eksport danych regularnie

## 9. Skalowanie

### Free Tier Limitations
- Render Free: 750 godzin/miesiąc
- MongoDB Atlas Free: 512MB storage
- Automatyczne usypianie po 15 min nieaktywności

### Upgrade
Gdy aplikacja rośnie, rozważ:
- Render Starter Plan ($7/miesiąc)
- MongoDB Atlas Shared Cluster ($9/miesiąc)

## 10. Wsparcie

W przypadku problemów:
1. Sprawdź dokumentację Render.com
2. Sprawdź dokumentację MongoDB Atlas
3. Przejrzyj logi aplikacji
4. Skontaktuj się z supportem platform