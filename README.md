# Obywtel Backend

Backend API dla aplikacji Obywtel - system zarządzania tokenami i dowodami tożsamości.

## Funkcjonalności

- **Zarządzanie tokenami**: Tworzenie, aktywacja, dezaktywacja tokenów dostępu
- **Autoryzacja użytkowników**: System logowania oparty na tokenach
- **Zarządzanie dokumentami**: Dodawanie, edycja, usuwanie dokumentów użytkowników
- **Sesje użytkowników**: Zarządzanie sesjami i bezpieczeństwo
- **Panel administratora**: Pełne zarządzanie systemem

## Technologie

- **Node.js** - Runtime JavaScript
- **Express.js** - Framework webowy
- **MongoDB** - Baza danych NoSQL
- **Mongoose** - ODM dla MongoDB
- **JWT** - Tokeny autoryzacji
- **bcryptjs** - Hashowanie haseł
- **Helmet** - Bezpieczeństwo HTTP
- **CORS** - Cross-Origin Resource Sharing

## Instalacja

1. **Sklonuj repozytorium i przejdź do folderu backend:**
   ```bash
   cd backend
   ```

2. **Zainstaluj zależności:**
   ```bash
   npm install
   ```

3. **Skonfiguruj zmienne środowiskowe:**
   ```bash
   cp .env.example .env
   ```
   
   Edytuj plik `.env` i ustaw:
   - `MONGODB_URI` - URL do bazy MongoDB
   - `JWT_SECRET` - Sekretny klucz JWT
   - `ADMIN_PASSWORD` - Hasło administratora
   - `FRONTEND_URL` - URL frontendu

4. **Uruchom serwer:**
   ```bash
   # Tryb produkcyjny
   npm start
   
   # Tryb deweloperski (z nodemon)
   npm run dev
   ```

## Konfiguracja MongoDB

1. **Utwórz cluster na MongoDB Atlas:**
   - Przejdź na https://cloud.mongodb.com/
   - Utwórz nowy cluster
   - Skonfiguruj użytkownika bazy danych
   - Dodaj IP do whitelist (0.0.0.0/0 dla wszystkich IP)

2. **Skopiuj connection string:**
   ```
   mongodb+srv://username:password@cluster.mongodb.net/obywtel?retryWrites=true&w=majority
   ```

3. **Ustaw w pliku .env:**
   ```
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/obywtel?retryWrites=true&w=majority
   ```

## Deployment na Render.com

1. **Utwórz konto na Render.com**

2. **Połącz repozytorium:**
   - Kliknij "New +" → "Web Service"
   - Połącz swoje repozytorium GitHub
   - Wybierz folder `backend`

3. **Skonfiguruj deployment:**
   - **Name**: `obywtel-backend`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Root Directory**: `backend`

4. **Ustaw zmienne środowiskowe:**
   W sekcji "Environment" dodaj:
   ```
   NODE_ENV=production
   MONGODB_URI=your_mongodb_connection_string
   JWT_SECRET=your_super_secret_jwt_key
   ADMIN_PASSWORD=Patrycjusz2134
   FRONTEND_URL=https://your-frontend-domain.com
   PORT=3000
   ```

5. **Deploy:**
   - Kliknij "Create Web Service"
   - Poczekaj na zakończenie deploymentu

## API Endpoints

### Autoryzacja
- `POST /api/login` - Logowanie użytkownika
- `GET /api/me` - Pobierz dane zalogowanego użytkownika
- `POST /api/logout` - Wylogowanie
- `GET /api/verify` - Weryfikacja tokenu

### Tokeny (Admin)
- `GET /api/tokens` - Pobierz wszystkie tokeny
- `POST /api/tokens` - Utwórz nowy token
- `GET /api/tokens/active` - Pobierz aktywne tokeny
- `GET /api/tokens/inactive` - Pobierz nieaktywne tokeny
- `PATCH /api/tokens/:id/activate` - Aktywuj token
- `PATCH /api/tokens/:id/deactivate` - Dezaktywuj token
- `DELETE /api/tokens/:id` - Usuń token

### Użytkownicy
- `GET /api/users/profile` - Pobierz profil użytkownika
- `PUT /api/users/profile` - Aktualizuj profil
- `GET /api/users/documents` - Pobierz dokumenty
- `POST /api/users/documents` - Dodaj dokument
- `PUT /api/users/documents/:id` - Aktualizuj dokument
- `DELETE /api/users/documents/:id` - Usuń dokument
- `GET /api/users/sessions` - Pobierz sesje użytkownika

## Struktura projektu

```
backend/
├── models/           # Modele MongoDB
│   ├── Token.js     # Model tokenu
│   └── User.js      # Model użytkownika
├── routes/          # Endpointy API
│   ├── auth.js      # Autoryzacja
│   ├── tokens.js    # Zarządzanie tokenami
│   └── users.js     # Zarządzanie użytkownikami
├── middleware/      # Middleware
│   └── auth.js      # Middleware autoryzacji
├── utils/           # Funkcje pomocnicze
│   └── helpers.js   # Różne funkcje pomocnicze
├── server.js        # Główny plik serwera
├── package.json     # Zależności npm
└── .env.example     # Przykład konfiguracji
```

## Bezpieczeństwo

- **Rate limiting** - Ograniczenie liczby żądań
- **Helmet** - Zabezpieczenia HTTP headers
- **CORS** - Kontrola dostępu cross-origin
- **JWT** - Bezpieczne tokeny autoryzacji
- **Walidacja danych** - Express-validator
- **Sanityzacja** - Oczyszczanie danych wejściowych

## Monitoring i logi

Serwer loguje:
- Połączenia z bazą danych
- Błędy aplikacji
- Aktywność użytkowników
- Próby nieautoryzowanego dostępu

## Wsparcie

W przypadku problemów:
1. Sprawdź logi serwera
2. Zweryfikuj konfigurację zmiennych środowiskowych
3. Upewnij się, że MongoDB jest dostępne
4. Sprawdź konfigurację CORS

## Licencja

MIT License