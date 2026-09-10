# CyberArena

Platforma edukacyjna cyberbezpieczeństwa: moduły, testy, laboratoria (CTF-style),
konkursy, XP, ranking, odznaki. Frontend to pojedynczy plik `frontend/index.html`
(HTML/CSS/JS, bez frameworków). Cała logika bezpieczeństwa, konta, role,
uprawnienia i dane żyją w prawdziwym backendzie (Node.js/Express + PostgreSQL) —
frontend nigdy nie przechowuje haseł ani nie autoryzuje samodzielnie.

## Struktura projektu

```
cyberarena/
├── backend/
│   ├── src/
│   │   ├── config/         env.js, db.js (pula połączeń PostgreSQL)
│   │   ├── middleware/     auth.js, permissions.js, rateLimiters.js, errorHandler.js
│   │   ├── routes/         auth, me, modules, tests, labs, contests, ranking, admin
│   │   ├── utils/          audit.js (logi bezpieczeństwa), xp.js, validate.js (zod)
│   │   ├── app.js          konfiguracja Express (helmet, CORS, sesje)
│   │   └── server.js       punkt wejścia
│   ├── db/
│   │   ├── migrations/001_init.sql
│   │   ├── migrate.js      uruchamia migracje idempotentnie
│   │   └── seed.js         tworzy konto admina + odznaki startowe
│   ├── package.json
│   ├── .env.example
│   └── .gitignore
├── frontend/
│   └── index.html          cały frontend w jednym pliku
├── deploy/
│   ├── nginx.conf.example
│   └── cyberarena-backend.service.example
└── README.md
```

## Wymagania

- Node.js ≥ 18
- PostgreSQL ≥ 14

## Uruchomienie lokalne (development)

```bash
cd backend
cp .env.example .env
# Wygeneruj losowy SESSION_SECRET:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Wklej wynik do .env jako SESSION_SECRET. Uzupełnij też DATABASE_URL.

npm install
createdb cyberarena           # lub odpowiednik w Twoim kliencie PostgreSQL
npm run migrate               # tworzy schemat + tabelę sesji
npm run seed                  # tworzy konto admin/admin (wymusza zmianę hasła)
npm run dev
```

Backend nasłuchuje domyślnie na `http://localhost:4000`. Otwórz
`frontend/index.html` przez dowolny lokalny serwer statyczny (np.
`npx serve frontend`) i ustaw `FRONTEND_ORIGIN` w `.env` na jego adres, żeby
CORS + ciasteczka sesji działały poprawnie. W produkcji frontend i `/api` są
serwowane z tej samej domeny przez nginx (patrz niżej), więc CORS praktycznie
nie wchodzi w grę poza środowiskiem deweloperskim.

## Pierwsze logowanie administratora

- Login: `admin`
- Hasło: wartość `ADMIN_INITIAL_PASSWORD` z `.env` (domyślnie `admin` — **zmień
  to w produkcji przed pierwszym seedem**, mimo że i tak wymuszona jest zmiana
  hasła przy pierwszym logowaniu).

Po zalogowaniu aplikacja automatycznie pokaże ekran wymuszonej zmiany hasła —
nie da się z niego pominąć bez ustawienia nowego hasła.

## Wdrożenie produkcyjne

1. **Baza danych**: dedykowany użytkownik PostgreSQL z ograniczonymi
   uprawnieniami (tylko do bazy `cyberarena`), połączenie po `DATABASE_URL`.
   Jeśli baza jest zdalna, ustaw `PGSSL=true`.
2. **Sekrety**: nigdy w kodzie ani w repozytorium. Wypełnij `.env` na
   serwerze; `.env` jest w `.gitignore`. `SESSION_SECRET` musi być losowy i
   długi (patrz komenda wyżej).
3. **Migracje + seed**: `npm run migrate && npm run seed` na serwerze
   docelowym, jednorazowo.
4. **Proces backendu**: uruchamiaj przez menedżera procesów, nie `node`
   bezpośrednio w terminalu. Przykładowy unit systemd:
   `deploy/cyberarena-backend.service.example` (skopiuj do
   `/etc/systemd/system/cyberarena-backend.service`, dostosuj ścieżki,
   `systemctl enable --now cyberarena-backend`).
5. **HTTPS + reverse proxy**: przykładowa konfiguracja nginx w
   `deploy/nginx.conf.example` — serwuje `frontend/index.html` statycznie i
   proxuje `/api/*` do lokalnego Express (`127.0.0.1:4000`). Certyfikat np.
   przez `certbot --nginx`.
6. **Zmienne produkcyjne**: `NODE_ENV=production`, `FRONTEND_ORIGIN` ustawione
   na realną domenę HTTPS (sesyjne ciasteczko ma wtedy `Secure` wymuszone).
7. **Kopie zapasowe**: skonfiguruj regularny `pg_dump` bazy `cyberarena` poza
   zakresem tego repo.

## Model bezpieczeństwa (skrót)

- **Hasła**: Argon2id, nigdy plaintext, minimalna długość 10 znaków
  (walidowana po stronie klienta *i* serwera przez zod).
- **Sesje**: przechowywane w PostgreSQL (`connect-pg-simple`), ciasteczko
  `HttpOnly`, `Secure` (produkcja), `SameSite=Strict`, regenerowane przy
  logowaniu/rejestracji (ochrona przed session fixation), z możliwością
  wylogowania wszystkich sesji naraz (`/api/auth/logout-all`).
- **Brute force**: `express-rate-limit` na `/api/auth/login` (domyślnie 5
  prób/15 min, kluczowane po IP + identyfikatorze), oraz blokada konta na 15
  minut po 5 nieudanych próbach z rzędu, zapisywana w bazie.
- **Role i uprawnienia**: rola (`user`/`employee`/`admin`) i granularne
  uprawnienia pracownika są odczytywane z bazy przy **każdym** żądaniu
  (`src/middleware/auth.js`, `src/middleware/permissions.js`) — frontend nie
  ma możliwości "podszycia się" pod wyższą rolę, bo backend nigdy nie ufa
  polom przesłanym przez klienta w tym zakresie.
- **SQL injection**: wyłącznie zapytania parametryzowane (`pg` z `$1, $2…`),
  zero konkatenacji stringów w SQL.
- **XSS**: cały tekst pochodzący od użytkownika jest renderowany przez
  `escapeHtml()` po stronie frontendu; `Content-Security-Policy` (helmet)
  blokuje inline-skrypty i zasoby spoza własnej domeny.
- **CSRF**: `SameSite=Strict` na ciasteczku sesji jako podstawowa obrona
  (ciasteczko nie jest wysyłane przy żądaniach cross-site).
- **IDOR**: każdy endpoint operujący na zasobie użytkownika filtruje po
  `req.user.id` z sesji, nigdy po ID przesłanym w body/query.
- **Mass assignment**: każdy endpoint POST/PUT waliduje wejście przez
  jawny schemat `zod` — nie ma generycznego `Object.assign(model, req.body)`.
- **Logi bezpieczeństwa**: tabela `security_logs` zapisuje logowania
  (udane/nieudane), blokady, zmiany haseł/uprawnień, tworzenie pracowników,
  usuwanie treści i przekroczenia rate limitu — nigdy hasła ani sekrety.

## Laboratoria — ważna uwaga architektoniczna

Obecna implementacja laboratoriów jest **opisowo-flagowa** (styl CTF): user
czyta instrukcję i przesyła flagę, którą backend weryfikuje przez
`argon2.verify` względem zahashowanej wartości w bazie. Żaden kod użytkownika
nie jest wykonywany na serwerze aplikacji.

Jeśli w przyszłości platforma ma faktycznie **uruchamiać kod dostarczony przez
użytkownika** (np. sandboxowe środowisko do ćwiczeń Python/Linux), to musi to
być osobny, odizolowany serwis wykonawczy — nigdy w tym samym procesie co
backend API. Rekomendowany kierunek: kontenery jednorazowe (np. Docker
`--network=none`, limity `--memory`, `--cpus`, `--pids-limit`, brak dostępu do
sieci hosta) uruchamiane przez osobną kolejkę zadań, z twardym limitem czasu i
rozmiaru logów. To celowo wykracza poza zakres tego repo — wymaga osobnej
analizy bezpieczeństwa (unikanie ucieczki z kontenera, DoS przez zasoby,
nadużycie do ataków na inne systemy).

## Skrót API

| Endpoint | Opis |
|---|---|
| `POST /api/auth/register` | Rejestracja + automatyczne zalogowanie |
| `POST /api/auth/login` | Logowanie |
| `POST /api/auth/logout` | Wylogowanie bieżącej sesji |
| `POST /api/auth/logout-all` | Wylogowanie wszystkich sesji użytkownika |
| `POST /api/auth/change-password` | Zmiana hasła (wymaga aktualnego) |
| `GET /api/me` | Bieżący użytkownik + uprawnienia |
| `GET /api/me/dashboard` | Dane pulpitu użytkownika |
| `GET/POST/PUT/DELETE /api/modules[/:id]` | Moduły + `/complete` |
| `GET/POST/DELETE /api/tests[/:id]` | Testy + `/submit` (ocena wyłącznie po stronie serwera) |
| `GET/POST/DELETE /api/labs[/:id]` | Laby + `/submit` (flaga) |
| `GET/POST/DELETE /api/contests[/:id]` | Konkursy + `/tasks/:id/submit` |
| `GET /api/ranking` | Globalny ranking XP |
| `GET /api/admin/dashboard` | Statystyki platformy |
| `GET/PUT /api/admin/users[...]` | Zarządzanie użytkownikami |
| `GET/POST/PUT/DELETE /api/admin/employees[...]` | Zarządzanie pracownikami i uprawnieniami |
| `GET /api/admin/security-logs` | Logi bezpieczeństwa |
| `GET/PUT /api/admin/settings[/:key]` | Ustawienia systemowe |

Pełne szczegóły (schematy walidacji, kody błędów) — patrz kod źródłowy w
`backend/src/routes/`.
