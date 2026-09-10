-- CyberArena — schemat początkowy
-- Uruchamiane przez db/migrate.js (idempotentnie, w transakcji)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============ UŻYTKOWNICY I ROLE ============

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username            VARCHAR(32) UNIQUE NOT NULL,
    email               VARCHAR(255) UNIQUE NOT NULL,
    password_hash       TEXT NOT NULL,
    role                VARCHAR(16) NOT NULL DEFAULT 'user'
                            CHECK (role IN ('user', 'employee', 'admin')),
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    is_blocked          BOOLEAN NOT NULL DEFAULT FALSE,
    xp                  INTEGER NOT NULL DEFAULT 0,
    level               INTEGER NOT NULL DEFAULT 1,
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_xp ON users(xp DESC);

-- Granularne uprawnienia przypisane pracownikom (rola 'employee').
-- Adminowi uprawnienia nie są wymagane — ma pełny dostęp zawsze (sprawdzane w kodzie, nie tylko tu).
CREATE TABLE IF NOT EXISTS user_permissions (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission  VARCHAR(64) NOT NULL,
    granted_by  UUID REFERENCES users(id),
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, permission)
);

-- express-session + connect-pg-simple store
CREATE TABLE IF NOT EXISTS session (
    sid    VARCHAR NOT NULL COLLATE "default" PRIMARY KEY,
    sess   JSON NOT NULL,
    expire TIMESTAMP(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_expire ON session(expire);

-- ============ MODUŁY, LEKCJE, PYTANIA ============

CREATE TABLE IF NOT EXISTS modules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        VARCHAR(160) NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    difficulty   VARCHAR(16) NOT NULL DEFAULT 'beginner'
                     CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
    image_url    TEXT,
    xp_reward    INTEGER NOT NULL DEFAULT 50,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    created_by   UUID REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lessons (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id   UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    title       VARCHAR(160) NOT NULL,
    content_md  TEXT NOT NULL DEFAULT '',
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_lessons_module ON lessons(module_id, position);

CREATE TABLE IF NOT EXISTS user_module_progress (
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    module_id    UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    status       VARCHAR(16) NOT NULL DEFAULT 'in_progress'
                     CHECK (status IN ('in_progress', 'completed')),
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, module_id)
);

-- ============ TESTY ============

CREATE TABLE IF NOT EXISTS tests (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id   UUID REFERENCES modules(id) ON DELETE CASCADE,
    title       VARCHAR(160) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    xp_reward   INTEGER NOT NULL DEFAULT 100,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS questions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id       UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    type          VARCHAR(16) NOT NULL
                      CHECK (type IN ('single_choice', 'multiple_choice', 'true_false', 'text')),
    prompt        TEXT NOT NULL,
    options       JSONB,              -- [{ "id": "a", "label": "..." }, ...] dla choice/true_false
    correct_answer JSONB NOT NULL,    -- np. "a" | ["a","c"] | true | "sha256"
    points        INTEGER NOT NULL DEFAULT 10,
    position      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_questions_test ON questions(test_id, position);

CREATE TABLE IF NOT EXISTS test_attempts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    test_id      UUID NOT NULL REFERENCES tests(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    answers      JSONB NOT NULL,      -- { "<question_id>": <answer> }
    score_points INTEGER NOT NULL,
    max_points   INTEGER NOT NULL,
    correct_count INTEGER NOT NULL,
    total_count  INTEGER NOT NULL,
    xp_awarded   INTEGER NOT NULL DEFAULT 0,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_attempts_user ON test_attempts(user_id);

-- ============ LABORATORIA ============
-- Laby są opisowe/flag-based (CTF-style) — nie wykonują kodu użytkownika na
-- serwerze aplikacji. Jeśli w przyszłości dodane zostanie uruchamianie kodu,
-- MUSI to trafić do osobnego, odizolowanego serwisu wykonawczego (patrz README).

CREATE TABLE IF NOT EXISTS labs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title        VARCHAR(160) NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    instructions_md TEXT NOT NULL DEFAULT '',
    difficulty   VARCHAR(16) NOT NULL DEFAULT 'beginner'
                     CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
    flag_hash    TEXT NOT NULL,       -- argon2id hash flagi — nigdy plaintext
    xp_reward    INTEGER NOT NULL DEFAULT 150,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    created_by   UUID REFERENCES users(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lab_submissions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lab_id       UUID NOT NULL REFERENCES labs(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_correct   BOOLEAN NOT NULL,
    xp_awarded   INTEGER NOT NULL DEFAULT 0,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_lab_submissions_user ON lab_submissions(user_id);
-- Jeden zaliczony lab per user liczy się do XP raz — wymuszone w logice aplikacji
-- oraz przez unikalny indeks częściowy poniżej.
CREATE UNIQUE INDEX IF NOT EXISTS uq_lab_first_solve
    ON lab_submissions(lab_id, user_id) WHERE is_correct = TRUE;

-- ============ KONKURSY ============

CREATE TABLE IF NOT EXISTS contests (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       VARCHAR(160) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    starts_at   TIMESTAMPTZ NOT NULL,
    ends_at     TIMESTAMPTZ NOT NULL,
    is_published BOOLEAN NOT NULL DEFAULT FALSE,
    created_by  UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at)
);

CREATE TABLE IF NOT EXISTS contest_tasks (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contest_id  UUID NOT NULL REFERENCES contests(id) ON DELETE CASCADE,
    title       VARCHAR(160) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    flag_hash   TEXT NOT NULL,
    points      INTEGER NOT NULL DEFAULT 100,
    position    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS contest_submissions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    contest_task_id UUID NOT NULL REFERENCES contest_tasks(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    is_correct   BOOLEAN NOT NULL,
    points_awarded INTEGER NOT NULL DEFAULT 0,
    submitted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_contest_submissions_user ON contest_submissions(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_contest_task_first_solve
    ON contest_submissions(contest_task_id, user_id) WHERE is_correct = TRUE;

-- ============ ODZNAKI ============

CREATE TABLE IF NOT EXISTS badges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code        VARCHAR(64) UNIQUE NOT NULL,
    title       VARCHAR(120) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    icon        VARCHAR(64) NOT NULL DEFAULT 'shield'
);

CREATE TABLE IF NOT EXISTS user_badges (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    badge_id   UUID NOT NULL REFERENCES badges(id) ON DELETE CASCADE,
    awarded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, badge_id)
);

-- ============ LOGI BEZPIECZEŃSTWA ============

CREATE TABLE IF NOT EXISTS security_logs (
    id          BIGSERIAL PRIMARY KEY,
    event_type  VARCHAR(64) NOT NULL,   -- login_success, login_failed, account_locked,
                                         -- password_changed, permission_changed,
                                         -- employee_created, content_deleted, suspicious_request
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    actor_username VARCHAR(32),
    target_id   UUID,
    ip_address  INET,
    user_agent  TEXT,
    details     JSONB,                  -- NIGDY haseł ani sekretów
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_security_logs_type ON security_logs(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_logs_actor ON security_logs(actor_id);

-- ============ USTAWIENIA SYSTEMOWE ============

CREATE TABLE IF NOT EXISTS settings (
    key         VARCHAR(64) PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO settings (key, value) VALUES
    ('min_password_length', '10'),
    ('registration_enabled', 'true')
ON CONFLICT (key) DO NOTHING;
