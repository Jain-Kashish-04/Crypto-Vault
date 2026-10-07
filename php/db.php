<?php
/**
 * CryptoVault — db.php
 * SQLite database bootstrap. Call getDB() to get a PDO instance.
 * All tables are created automatically on first use.
 */

declare(strict_types=1);

define('DB_PATH', __DIR__ . '/../data/cryptovault.sqlite');

function getDB(): PDO
{
    static $pdo = null;
    if ($pdo !== null) return $pdo;

    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    $pdo = new PDO('sqlite:' . DB_PATH, null, null, [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    // Enable WAL for concurrent reads
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');

    createTables($pdo);
    return $pdo;
}

function createTables(PDO $pdo): void
{
    /* ── USERS ────────────────────────────────────────────────── */
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name     TEXT    NOT NULL,
            email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            mobile        TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            role          TEXT    NOT NULL DEFAULT 'user',
            avatar_initials TEXT  NOT NULL DEFAULT '',
            created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
            last_login    TEXT,
            is_active     INTEGER NOT NULL DEFAULT 1
        )
    ");

    /* ── ID VERIFICATION ─────────────────────────────────────── */
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS id_verifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            id_type     TEXT    NOT NULL,           -- 'aadhaar' | 'pan'
            id_number   TEXT    NOT NULL,           -- stored masked, not plain
            id_name     TEXT    NOT NULL,           -- name on the document
            status      TEXT    NOT NULL DEFAULT 'pending',  -- pending|verified|rejected
            submitted_at TEXT   NOT NULL DEFAULT (datetime('now')),
            reviewed_at  TEXT,
            notes        TEXT
        )
    ");

    /* ── SESSIONS ────────────────────────────────────────────── */
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            token       TEXT    NOT NULL UNIQUE,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            expires_at  TEXT    NOT NULL,
            ip_address  TEXT,
            user_agent  TEXT
        )
    ");

    /* ── ENCRYPTION HISTORY ──────────────────────────────────── */
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS history (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            algorithm    TEXT    NOT NULL,
            algo_label   TEXT    NOT NULL,
            mode         TEXT    NOT NULL,          -- encrypt | decrypt
            input_text   TEXT    NOT NULL,
            output_text  TEXT    NOT NULL,
            input_length INTEGER NOT NULL DEFAULT 0,
            output_length INTEGER NOT NULL DEFAULT 0,
            time_ms      REAL    NOT NULL DEFAULT 0,
            created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    ");

    /* ── INDEXES ─────────────────────────────────────────────── */
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_history_user   ON history(user_id, created_at DESC)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sessions_token ON user_sessions(token)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_sessions_user  ON user_sessions(user_id)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_idv_user       ON id_verifications(user_id)");
}
