<?php
/**
 * CryptoVault — auth.php
 * JSON API for user registration, login, logout, session-check,
 * profile update, password change, and ID verification submission.
 *
 * All endpoints: POST with JSON body { "action": "...", ...fields }
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';

/* ── Headers ──────────────────────────────────────────────────── */
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Session-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { jsonErr('POST only.', 405); }

/* ── Parse body ───────────────────────────────────────────────── */
$raw  = file_get_contents('php://input');
$body = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) jsonErr('Invalid JSON.', 400);

$action = trim($body['action'] ?? '');
if (!$action) jsonErr('Missing action.', 400);

/* ── Dispatch ─────────────────────────────────────────────────── */
match ($action) {
    'register'        => doRegister($body),
    'login'           => doLogin($body),
    'logout'          => doLogout(),
    'check'           => doCheck(),
    'profile_update'  => doProfileUpdate($body),
    'password_change' => doPasswordChange($body),
    'submit_id'       => doSubmitID($body),
    'get_id_status'   => doGetIDStatus(),
    default           => jsonErr("Unknown action: {$action}", 400),
};

/* ════════════════════════════════════════════════════════════════
   REGISTER
   ════════════════════════════════════════════════════════════════ */
function doRegister(array $b): never
{
    $fullName = trim($b['full_name'] ?? '');
    $email    = strtolower(trim($b['email']  ?? ''));
    $mobile   = trim($b['mobile']   ?? '');
    $password = $b['password']      ?? '';
    $confirm  = $b['confirm']       ?? '';

    /* ── Validation ── */
    $errs = [];
    if (strlen($fullName) < 2)           $errs[] = 'Full name must be at least 2 characters.';
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errs[] = 'Invalid email address.';
    if (!preg_match('/^[6-9]\d{9}$/', $mobile))     $errs[] = 'Mobile must be a valid 10-digit Indian number.';
    if (strlen($password) < 8)           $errs[] = 'Password must be at least 8 characters.';
    if (!preg_match('/[A-Z]/', $password)) $errs[] = 'Password must contain at least one uppercase letter.';
    if (!preg_match('/\d/', $password))   $errs[] = 'Password must contain at least one digit.';
    if ($password !== $confirm)           $errs[] = 'Passwords do not match.';
    if ($errs) jsonErr(implode(' ', $errs), 422);

    $db = getDB();

    /* ── Duplicate check ── */
    $dup = $db->prepare('SELECT id FROM users WHERE email=? OR mobile=? LIMIT 1');
    $dup->execute([$email, $mobile]);
    if ($dup->fetch()) jsonErr('An account with this email or mobile number already exists.', 409);

    /* ── Insert ── */
    $hash     = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
    $initials = makeInitials($fullName);

    $ins = $db->prepare('
        INSERT INTO users (full_name, email, mobile, password_hash, avatar_initials)
        VALUES (?, ?, ?, ?, ?)
    ');
    $ins->execute([$fullName, $email, $mobile, $hash, $initials]);
    $userId = (int) $db->lastInsertId();

    /* ── Auto-login ── */
    $token = createSession($db, $userId);

    jsonOk([
        'message' => 'Account created successfully.',
        'token'   => $token,
        'user'    => safeUser($db, $userId),
    ]);
}

/* ════════════════════════════════════════════════════════════════
   LOGIN
   ════════════════════════════════════════════════════════════════ */
function doLogin(array $b): never
{
    $identifier = strtolower(trim($b['identifier'] ?? '')); // email or mobile
    $password   = $b['password'] ?? '';

    if (!$identifier || !$password) jsonErr('Email/mobile and password are required.', 422);

    $db = getDB();
    $q  = $db->prepare('
        SELECT * FROM users
        WHERE (email=? OR mobile=?) AND is_active=1
        LIMIT 1
    ');
    $q->execute([$identifier, $identifier]);
    $user = $q->fetch();

    if (!$user || !password_verify($password, $user['password_hash'])) {
        jsonErr('Invalid credentials. Please check your email/mobile and password.', 401);
    }

    /* ── Update last_login ── */
    $db->prepare('UPDATE users SET last_login=datetime(\'now\') WHERE id=?')
       ->execute([$user['id']]);

    /* ── Invalidate old sessions (keep last 3) ── */
    $db->prepare('
        DELETE FROM user_sessions WHERE user_id=? AND id NOT IN (
            SELECT id FROM user_sessions WHERE user_id=? ORDER BY created_at DESC LIMIT 3
        )
    ')->execute([$user['id'], $user['id']]);

    $token = createSession($db, (int) $user['id']);

    jsonOk([
        'message' => 'Login successful.',
        'token'   => $token,
        'user'    => safeUser($db, (int) $user['id']),
    ]);
}

/* ════════════════════════════════════════════════════════════════
   LOGOUT
   ════════════════════════════════════════════════════════════════ */
function doLogout(): never
{
    $token = getToken();
    if ($token) {
        $db = getDB();
        $db->prepare('DELETE FROM user_sessions WHERE token=?')->execute([$token]);
    }
    jsonOk(['message' => 'Logged out successfully.']);
}

/* ════════════════════════════════════════════════════════════════
   CHECK SESSION
   ════════════════════════════════════════════════════════════════ */
function doCheck(): never
{
    $user = requireAuth();
    jsonOk(['user' => $user]);
}

/* ════════════════════════════════════════════════════════════════
   PROFILE UPDATE
   ════════════════════════════════════════════════════════════════ */
function doProfileUpdate(array $b): never
{
    $user     = requireAuth();
    $fullName = trim($b['full_name'] ?? '');
    $mobile   = trim($b['mobile']   ?? '');

    $errs = [];
    if (strlen($fullName) < 2) $errs[] = 'Full name must be at least 2 characters.';
    if (!preg_match('/^[6-9]\d{9}$/', $mobile)) $errs[] = 'Invalid mobile number.';
    if ($errs) jsonErr(implode(' ', $errs), 422);

    $db = getDB();

    /* mobile uniqueness — exclude self */
    $mq = $db->prepare('SELECT id FROM users WHERE mobile=? AND id!=? LIMIT 1');
    $mq->execute([$mobile, $user['id']]);
    if ($mq->fetch()) jsonErr('This mobile number is already registered.', 409);

    $initials = makeInitials($fullName);
    $db->prepare('UPDATE users SET full_name=?, mobile=?, avatar_initials=? WHERE id=?')
       ->execute([$fullName, $mobile, $initials, $user['id']]);

    jsonOk(['message' => 'Profile updated.', 'user' => safeUser($db, (int) $user['id'])]);
}

/* ════════════════════════════════════════════════════════════════
   PASSWORD CHANGE
   ════════════════════════════════════════════════════════════════ */
function doPasswordChange(array $b): never
{
    $user    = requireAuth();
    $current = $b['current_password'] ?? '';
    $newPwd  = $b['new_password']     ?? '';
    $confirm = $b['confirm_password'] ?? '';

    if (!$current || !$newPwd || !$confirm) jsonErr('All password fields are required.', 422);
    if ($newPwd !== $confirm) jsonErr('New passwords do not match.', 422);
    if (strlen($newPwd) < 8) jsonErr('New password must be at least 8 characters.', 422);
    if (!preg_match('/[A-Z]/', $newPwd)) jsonErr('New password must contain at least one uppercase letter.', 422);
    if (!preg_match('/\d/', $newPwd))   jsonErr('New password must contain at least one digit.', 422);

    $db  = getDB();
    $row = $db->prepare('SELECT password_hash FROM users WHERE id=?');
    $row->execute([$user['id']]);
    $data = $row->fetch();

    if (!password_verify($current, $data['password_hash'])) {
        jsonErr('Current password is incorrect.', 401);
    }

    $hash = password_hash($newPwd, PASSWORD_BCRYPT, ['cost' => 12]);
    $db->prepare('UPDATE users SET password_hash=? WHERE id=?')
       ->execute([$hash, $user['id']]);

    jsonOk(['message' => 'Password changed successfully.']);
}

/* ════════════════════════════════════════════════════════════════
   SUBMIT ID VERIFICATION
   ════════════════════════════════════════════════════════════════ */
function doSubmitID(array $b): never
{
    $user   = requireAuth();
    $type   = trim($b['id_type']   ?? '');
    $number = trim($b['id_number'] ?? '');
    $name   = trim($b['id_name']   ?? '');

    $errs = [];
    if (!in_array($type, ['aadhaar', 'pan'], true)) $errs[] = 'Select a valid ID type.';
    if ($type === 'aadhaar' && !preg_match('/^\d{12}$/', $number))
        $errs[] = 'Aadhaar number must be exactly 12 digits.';
    if ($type === 'pan' && !preg_match('/^[A-Z]{5}[0-9]{4}[A-Z]$/', strtoupper($number)))
        $errs[] = 'PAN must be in format ABCDE1234F.';
    if (strlen($name) < 2) $errs[] = 'Name on ID is required.';
    if ($errs) jsonErr(implode(' ', $errs), 422);

    $db = getDB();

    /* Only one pending/verified record allowed — remove old rejected/pending */
    $existing = $db->prepare('SELECT id, status FROM id_verifications WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1');
    $existing->execute([$user['id']]);
    $prev = $existing->fetch();
    if ($prev && in_array($prev['status'], ['pending', 'verified'], true)) {
        jsonErr('You already have a ' . $prev['status'] . ' verification. Contact support to change it.', 409);
    }

    /* Mask the ID — store only last 4 digits visible */
    $masked = maskID($type, $number);

    $ins = $db->prepare('
        INSERT INTO id_verifications (user_id, id_type, id_number, id_name, status)
        VALUES (?, ?, ?, ?, \'pending\')
    ');
    $ins->execute([$user['id'], $type, $masked, $name]);

    /* Simulate auto-verify after 5 seconds (demo purposes)
       In production this would call an official UIDAI/NSDL API.
       Here we immediately mark as "verified" to demonstrate the workflow. */
    $db->prepare('UPDATE id_verifications SET status=\'verified\', reviewed_at=datetime(\'now\'),
        notes=\'Simulated verification — demo mode\' WHERE user_id=? AND status=\'pending\'')
       ->execute([$user['id']]);

    jsonOk([
        'message' => 'ID submitted and verified (demo mode).',
        'status'  => 'verified',
        'masked'  => $masked,
    ]);
}

/* ════════════════════════════════════════════════════════════════
   GET ID VERIFICATION STATUS
   ════════════════════════════════════════════════════════════════ */
function doGetIDStatus(): never
{
    $user = requireAuth();
    $db   = getDB();
    $q    = $db->prepare('
        SELECT id_type, id_number, id_name, status, submitted_at, reviewed_at, notes
        FROM id_verifications WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1
    ');
    $q->execute([$user['id']]);
    $rec = $q->fetch();

    jsonOk(['verification' => $rec ?: null]);
}

/* ════════════════════════════════════════════════════════════════
   HELPERS
   ════════════════════════════════════════════════════════════════ */

function requireAuth(): array
{
    $token = getToken();
    if (!$token) jsonErr('Authentication required. Please log in.', 401);

    $db = getDB();
    $q  = $db->prepare('
        SELECT s.user_id, s.expires_at, u.id, u.full_name, u.email, u.mobile,
               u.role, u.avatar_initials, u.created_at, u.last_login, u.is_active
        FROM user_sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token=? AND s.expires_at > datetime(\'now\') AND u.is_active=1
        LIMIT 1
    ');
    $q->execute([$token]);
    $row = $q->fetch();

    if (!$row) jsonErr('Session expired or invalid. Please log in again.', 401);

    /* Extend session on activity */
    $db->prepare('UPDATE user_sessions SET expires_at=datetime(\'now\',\'+7 days\') WHERE token=?')
       ->execute([$token]);

    return $row;
}

function getToken(): ?string
{
    // Accept from X-Session-Token header or Authorization: Bearer ...
    $headers = getallheaders();
    if (!empty($headers['X-Session-Token'])) return trim($headers['X-Session-Token']);
    if (!empty($headers['Authorization'])) {
        return trim(str_replace('Bearer ', '', $headers['Authorization']));
    }
    return null;
}

function createSession(PDO $db, int $userId): string
{
    $token     = bin2hex(random_bytes(32));
    $expiresAt = date('Y-m-d H:i:s', strtotime('+7 days'));
    $ip        = $_SERVER['REMOTE_ADDR']     ?? '';
    $ua        = $_SERVER['HTTP_USER_AGENT'] ?? '';

    $db->prepare('
        INSERT INTO user_sessions (user_id, token, expires_at, ip_address, user_agent)
        VALUES (?, ?, ?, ?, ?)
    ')->execute([$userId, $token, $expiresAt, $ip, $ua]);

    return $token;
}

function safeUser(PDO $db, int $userId): array
{
    $q = $db->prepare('
        SELECT id, full_name, email, mobile, role, avatar_initials, created_at, last_login
        FROM users WHERE id=? LIMIT 1
    ');
    $q->execute([$userId]);
    $u = $q->fetch();

    /* Attach ID verification status */
    $idq = $db->prepare('
        SELECT id_type, id_number, id_name, status, submitted_at
        FROM id_verifications WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1
    ');
    $idq->execute([$userId]);
    $u['id_verification'] = $idq->fetch() ?: null;

    return $u;
}

function makeInitials(string $name): string
{
    $parts = array_filter(explode(' ', $name));
    if (count($parts) >= 2) {
        return strtoupper(substr($parts[0], 0, 1) . substr(end($parts), 0, 1));
    }
    return strtoupper(substr($name, 0, 2));
}

function maskID(string $type, string $number): string
{
    if ($type === 'aadhaar') {
        return 'XXXX-XXXX-' . substr($number, -4);
    }
    // PAN: ABCDE1234F → AB***1234F
    return substr($number, 0, 2) . '***' . substr($number, -4);
}

function jsonOk(array $data): never
{
    echo json_encode(['success' => true] + $data, JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonErr(string $message, int $status = 400): never
{
    http_response_code($status);
    echo json_encode(['success' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}
