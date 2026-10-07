<?php
/**
 * CryptoVault — encrypt.php
 * Handles AES-256-CBC encryption/decryption and SHA-256/512 hashing.
 * Called via fetch() from app.js as a JSON API.
 */

declare(strict_types=1);

/* ── CORS / Headers ─────────────────────────────────────────── */
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

/* ── Only accept POST ───────────────────────────────────────── */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonError('Only POST requests are accepted.', 405);
}

/* ── Parse JSON body ────────────────────────────────────────── */
$raw  = file_get_contents('php://input');
$data = json_decode($raw, true);

if (json_last_error() !== JSON_ERROR_NONE) {
    jsonError('Invalid JSON payload.', 400);
}

$algo   = trim($data['algo']   ?? '');
$mode   = trim($data['mode']   ?? '');   // 'encrypt' | 'decrypt'
$text   = $data['text']        ?? '';
$key    = $data['key']         ?? '';

/* ── Validate basics ────────────────────────────────────────── */
if ($algo === '') jsonError('No algorithm specified.', 400);
if (!in_array($mode, ['encrypt', 'decrypt'], true)) jsonError('Mode must be "encrypt" or "decrypt".', 400);
if ($text === '') jsonError('Input text is empty.', 400);

/* ── Dispatch ───────────────────────────────────────────────── */
$start = microtime(true);

switch ($algo) {
    case 'aes':
        $result = handleAES($text, $key, $mode);
        break;
    case 'sha256':
        $result = handleSHA($text, 'sha256');
        break;
    case 'sha512':
        $result = handleSHA($text, 'sha512');
        break;
    default:
        jsonError("Unknown algorithm: {$algo}", 400);
}

$elapsed = round((microtime(true) - $start) * 1000, 4); // ms

jsonSuccess([
    'output'  => $result,
    'algo'    => $algo,
    'mode'    => $mode,
    'time_ms' => $elapsed,
    'in_len'  => mb_strlen($text),
    'out_len' => mb_strlen($result),
]);

/* ════════════════════════════════════════════════════════════
   AES-256-CBC
   ════════════════════════════════════════════════════════════ */
function handleAES(string $text, string $passphrase, string $mode): string
{
    if (strlen($passphrase) < 8) {
        jsonError('AES passphrase must be at least 8 characters.', 422);
    }

    $cipher    = 'AES-256-CBC';
    $ivLength  = openssl_cipher_iv_length($cipher);

    // Derive a 256-bit key from the passphrase using SHA-256
    $derivedKey = hash('sha256', $passphrase, true); // 32 bytes raw

    if ($mode === 'encrypt') {
        $iv         = openssl_random_pseudo_bytes($ivLength);
        $encrypted  = openssl_encrypt($text, $cipher, $derivedKey, OPENSSL_RAW_DATA, $iv);

        if ($encrypted === false) {
            jsonError('AES encryption failed: ' . openssl_error_string(), 500);
        }

        // Prepend IV to ciphertext and Base64-encode the whole thing
        return base64_encode($iv . $encrypted);
    }

    // Decrypt
    $decoded = base64_decode($text, true);
    if ($decoded === false || strlen($decoded) <= $ivLength) {
        jsonError('Invalid AES ciphertext. Make sure you are decrypting a valid AES-256-CBC encrypted value.', 422);
    }

    $iv        = substr($decoded, 0, $ivLength);
    $ciphertext = substr($decoded, $ivLength);
    $decrypted  = openssl_decrypt($ciphertext, $cipher, $derivedKey, OPENSSL_RAW_DATA, $iv);

    if ($decrypted === false) {
        jsonError('AES decryption failed. Wrong passphrase or corrupted ciphertext.', 422);
    }

    return $decrypted;
}

/* ════════════════════════════════════════════════════════════
   SHA Hashing (one-way)
   ════════════════════════════════════════════════════════════ */
function handleSHA(string $text, string $algo): string
{
    return hash($algo, $text);
}

/* ════════════════════════════════════════════════════════════
   Response helpers
   ════════════════════════════════════════════════════════════ */
function jsonSuccess(array $data): never
{
    echo json_encode(['success' => true, 'data' => $data], JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonError(string $message, int $status = 400): never
{
    http_response_code($status);
    echo json_encode(['success' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}
