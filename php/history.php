<?php
/**
 * CryptoVault — history.php
 * Per-user encryption/decryption history API.
 *
 * Actions (POST JSON):
 *   save       — store one history entry
 *   list       — paginated list for logged-in user
 *   stats      — aggregate counts per algorithm
 *   delete     — delete one entry by id
 *   clear_all  — wipe all history for user
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';

/* ── Headers ──────────────────────────────────────────────────── */
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Session-Token, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }
if ($_SERVER['REQUEST_METHOD'] !== 'POST')    { hErr('POST only.', 405); }

/* ── Parse ────────────────────────────────────────────────────── */
$raw  = file_get_contents('php://input');
$body = json_decode($raw, true);
if (json_last_error() !== JSON_ERROR_NONE) hErr('Invalid JSON.', 400);

$action = trim($body['action'] ?? '');
if (!$action) hErr('Missing action.', 400);

/* ── Auth ─────────────────────────────────────────────────────── */
$userId = hRequireAuth();

/* ── Dispatch ─────────────────────────────────────────────────── */
match ($action) {
    'save'      => doSave($body, $userId),
    'list'      => doList($body, $userId),
    'stats'     => doStats($userId),
    'delete'    => doDelete($body, $userId),
    'clear_all' => doClearAll($userId),
    default     => hErr("Unknown action: {$action}", 400),
};

/* ════════════════════════════════════════════════════════════════
   SAVE
   ════════════════════════════════════════════════════════════════ */
function doSave(array $b, int $userId): never
{
    $algorithm    = trim($b['algorithm']    ?? '');
    $algoLabel    = trim($b['algo_label']   ?? $algorithm);
    $mode         = trim($b['mode']         ?? '');
    $inputText    = $b['input_text']        ?? '';
    $outputText   = $b['output_text']       ?? '';
    $inputLength  = (int)($b['input_length']  ?? strlen($inputText));
    $outputLength = (int)($b['output_length'] ?? strlen($outputText));
    $timeMs       = (float)($b['time_ms']     ?? 0);

    if (!$algorithm || !in_array($mode, ['encrypt', 'decrypt'], true))
        hErr('algorithm and mode are required.', 422);

    /* Truncate stored text to 2000 chars to keep DB manageable */
    $inputStored  = mb_substr($inputText,  0, 2000);
    $outputStored = mb_substr($outputText, 0, 2000);

    $db = getDB();
    $db->prepare('
        INSERT INTO history
            (user_id, algorithm, algo_label, mode, input_text, output_text,
             input_length, output_length, time_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ')->execute([
        $userId, $algorithm, $algoLabel, $mode,
        $inputStored, $outputStored,
        $inputLength, $outputLength, round($timeMs, 4),
    ]);

    $id = (int) $db->lastInsertId();
    hOk(['id' => $id, 'message' => 'Saved to history.']);
}

/* ════════════════════════════════════════════════════════════════
   LIST
   ════════════════════════════════════════════════════════════════ */
function doList(array $b, int $userId): never
{
    $limit  = min((int)($b['limit']  ?? 20), 100);
    $offset = max((int)($b['offset'] ?? 0), 0);
    $filter = trim($b['filter'] ?? ''); // optional algorithm filter

    $db = getDB();

    if ($filter) {
        $q = $db->prepare('
            SELECT id, algorithm, algo_label, mode, input_text, output_text,
                   input_length, output_length, time_ms, created_at
            FROM history
            WHERE user_id=? AND algorithm=?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ');
        $q->execute([$userId, $filter, $limit, $offset]);

        $cq = $db->prepare('SELECT COUNT(*) as cnt FROM history WHERE user_id=? AND algorithm=?');
        $cq->execute([$userId, $filter]);
    } else {
        $q = $db->prepare('
            SELECT id, algorithm, algo_label, mode, input_text, output_text,
                   input_length, output_length, time_ms, created_at
            FROM history
            WHERE user_id=?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ');
        $q->execute([$userId, $limit, $offset]);

        $cq = $db->prepare('SELECT COUNT(*) as cnt FROM history WHERE user_id=?');
        $cq->execute([$userId]);
    }

    $rows  = $q->fetchAll();
    $total = (int)($cq->fetch()['cnt'] ?? 0);

    hOk([
        'history' => $rows,
        'total'   => $total,
        'limit'   => $limit,
        'offset'  => $offset,
    ]);
}

/* ════════════════════════════════════════════════════════════════
   STATS
   ════════════════════════════════════════════════════════════════ */
function doStats(int $userId): never
{
    $db = getDB();

    /* Total counts */
    $tot = $db->prepare('
        SELECT
            COUNT(*) as total_ops,
            SUM(CASE WHEN mode=\'encrypt\' THEN 1 ELSE 0 END) as encryptions,
            SUM(CASE WHEN mode=\'decrypt\' THEN 1 ELSE 0 END) as decryptions
        FROM history WHERE user_id=?
    ');
    $tot->execute([$userId]);
    $totals = $tot->fetch();

    /* Per-algorithm breakdown */
    $alg = $db->prepare('
        SELECT algo_label, algorithm,
               COUNT(*) as count,
               SUM(CASE WHEN mode=\'encrypt\' THEN 1 ELSE 0 END) as enc,
               SUM(CASE WHEN mode=\'decrypt\' THEN 1 ELSE 0 END) as dec,
               AVG(time_ms) as avg_ms
        FROM history WHERE user_id=?
        GROUP BY algorithm
        ORDER BY count DESC
    ');
    $alg->execute([$userId]);
    $byAlgo = $alg->fetchAll();

    /* Recent 5 */
    $rec = $db->prepare('
        SELECT id, algo_label, mode, input_length, output_length, time_ms, created_at
        FROM history WHERE user_id=?
        ORDER BY created_at DESC LIMIT 5
    ');
    $rec->execute([$userId]);
    $recent = $rec->fetchAll();

    hOk([
        'totals'   => $totals,
        'by_algo'  => $byAlgo,
        'recent'   => $recent,
    ]);
}

/* ════════════════════════════════════════════════════════════════
   DELETE ONE
   ════════════════════════════════════════════════════════════════ */
function doDelete(array $b, int $userId): never
{
    $id = (int)($b['id'] ?? 0);
    if (!$id) hErr('id is required.', 422);

    $db = getDB();
    $q  = $db->prepare('DELETE FROM history WHERE id=? AND user_id=?');
    $q->execute([$id, $userId]);

    if ($q->rowCount() === 0) hErr('Record not found or not yours.', 404);
    hOk(['message' => 'Deleted.']);
}

/* ════════════════════════════════════════════════════════════════
   CLEAR ALL
   ════════════════════════════════════════════════════════════════ */
function doClearAll(int $userId): never
{
    $db = getDB();
    $db->prepare('DELETE FROM history WHERE user_id=?')->execute([$userId]);
    hOk(['message' => 'History cleared.']);
}

/* ════════════════════════════════════════════════════════════════
   AUTH HELPER (inline — no shared state with auth.php)
   ════════════════════════════════════════════════════════════════ */
function hRequireAuth(): int
{
    $token = hGetToken();
    if (!$token) hErr('Authentication required.', 401);

    $db = getDB();
    $q  = $db->prepare('
        SELECT s.user_id
        FROM user_sessions s
        JOIN users u ON u.id=s.user_id
        WHERE s.token=? AND s.expires_at > datetime(\'now\') AND u.is_active=1
        LIMIT 1
    ');
    $q->execute([$token]);
    $row = $q->fetch();
    if (!$row) hErr('Session expired. Please log in again.', 401);

    /* Extend session */
    $db->prepare('UPDATE user_sessions SET expires_at=datetime(\'now\',\'+7 days\') WHERE token=?')
       ->execute([$token]);

    return (int) $row['user_id'];
}

function hGetToken(): ?string
{
    $headers = getallheaders();
    if (!empty($headers['X-Session-Token']))  return trim($headers['X-Session-Token']);
    if (!empty($headers['Authorization']))
        return trim(str_replace('Bearer ', '', $headers['Authorization']));
    return null;
}

function hOk(array $data): never
{
    echo json_encode(['success' => true] + $data, JSON_UNESCAPED_UNICODE);
    exit;
}

function hErr(string $msg, int $status = 400): never
{
    http_response_code($status);
    echo json_encode(['success' => false, 'error' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}
