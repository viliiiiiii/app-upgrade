<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

date_default_timezone_set(APP_TIMEZONE);

// Ensure session started
if (session_status() === PHP_SESSION_NONE) {
    session_name(SESSION_NAME);
    session_start();
}

// Composer autoload if present
$autoloadPath = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloadPath)) {
    require_once $autoloadPath;
}

// Guard: only define functions once even if file is included multiple times.
if (!defined('HELPERS_BOOTSTRAPPED')) {
    define('HELPERS_BOOTSTRAPPED', true);

    /**
     * Return a PDO connection to either the application DB ("apps" = punchlist)
     * or the core governance DB ("core" = users/roles/activity).
     */
    function get_pdo(string $which = 'apps'): PDO {
        static $pool = [];
        if (isset($pool[$which])) return $pool[$which];

        if ($which === 'core') {
            $dsn  = CORE_DSN;
            $user = CORE_DB_USER;
            $pass = CORE_DB_PASS;
        } else {
            $dsn  = APPS_DSN;
            $user = APPS_DB_USER;
            $pass = APPS_DB_PASS;
        }

        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
        $pool[$which] = $pdo;
        return $pdo;
    }

    /* ===== Security: CSRF, flash, redirects ===== */

    function csrf_token(): string {
        if (empty($_SESSION[CSRF_TOKEN_NAME])) {
            $_SESSION[CSRF_TOKEN_NAME] = bin2hex(random_bytes(32));
        }
        return $_SESSION[CSRF_TOKEN_NAME];
    }

    function verify_csrf_token(?string $token): bool {
        return isset($_SESSION[CSRF_TOKEN_NAME]) && hash_equals($_SESSION[CSRF_TOKEN_NAME], (string)$token);
    }

    function redirect_with_message(string $location, string $message, string $type='success'): void {
        $_SESSION['flash'] = ['message'=>$message,'type'=>$type];
        header('Location: '.$location);
        exit;
    }

    function flash_message(): void {
    if (!empty($_SESSION['flash'])) {
        $flash = $_SESSION['flash'];
        unset($_SESSION['flash']);

        $type    = htmlspecialchars((string)($flash['type'] ?? 'success'), ENT_QUOTES, 'UTF-8');
        $message = htmlspecialchars((string)($flash['message'] ?? ''),       ENT_QUOTES, 'UTF-8');

        echo '<div class="flash flash-', $type, '">', $message, '</div>';
    }
}

    /* ===== Auth & Session (CORE-first) ===== */

    /**
     * Log the user in by CORE user id.
     * Stores only the id in session to keep data source of truth in CORE DB.
     */
    function auth_login(int $userId): void {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_name(SESSION_NAME);
            session_start();
        }
        // Use a dedicated key; keep old 'user' for backward compat but clear it to avoid stale records
        $_SESSION['uid'] = (int)$userId;
        unset($_SESSION['user']); // clear legacy session payload if present
    }

    /** Destroy session completely. */
    function auth_logout(): void {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_name(SESSION_NAME);
            session_start();
        }
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time()-42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();
    }

    /**
     * Fetch current user: primary from CORE via uid; fallback from legacy $_SESSION['user'].
     * If legacy payload contains an email that exists in CORE, we auto-upgrade to uid.
     */
    function current_user(): ?array {
        // Preferred path: uid -> core users table
        if (!empty($_SESSION['uid'])) {
            $core = core_user_record((int)$_SESSION['uid']);
            if ($core) return $core;
        }

        // Back-compat path (older code may set $_SESSION['user'])
        if (!empty($_SESSION['user']) && is_array($_SESSION['user'])) {
            $legacy = $_SESSION['user'];
            // Try to resolve to CORE by email
            if (!empty($legacy['email'])) {
                $u = core_find_user_by_email((string)$legacy['email']);
                if ($u) {
                    // upgrade session to uid for all subsequent requests
                    $_SESSION['uid'] = (int)$u['id'];
                    unset($_SESSION['user']);
                    return $u;
                }
            }
            // Last resort: return legacy payload (may not include permissions)
            return $legacy;
        }

        return null;
    }

    /**
     * Require a logged-in user; also logs a "login" activity once per session.
     * Enforces suspension immediately.
     */
    function require_login(): void {
        $user = current_user();
        if (!$user) {
            header('Location: login.php');
            exit;
        }
        $userId = $user['id'] ?? null;
        $sessionMarker = session_id();
        if (!isset($_SESSION['login_logged_marker']) || $_SESSION['login_logged_marker'] !== $sessionMarker) {
            $_SESSION['login_logged_marker'] = $sessionMarker;
            log_event('login', 'user', $userId ? (int)$userId : null);
        }
        enforce_not_suspended();
    }

    function is_post(): bool { return ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'; }
    function sanitize(string $v): string { return htmlspecialchars($v, ENT_QUOTES|ENT_SUBSTITUTE, 'UTF-8'); }

    /* ===== Domain constants ===== */

    function get_priorities(): array { return ['', 'low','low/mid','mid','mid/high','high']; }
    function get_statuses(): array { return ['open','in_progress','done']; }

    function priority_label(string $p): string {
        $map = [''=>'No priority','low'=>'Low','low/mid'=>'Low/Mid','mid'=>'Mid','mid/high'=>'Mid/High','high'=>'High'];
        return $map[$p] ?? $p;
    }
    function priority_class(string $p): string {
        return match ($p) {
            'low' => 'priority-low',
            'low/mid' => 'priority-lowmid',
            'mid' => 'priority-mid',
            'mid/high' => 'priority-midhigh',
            'high' => 'priority-high',
            default => 'priority-none'
        };
    }
    function status_label(string $s): string {
        return match ($s) { 'open'=>'Open','in_progress'=>'In Progress','done'=>'Done', default=>ucfirst($s) };
    }
    function status_class(string $s): string {
        return match ($s) { 'open'=>'status-open','in_progress'=>'status-inprogress','done'=>'status-done', default=>'status-open' };
    }

    /* ===== App (punchlist) queries — use APPS DB ===== */

    function fetch_buildings(): array {
        $stmt = get_pdo()->query('SELECT id,name FROM buildings ORDER BY name');
        return $stmt->fetchAll();
    }

    function fetch_rooms_by_building(?int $buildingId): array {
        if (!$buildingId) return [];
        $stmt = get_pdo()->prepare('SELECT id,room_number,label FROM rooms WHERE building_id=? ORDER BY room_number');
        $stmt->execute([$buildingId]);
        return $stmt->fetchAll();
    }

    function fetch_task_photos(int $taskId): array {
        $stmt = get_pdo()->prepare('SELECT * FROM task_photos WHERE task_id=? ORDER BY position');
        $stmt->execute([$taskId]);
        $indexed = [];
        foreach ($stmt->fetchAll() as $p) { $indexed[(int)$p['position']] = $p; }
        return $indexed;
    }

    /* ===== S3 helpers ===== */

    function s3_client(): Aws\S3\S3Client {
        static $client;
        if ($client === null) {
            $client = new Aws\S3\S3Client([
                'version' => 'latest',
                'region'  => S3_REGION,
                'credentials' => ['key'=>S3_KEY,'secret'=>S3_SECRET],
                'endpoint' => S3_ENDPOINT,
                'use_path_style_endpoint' => S3_USE_PATH_STYLE,
            ]);
        }
        return $client;
    }

    function s3_signed_url_for_key(string $key, int $ttlSeconds = 900): string {
        $client = s3_client();
        $cmd = $client->getCommand('GetObject', ['Bucket' => S3_BUCKET, 'Key' => $key]);
        $req = $client->createPresignedRequest($cmd, '+' . $ttlSeconds . ' seconds');
        return (string) $req->getUri();
    }

    /** Produce a browser-usable URL for a photo row */
    function photo_public_url(array|string $photoOrKey, ?int $maxWidth = null): string {
        $key = is_array($photoOrKey) ? ($photoOrKey['s3_key'] ?? '') : $photoOrKey;
        if ($key === '') return '#';
        // (maxWidth reserved for future; not used by file.php now)
        return '/download.php?key=' . rawurlencode($key);
    }

    function s3_object_url(string $key): string {
        if (S3_URL_BASE !== '') return rtrim(S3_URL_BASE,'/').'/'.ltrim($key,'/');
        $endpoint = rtrim(S3_ENDPOINT,'/');
        if (S3_USE_PATH_STYLE) {
            return $endpoint.'/'.rawurlencode(S3_BUCKET).'/'.implode('/', array_map('rawurlencode', explode('/', $key)));
        }
        $parts = parse_url($endpoint);
        $host = $parts['scheme'].'://'.S3_BUCKET.'.'.$parts['host'];
        $path = $parts['path'] ?? '';
        return rtrim($host.$path,'/').'/'.ltrim($key,'/');
    }

    /* ===== Tasks (APPS DB) ===== */

    function build_task_filter_query(array $filters, array &$params): string {
    $conditions = [];

    // 🔎 Search (title or description). COALESCE fixes NULL description rows.
    if (isset($filters['search']) && $filters['search'] !== '') {
    $conditions[] = "(CONCAT_WS(' ', t.title, t.description) LIKE :search)";
    $params[':search'] = '%' . $filters['search'] . '%';
}

    if (!empty($filters['building_id'])) {
        $conditions[] = 't.building_id = :building_id';
        $params[':building_id'] = (int)$filters['building_id'];
    }

    if (!empty($filters['room_id'])) {
        $conditions[] = 't.room_id = :room_id';
        $params[':room_id'] = (int)$filters['room_id'];
    }

    if (!empty($filters['priority']) && is_array($filters['priority'])) {
        $ph = [];
        foreach ($filters['priority'] as $i => $p) {
            $k = ":priority$i";
            $ph[] = $k;
            $params[$k] = $p;
        }
        if ($ph) {
            $conditions[] = 't.priority IN (' . implode(',', $ph) . ')';
        }
    }

    if (!empty($filters['status'])) {
        $conditions[] = 't.status = :status';
        $params[':status'] = $filters['status'];
    }

    if (!empty($filters['assigned_to'])) {
        $conditions[] = 't.assigned_to LIKE :assigned_to';
        $params[':assigned_to'] = '%' . $filters['assigned_to'] . '%';
    }

    if (!empty($filters['created_from'])) {
        $conditions[] = 'DATE(t.created_at) >= :created_from';
        $params[':created_from'] = $filters['created_from'];
    }

    if (!empty($filters['created_to'])) {
        $conditions[] = 'DATE(t.created_at) <= :created_to';
        $params[':created_to'] = $filters['created_to'];
    }

    if (!empty($filters['due_from'])) {
        $conditions[] = 't.due_date >= :due_from';
        $params[':due_from'] = $filters['due_from'];
    }

    if (!empty($filters['due_to'])) {
        $conditions[] = 't.due_date <= :due_to';
        $params[':due_to'] = $filters['due_to'];
    }

    if (isset($filters['has_photos']) && $filters['has_photos'] !== '') {
        $conditions[] = ($filters['has_photos'] === '1')
            ? 'EXISTS (SELECT 1 FROM task_photos tp WHERE tp.task_id = t.id)'
            : 'NOT EXISTS (SELECT 1 FROM task_photos tp WHERE tp.task_id = t.id)';
    }

    return $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';
}


    function fetch_tasks(array $filters, string $sort, string $direction, int $limit, int $offset, int &$total): array {
        $params = [];
        $where = build_task_filter_query($filters, $params);
        $sortColumns = ['created_at'=>'t.created_at','priority'=>'t.priority','due_date'=>'t.due_date','room'=>'r.room_number'];
        $sortColumn = $sortColumns[$sort] ?? 't.created_at';
        $direction = strtoupper($direction)==='ASC' ? 'ASC' : 'DESC';

        $pdo = get_pdo();
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM tasks t $where");
        $stmt->execute($params);
        $total = (int)$stmt->fetchColumn();

        $sql = "SELECT t.*, b.name AS building_name, r.room_number, r.label AS room_label,
                (SELECT COUNT(*) FROM task_photos tp WHERE tp.task_id=t.id) AS photo_count
                FROM tasks t
                JOIN buildings b ON b.id=t.building_id
                JOIN rooms r ON r.id=t.room_id
                $where
                ORDER BY $sortColumn $direction
                LIMIT :limit OFFSET :offset";
        $stmt = $pdo->prepare($sql);
        foreach ($params as $k=>$v) $stmt->bindValue($k,$v);
        $stmt->bindValue(':limit',$limit,PDO::PARAM_INT);
        $stmt->bindValue(':offset',$offset,PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->fetchAll();
    }

    function fetch_task(int $taskId): ?array {
        $stmt = get_pdo()->prepare("SELECT t.*, b.name AS building_name, r.room_number, r.label AS room_label
                                    FROM tasks t
                                    JOIN buildings b ON b.id=t.building_id
                                    JOIN rooms r ON r.id=t.room_id
                                    WHERE t.id=?");
        $stmt->execute([$taskId]);
        $t = $stmt->fetch();
        return $t ?: null;
    }

    function insert_task(array $data): int {
        // convert '' -> NULL for due_date to avoid "Incorrect date value: ''"
        $due = isset($data['due_date']) && $data['due_date'] !== '' ? $data['due_date'] : null;

        $sql = "INSERT INTO tasks (building_id, room_id, title, description, priority, assigned_to, status, due_date, created_by)
                VALUES (:building_id,:room_id,:title,:description,:priority,:assigned_to,:status,:due_date,:created_by)";
        $stmt = get_pdo()->prepare($sql);
        $stmt->execute([
            ':building_id'=>$data['building_id'],
            ':room_id'=>$data['room_id'],
            ':title'=>$data['title'],
            ':description'=>$data['description'] ?? null,
            ':priority'=>$data['priority'] ?? '',
            ':assigned_to'=>$data['assigned_to'] ?? null,
            ':status'=>$data['status'] ?? 'open',
            ':due_date'=>$due,
            ':created_by'=>$data['created_by'] ?? null,
        ]);
        return (int)get_pdo()->lastInsertId();
    }

    function update_task(int $taskId, array $data): void {
        $due = isset($data['due_date']) && $data['due_date'] !== '' ? $data['due_date'] : null;

        $sql = "UPDATE tasks SET building_id=:building_id, room_id=:room_id, title=:title,
                description=:description, priority=:priority, assigned_to=:assigned_to,
                status=:status, due_date=:due_date WHERE id=:id";
        $stmt = get_pdo()->prepare($sql);
        $stmt->execute([
            ':building_id'=>$data['building_id'],
            ':room_id'=>$data['room_id'],
            ':title'=>$data['title'],
            ':description'=>$data['description'] ?? null,
            ':priority'=>$data['priority'] ?? '',
            ':assigned_to'=>$data['assigned_to'] ?? null,
            ':status'=>$data['status'] ?? 'open',
            ':due_date'=>$due,
            ':id'=>$taskId,
        ]);
    }

    function delete_task(int $taskId): void {
        // Delete S3 photos first (best-effort)
        foreach (fetch_task_photos($taskId) as $p) {
            try { s3_client()->deleteObject(['Bucket'=>S3_BUCKET,'Key'=>$p['s3_key']]); } catch (Throwable $e) {}
        }
        $stmt = get_pdo()->prepare('DELETE FROM tasks WHERE id=?');
        $stmt->execute([$taskId]);
    }

    function upsert_photo(int $taskId, int $position, string $key, string $url): void {
        $sql = "INSERT INTO task_photos (task_id,position,s3_key,url)
                VALUES (:task_id,:position,:s3_key,:url)
                ON DUPLICATE KEY UPDATE s3_key=VALUES(s3_key), url=VALUES(url), created_at=NOW()";
        $stmt = get_pdo()->prepare($sql);
        $stmt->execute([':task_id'=>$taskId,':position'=>$position,':s3_key'=>$key,':url'=>$url]);
    }

    function remove_photo(int $photoId): void {
        $pdo = get_pdo();
        $stmt = $pdo->prepare('SELECT * FROM task_photos WHERE id=?');
        $stmt->execute([$photoId]);
        $p = $stmt->fetch();
        if ($p) {
            try { s3_client()->deleteObject(['Bucket'=>S3_BUCKET,'Key'=>$p['s3_key']]); } catch (Throwable $e) {}
            $pdo->prepare('DELETE FROM task_photos WHERE id=?')->execute([$photoId]);
        }
    }

    function get_filter_values(): array {
    $rawSearch = $_GET['search'] ?? ($_GET['q'] ?? '');
    return [
        'search'       => trim((string)$rawSearch),
        'building_id'  => ($_GET['building_id'] ?? '') !== '' ? (int)$_GET['building_id'] : null,
        'room_id'      => ($_GET['room_id'] ?? '') !== '' ? (int)$_GET['room_id'] : null,
        'priority'     => isset($_GET['priority']) ? array_filter((array)$_GET['priority'], fn($p)=>$p!=='') : [],
        'status'       => $_GET['status'] ?? '',
        'assigned_to'  => trim((string)($_GET['assigned_to'] ?? '')),
        'created_from' => $_GET['created_from'] ?? '',
        'created_to'   => $_GET['created_to'] ?? '',
        'due_from'     => $_GET['due_from'] ?? '',
        'due_to'       => $_GET['due_to'] ?? '',
        'has_photos'   => $_GET['has_photos'] ?? '',
    ];
}

    function filter_summary(array $f): string {
        $parts = [];
        if ($f['search']) $parts[] = 'Search: "'.sanitize($f['search']).'"';
        if ($f['building_id']) { $b = fetch_building_name($f['building_id']); if ($b) $parts[]='Building: '.sanitize($b); }
        if ($f['room_id']) { $r = fetch_room_label($f['room_id']); if ($r) $parts[]='Room: '.sanitize($r); }
        if ($f['priority']) $parts[] = 'Priority: '.implode(', ', array_map('priority_label',$f['priority']));
        if ($f['status']) $parts[] = 'Status: '.status_label($f['status']);
        if ($f['assigned_to']) $parts[] = 'Assigned To: '.sanitize($f['assigned_to']);
        if ($f['created_from'] || $f['created_to']) $parts[]='Created: '.($f['created_from']?:'any').' to '.($f['created_to']?:'any');
        if ($f['due_from'] || $f['due_to']) $parts[]='Due: '.($f['due_from']?:'any').' to '.($f['due_to']?:'any');
        if ($f['has_photos']!=='') $parts[] = $f['has_photos']==='1' ? 'Has Photos' : 'No Photos';
        return $parts ? implode(' • ', $parts) : 'No filters applied';
    }

    function fetch_building_name(int $buildingId): ?string {
        $stmt = get_pdo()->prepare('SELECT name FROM buildings WHERE id=?');
        $stmt->execute([$buildingId]);
        $v = $stmt->fetchColumn();
        return $v !== false ? $v : null;
    }

    function fetch_room_label(int $roomId): ?string {
        $stmt = get_pdo()->prepare('SELECT CONCAT(room_number, IF(label IS NULL OR label="", "", CONCAT(" - ", label))) FROM rooms WHERE id=?');
        $stmt->execute([$roomId]);
        $v = $stmt->fetchColumn();
        return $v !== false ? $v : null;
    }

    function validate_task_payload(array $data, array &$errors): bool {
        $errors=[];
        if (empty($data['building_id'])) $errors['building_id']='Building is required';
        if (empty($data['room_id'])) $errors['room_id']='Room is required';
        if (empty(trim($data['title'] ?? ''))) $errors['title']='Title is required';
        if (!in_array($data['priority'] ?? '', get_priorities(), true)) $errors['priority']='Invalid priority';
        if (!in_array($data['status'] ?? 'open', get_statuses(), true)) $errors['status']='Invalid status';
        if (!empty($data['due_date']) && !preg_match('/^\d{4}-\d{2}-\d{2}$/', (string)$data['due_date'])) $errors['due_date']='Due date must be YYYY-MM-DD';
        return empty($errors);
    }

    function ensure_building_room_valid(int $buildingId, int $roomId): bool {
        $stmt = get_pdo()->prepare('SELECT COUNT(*) FROM rooms WHERE id=? AND building_id=?');
        $stmt->execute([$roomId,$buildingId]);
        return (bool)$stmt->fetchColumn();
    }

    function get_age_bucket_sql(): string {
        return "CASE
            WHEN DATEDIFF(CURDATE(), DATE(t.created_at)) <= 7 THEN '0-7'
            WHEN DATEDIFF(CURDATE(), DATE(t.created_at)) BETWEEN 8 AND 14 THEN '8-14'
            WHEN DATEDIFF(CURDATE(), DATE(t.created_at)) BETWEEN 15 AND 30 THEN '15-30'
            ELSE '>30' END";
    }

    function analytics_counts(): array {
        $pdo = get_pdo();
        $open    = $pdo->query("SELECT COUNT(*) FROM tasks WHERE status='open'")->fetchColumn();
        $done30  = $pdo->query("SELECT COUNT(*) FROM tasks WHERE status='done' AND updated_at >= (CURDATE() - INTERVAL 30 DAY)")->fetchColumn();
        $dueWeek = $pdo->query("SELECT COUNT(*) FROM tasks WHERE status <> 'done' AND due_date BETWEEN CURDATE() AND (CURDATE() + INTERVAL 7 DAY)")->fetchColumn();
        $overdue = $pdo->query("SELECT COUNT(*) FROM tasks WHERE status <> 'done' AND due_date IS NOT NULL AND due_date < CURDATE()")->fetchColumn();
        return ['open'=>(int)$open,'done30'=>(int)$done30,'dueWeek'=>(int)$dueWeek,'overdue'=>(int)$overdue];
    }

    function analytics_group(string $sql): array {
        return get_pdo()->query($sql)->fetchAll();
    }

    function export_tasks(array $filters): array {
        $params=[]; $where=build_task_filter_query($filters,$params);
        $sql="SELECT t.*, b.name AS building_name, r.room_number, r.label AS room_label
              FROM tasks t
              JOIN buildings b ON b.id=t.building_id
              JOIN rooms r ON r.id=t.room_id
              $where
              ORDER BY b.name, r.room_number, t.priority DESC, t.created_at DESC";
        $stmt=get_pdo()->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    function fetch_tasks_by_ids(array $ids): array {
        if (empty($ids)) return [];
        $ph = implode(',', array_fill(0,count($ids),'?'));
        $sql="SELECT t.*, b.name AS building_name, r.room_number, r.label AS room_label
              FROM tasks t
              JOIN buildings b ON b.id=t.building_id
              JOIN rooms r ON r.id=t.room_id
              WHERE t.id IN ($ph)
              ORDER BY t.created_at DESC";
        $stmt=get_pdo()->prepare($sql);
        $stmt->execute($ids);
        return $stmt->fetchAll();
    }

    function room_tasks(int $roomId): array {
        $stmt = get_pdo()->prepare("SELECT t.*, b.name AS building_name, r.room_number, r.label AS room_label
                                    FROM tasks t
                                    JOIN buildings b ON b.id=t.building_id
                                    JOIN rooms r ON r.id=t.room_id
                                    WHERE t.room_id=:room
                                    ORDER BY t.status, t.priority DESC, t.created_at DESC");
        $stmt->execute([':room'=>$roomId]);
        return $stmt->fetchAll();
    }

    function group_tasks_by_status(array $tasks): array {
        $g=['open'=>[],'in_progress'=>[],'done'=>[]];
        foreach ($tasks as $t) { $g[$t['status']][]=$t; }
        return $g;
    }

    function task_photo_thumbnails(int $taskId): array {
        $photos = fetch_task_photos($taskId);  // indexed by position already
        $out = [];
        for ($i = 1; $i <= 3; $i++) {
            $out[$i] = !empty($photos[$i]) ? photo_public_url($photos[$i], 900) : null;
        }
        return $out;
    }

    function fetch_photos_for_tasks(array $ids): array {
        if (empty($ids)) return [];
        $ph = implode(',', array_fill(0,count($ids),'?'));
        $stmt = get_pdo()->prepare("SELECT * FROM task_photos WHERE task_id IN ($ph) ORDER BY task_id, position");
        $stmt->execute($ids);
        $out=[];
        while ($r=$stmt->fetch()) { $out[$r['task_id']][]=$r; }
        return $out;
    }

    function json_response(array $data, int $status=200): void {
        http_response_code($status);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }

    /* =====================
       CORE user helpers
       ===================== */

    /**
     * Primary lookup: find a CORE user by email.
     * Returns role/sector slugs if available.
     */
    function core_find_user_by_email(string $email): ?array {
        try {
            $pdo = get_pdo('core');
            $sql = "SELECT u.*,
                           r.key_slug  AS role_slug,  r.label AS role_label,
                           s.key_slug  AS sector_slug, s.name AS sector_name
                    FROM users u
                    JOIN roles r   ON r.id = u.role_id
                    LEFT JOIN sectors s ON s.id = u.sector_id
                    WHERE u.email = ?
                    LIMIT 1";
            $st = $pdo->prepare($sql);
            $st->execute([$email]);
            $u = $st->fetch();
            return $u ?: null;
        } catch (Throwable $e) {
            return null;
        }
    }

    /**
     * Cached lookup by CORE id (used by current_user()).
     * (Implementation in CODEGEN block below uses get_pdo('core').)
     */

    /* ===== Permission & activity (CODEGEN EXTENSIONS) ===== */

    /* CODEGEN EXTENSIONS START */
    function core_user_record(int $userId): ?array {
        static $cache = [];
        if (array_key_exists($userId, $cache)) {
            return $cache[$userId];
        }
        try {
            $stmt = get_pdo('core')->prepare('SELECT u.*, r.key_slug AS role_key FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = ?');
            $stmt->execute([$userId]);
            $row = $stmt->fetch();
            if ($row) {
                $cache[$userId] = $row;
                return $row;
            }
        } catch (Throwable $e) {
            $cache[$userId] = null;
        }
        return $cache[$userId] ?? null;
    }

    function current_user_role_key(): string {
        $user = current_user();
        if (!$user) {
            return 'viewer';
        }
        $record = null;
        if (!empty($user['id'])) {
            $record = core_user_record((int)$user['id']);
        }
        if ($record && !empty($record['role_key'])) {
            return (string)$record['role_key'];
        }
        if (!empty($user['role'])) {
            return (string)$user['role'];
        }
        return 'viewer';
    }

    function current_user_sector_id(): ?int {
        $user = current_user();
        if (!$user || empty($user['id'])) {
            return null;
        }
        $record = core_user_record((int)$user['id']);
        if ($record && isset($record['sector_id'])) {
            return $record['sector_id'] !== null ? (int)$record['sector_id'] : null;
        }
        return null;
    }

    function can(string $perm): bool {
        $role = current_user_role_key();
        if ($role === 'root') {
            return true;
        }
        $map = [
            'viewer' => ['view', 'download'],
            'admin'  => ['view', 'download', 'edit', 'inventory_manage'],
        ];
        return in_array($perm, $map[$role] ?? [], true);
    }

    function require_perm(string $perm): void {
        require_login();
        if (!can($perm)) {
            http_response_code(403);
            exit('Forbidden');
        }
    }

    function enforce_not_suspended(): void {
        $user = current_user();
        if (!$user || empty($user['id'])) {
            return;
        }
        $record = core_user_record((int)$user['id']);
        if ($record && !empty($record['suspended_at'])) {
            // hard logout
            unset($_SESSION['uid'], $_SESSION['user']);
            $_SESSION['flash'] = ['message' => 'Account suspended.', 'type' => 'error'];
            header('Location: login.php');
            exit;
        }
    }
    /* ===================== NOTES SHARING HELPERS ===================== */


/** Fetch {id,email} options from CORE DB for a <select> list. */
function core_user_options(): array {
    try {
        $core = get_pdo('core');
        $st = $core->query("SELECT id, email FROM users WHERE suspended_at IS NULL ORDER BY email");
        return $st->fetchAll();
    } catch (Throwable $e) {
        return [];
    }
}


function require_root(): void {
  if (current_user_role_key() !== 'root') {
    http_response_code(403);
    exit('Forbidden');
  }
}
function notify_users(array $userIds, string $type, string $title, string $body, ?string $link = null, array $payload = []): void {
    if (!$userIds) return;
    $pdo = get_pdo();
    $now = date('Y-m-d H:i:s');
    $sql = "INSERT INTO notifications (user_id, type, title, body, link, payload, created_at)
            VALUES (:user_id, :type, :title, :body, :link, :payload, :created_at)";
    $stmt = $pdo->prepare($sql);
    $json = $payload ? json_encode($payload, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES) : null;

    $seen = [];
    foreach ($userIds as $uid) {
        $uid = (int)$uid;
        if (!$uid || isset($seen[$uid])) continue;
        $seen[$uid] = true;
        $stmt->execute([
            ':user_id'    => $uid,
            ':type'       => $type,
            ':title'      => $title,
            ':body'       => $body,
            ':link'       => $link,
            ':payload'    => $json,
            ':created_at' => $now,
        ]);
    }
}



// Improved log_event(): richer context, safe meta, better IP detection
function log_event(string $action, ?string $type = null, ?int $id = null, array $meta = []): void
{
    // Optional sampling to reduce volume (0.0–1.0). Define LOG_SAMPLE_RATE if you want.
    if (defined('LOG_SAMPLE_RATE')) {
        $r = mt_rand() / mt_getrandmax();
        if ($r > (float)LOG_SAMPLE_RATE) return;
    }

    // Get PDO (core)
    try {
        $pdo = get_pdo('core');
    } catch (Throwable $e) {
        return; // If logging DB is down, never break the app
    }

    // Who
    $userId = null;
    $user   = null;
    try { $user = current_user(); } catch (Throwable $e) {}
    if (is_array($user) && isset($user['id'])) {
        $userId = (int)$user['id'];
    }

    // Role / sector (if available in your helpers)
    $roleKey    = function_exists('current_user_role_key')   ? (string)(current_user_role_key() ?? '')   : '';
    $sectorId   = function_exists('current_user_sector_id')  ? (current_user_sector_id() ?? null)        : null;

    // Request basics
    $method     = $_SERVER['REQUEST_METHOD'] ?? '';
    $uri        = $_SERVER['REQUEST_URI'] ?? '';
    $path       = (string)(parse_url($uri, PHP_URL_PATH) ?? '');
    $ref        = $_SERVER['HTTP_REFERER'] ?? '';
    $ua         = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);

    // Request timing
    $t0         = (float)($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true));
    $durationMs = (int)round((microtime(true) - $t0) * 1000);

    // Generate / reuse a per-request id (good for correlating multiple logs in one request)
    if (!defined('REQUEST_ID')) {
        define('REQUEST_ID', bin2hex(random_bytes(8))); // 16-hex request id
    }
    $requestId = REQUEST_ID;

    // IP detection with X-Forwarded-For (don’t trust it blindly on the open internet; works fine if you’re behind a known proxy)
    $xffHeader  = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
    $chain      = array_values(array_filter(array_map('trim', explode(',', $xffHeader)), fn($v) => $v !== ''));
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? null;

    // Choose a candidate IP (first in XFF chain, else REMOTE_ADDR)
    $ipCandidate = $chain[0] ?? $remoteAddr;
    $ipBinary    = null;
    if ($ipCandidate) {
        $packed = @inet_pton($ipCandidate);
        if ($packed !== false) $ipBinary = $packed;
    }

    // Scrub sensitive keys in meta and add context under "_ctx"
    $meta = _log_scrub_meta($meta);
    $meta['_ctx'] = [
        'request_id' => $requestId,
        'method'     => $method,
        'path'       => $path,
        'referer'    => $ref,
        'duration_ms'=> $durationMs,
        'role'       => $roleKey,
        'sector_id'  => $sectorId,
        'ip_source'  => $chain ? 'xff' : 'remote_addr',
        'ip_chain'   => $chain,      // full chain kept in meta (string list)
    ];

    // App/env hints if you have them
    if (defined('APP_TITLE'))   $meta['_ctx']['app'] = (string)APP_TITLE;
    if (defined('APP_ENV'))     $meta['_ctx']['env'] = (string)APP_ENV;
    if (defined('APP_VERSION')) $meta['_ctx']['ver'] = (string)APP_VERSION;

    // Safe JSON encode with size guard (prevents oversized meta from blowing up)
    $metaJson = _log_safe_json($meta, 65535); // ~64KB safety limit

    try {
        $stmt = $pdo->prepare(
            'INSERT INTO activity_log (user_id, action, entity_type, entity_id, meta, ip, ua)
             VALUES (:user_id, :action, :entity_type, :entity_id, :meta, :ip, :ua)'
        );
        $stmt->execute([
            ':user_id'     => $userId,
            ':action'      => $action,
            ':entity_type' => $type,
            ':entity_id'   => $id,
            ':meta'        => $metaJson,
            ':ip'          => $ipBinary,
            ':ua'          => $ua,
        ]);
    } catch (Throwable $e) {
        // swallow logging errors
    }
}

/**
 * Scrub sensitive keys from meta recursively.
 * Redacts common secrets (passwords, tokens, cookies, auth headers, etc.).
 */
function _log_scrub_meta(array $meta): array
{
    $sensitive = [
        'password','password1','password2','pass','passwd','pwd',
        'password_hash','hash','token','access_token','refresh_token','id_token',
        'secret','client_secret','api_key','apikey','authorization','auth','cookie','cookies','phpessid','phpsessid','csrf','_csrf'
    ];

    $scrub = function ($value) use (&$scrub, $sensitive) {
        if (is_array($value)) {
            $out = [];
            foreach ($value as $k => $v) {
                $keyLower = is_string($k) ? strtolower($k) : $k;
                if (is_string($keyLower) && in_array($keyLower, $sensitive, true)) {
                    $out[$k] = '[REDACTED]';
                } else {
                    $out[$k] = $scrub($v);
                }
            }
            return $out;
        }
        if (is_object($value)) {
            // Convert to array to scrub
            return $scrub((array)$value);
        }
        if (is_string($value)) {
            // Avoid accidental huge strings in meta
            if (strlen($value) > 8000) {
                return substr($value, 0, 8000) . '…[truncated]';
            }
        }
        return $value;
    };

    return $scrub($meta);
}

/**
 * Safe JSON encoder with fallback and size cap.
 * - Forces UTF-8
 * - Truncates beyond $maxBytes (roughly)
 */
function _log_safe_json(array $data, int $maxBytes = 65535): ?string
{
    // Best-effort: ensure strings are UTF-8
    $normalize = function ($v) use (&$normalize) {
        if (is_array($v)) {
            foreach ($v as $k => $vv) $v[$k] = $normalize($vv);
            return $v;
        }
        if (is_object($v)) return $normalize((array)$v);
        if (is_string($v)) {
            if (!mb_detect_encoding($v, 'UTF-8', true)) {
                $v = mb_convert_encoding($v, 'UTF-8');
            }
            return $v;
        }
        return $v;
    };
    $clean = $normalize($data);

    $json = json_encode($clean, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        // As a last resort, stringify minimally
        $json = '{"_error":"json_encode_failed"}';
    }

    if ($maxBytes > 0 && strlen($json) > $maxBytes) {
        // Try to shrink by replacing large subtrees
        $json = _log_shrink_json($clean, $maxBytes);
    }

    return $json;
}

/**
 * Try to shrink JSON to fit within $maxBytes by truncating large strings/arrays.
 */
function _log_shrink_json(array $data, int $maxBytes): string
{
    // Flatten and spot the biggest strings/arrays to trim
    $queue = [ &$data ];
    $budget = $maxBytes;

    // Pass 1: aggressive truncation of long strings
    $truncate = function (&$node, $limit = 1024) use (&$truncate) {
        if (is_array($node)) {
            foreach ($node as &$v) $truncate($v, $limit);
            unset($v);
        } elseif (is_string($node) && strlen($node) > $limit) {
            $node = substr($node, 0, $limit) . '…[truncated]';
        }
    };
    $truncate($data, 1024);

    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json !== false && strlen($json) <= $maxBytes) {
        return $json;
    }

    // Pass 2: harder truncation
    $truncate($data, 256);
    $json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json !== false && strlen($json) <= $maxBytes) {
        return $json;
    }

    // Final fallback
    return '{"_note":"meta_truncated"}';
}

    /* CODEGEN EXTENSIONS END */
}
