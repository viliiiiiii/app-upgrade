<?php
// notifications/api.php
require_once __DIR__ . '/../helpers.php';
require_once __DIR__ . '/../includes/notifications.php';
require_login();

header('Content-Type: application/json; charset=utf-8');

$me = current_user();
$userId = (int)($me['id'] ?? 0);
if (!$userId) { http_response_code(401); echo json_encode(['ok'=>false,'error'=>'auth']); exit; }

$action = $_GET['action'] ?? $_POST['action'] ?? '';

try {
    switch ($action) {
        case 'unread_count':
            echo json_encode(['ok'=>true,'count'=>notif_unread_count($userId)]);
            break;

        case 'list':
            $limit  = max(1, min(100, (int)($_GET['limit'] ?? 20)));
            $offset = max(0, (int)($_GET['offset'] ?? 0));
            $rows = notif_list($userId, $limit, $offset);
            echo json_encode(['ok'=>true,'items'=>$rows,'unread'=>notif_unread_count($userId)]);
            break;

        case 'mark_read':
            if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
                http_response_code(422); echo json_encode(['ok'=>false,'error'=>'csrf']); break;
            }
            $id = (int)($_POST['id'] ?? 0);
            if ($id) notif_mark_read($userId, $id);
            $count = notif_unread_count($userId);
            echo json_encode(['ok'=>true,'count'=>$count]);
            break;

        case 'mark_all_read':
            if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
                http_response_code(422); echo json_encode(['ok'=>false,'error'=>'csrf']); break;
            }
            notif_mark_all_read($userId);
            $count = notif_unread_count($userId);
            echo json_encode(['ok'=>true,'count'=>$count]);
            break;

        default:
            http_response_code(400);
            echo json_encode(['ok'=>false,'error'=>'bad_action']);
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['ok'=>false,'error'=>'server','msg'=>$e->getMessage()]);
}
