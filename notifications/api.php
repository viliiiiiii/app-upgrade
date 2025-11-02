<?php
// notifications/api.php
require_once __DIR__ . '/../helpers.php';
require_once __DIR__ . '/../includes/notifications.php';
require_login();

$acceptHeader = (string)($_SERVER['HTTP_ACCEPT'] ?? '');
$xhrHeader    = strtolower((string)($_SERVER['HTTP_X_REQUESTED_WITH'] ?? ''));
$wantsJson    = $xhrHeader === 'xmlhttprequest'
  || stripos($acceptHeader, 'application/json') !== false
  || stripos($acceptHeader, 'text/json') !== false;

header('Vary: Accept');

if (!function_exists('notifications_api_respond')) {
    function notifications_api_respond(array $payload, bool $wantsJson, int $status = 200, string $successMessage = '', string $errorMessage = ''): void {
        if ($wantsJson) {
            http_response_code($status);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($payload);
            exit;
        }

        $ok = !empty($payload['ok']);
        $message = $ok
            ? ($successMessage !== '' ? $successMessage : 'Done.')
            : ($errorMessage !== '' ? $errorMessage : ($payload['error'] ?? 'Unable to complete request.'));
        $type = $ok ? 'success' : 'error';
        redirect_with_message('/notifications/index.php', $message, $type);
    }
}

$me = current_user();
$userId = (int)($me['id'] ?? 0);
if (!$userId) {
    notifications_api_respond(['ok' => false, 'error' => 'auth'], $wantsJson, 401, '', 'You need to be signed in to manage notifications.');
}

$action = $_GET['action'] ?? $_POST['action'] ?? '';

try {
    switch ($action) {
        case 'unread_count':
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['ok'=>true,'count'=>notif_unread_count($userId)]);
            break;

        case 'list':
            $limit  = max(1, min(100, (int)($_GET['limit'] ?? 20)));
            $offset = max(0, (int)($_GET['offset'] ?? 0));
            $rows = notif_list($userId, $limit, $offset);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['ok'=>true,'items'=>$rows,'unread'=>notif_unread_count($userId)]);
            break;

        case 'mark_read':
            if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
                notifications_api_respond(['ok'=>false,'error'=>'csrf'], $wantsJson, 422, '', 'We could not verify that request.');
                break;
            }
            $id = (int)($_POST['id'] ?? 0);
            if ($id) {
                notif_mark_read($userId, $id);
            }
            $count = notif_unread_count($userId);
            notifications_api_respond(['ok'=>true,'count'=>$count], $wantsJson, 200, 'Notification marked as read.');
            break;

        case 'mark_all_read':
            if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
                notifications_api_respond(['ok'=>false,'error'=>'csrf'], $wantsJson, 422, '', 'We could not verify that request.');
                break;
            }
            notif_mark_all_read($userId);
            $count = notif_unread_count($userId);
            notifications_api_respond(['ok'=>true,'count'=>$count], $wantsJson, 200, 'All notifications marked as read.');
            break;

        default:
            notifications_api_respond(['ok'=>false,'error'=>'bad_action'], $wantsJson, 400, '', 'Unsupported notification action.');
    }
} catch (Throwable $e) {
    notifications_api_respond(['ok'=>false,'error'=>'server','msg'=>$e->getMessage()], $wantsJson, 500, '', 'Something went wrong while updating notifications.');
}
