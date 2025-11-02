<?php
require_once __DIR__ . '/helpers.php';
require_login();

use Dompdf\Dompdf;

$roomId = (int)($_GET['room_id'] ?? 0);
$roomLabel = fetch_room_label($roomId);
if (!$roomLabel) {
    exit('Room not found');
}

$tasks = room_tasks($roomId);
$grouped = group_tasks_by_status($tasks);
$photos = fetch_photos_for_tasks(array_column($tasks, 'id'));

$html = '<html><head><style>';
$html .= 'body{font-family:Arial,sans-serif;font-size:12px;color:#1f2933;}';
$html .= 'h1{font-size:20px;margin-bottom:6px;}';
$html .= 'h2{font-size:16px;margin-top:18px;}';
$html .= '.task{margin-bottom:14px;}';
$html .= '.badge{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;text-transform:uppercase;margin-right:4px;}';
$html .= '.priority-high{background:#fde2e1;color:#d64545;}';
$html .= '.priority-mid{background:#fff3c4;color:#b7791f;}';
$html .= '.priority-low{background:#e1f5e0;color:#2d9d78;}';
$html .= '.priority-none{background:#e4e7eb;color:#52606d;}';
$html .= '.photos{display:flex;gap:6px;flex-wrap:wrap;}';
$html .= '.photos img{width:150px;height:110px;object-fit:cover;border-radius:4px;}';
$html .= '</style></head><body>';
$html .= '<h1>Room Punch List</h1>';
$html .= '<p><strong>Room:</strong> ' . htmlspecialchars($roomLabel) . '</p>';
$html .= '<p><strong>Total tasks:</strong> ' . count($tasks) . '</p>';

foreach (['open' => 'Open', 'in_progress' => 'In Progress', 'done' => 'Done'] as $statusKey => $label) {
    $html .= '<h2>' . $label . ' (' . count($grouped[$statusKey]) . ')</h2>';
    foreach ($grouped[$statusKey] as $task) {
        $priorityClass = 'priority-' . ($task['priority'] ?: 'none');
        $html .= '<div class="task">';
        $html .= '<h3>#' . $task['id'] . ' ' . htmlspecialchars($task['title']) . '</h3>';
        $html .= '<div><span class="badge ' . $priorityClass . '">' . htmlspecialchars(priority_label($task['priority'])) . '</span> ';
        $html .= '<strong>Assigned:</strong> ' . htmlspecialchars($task['assigned_to'] ?? '') . ' | ';
        $html .= '<strong>Due:</strong> ' . ($task['due_date'] ? htmlspecialchars($task['due_date']) : '—') . ' | ';
        $html .= '<strong>Created:</strong> ' . htmlspecialchars($task['created_at']) . ' | ';
        $html .= '<strong>Updated:</strong> ' . ($task['updated_at'] ? htmlspecialchars($task['updated_at']) : '—') . '</div>';
        if (!empty($task['description'])) {
            $html .= '<p>' . nl2br(htmlspecialchars($task['description'])) . '</p>';
        }
        if (!empty($photos[$task['id']])) {
            $html .= '<div class="photos">';
            foreach ($photos[$task['id']] as $photo) {
                $html .= '<img src="' . htmlspecialchars($photo['url']) . '" alt="Photo">';
            }
            $html .= '</div>';
        }
        $html .= '</div>';
    }
}

$html .= '</body></html>';

$dompdf = new Dompdf(['isRemoteEnabled' => true]);
$dompdf->loadHtml($html);
$dompdf->setPaper('A4', 'portrait');
$dompdf->render();
$dompdf->stream('room-' . $roomId . '-punch-list.pdf', ['Attachment' => false]);
