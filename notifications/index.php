<?php
// notifications/index.php
require_once __DIR__ . '/../helpers.php';
require_once __DIR__ . '/../includes/notifications.php';
require_login();

$me = current_user();
$userId = (int)$me['id'];
$page   = max(1, (int)($_GET['page'] ?? 1));
$per    = 20;
$list   = notif_list($userId, $per, ($page-1)*$per);

$title = 'Notifications';
include __DIR__ . '/../includes/header.php';
?>
<section class="card">
  <div class="card-header">
    <h1>Notifications</h1>
    <div class="actions">
      <form method="post" action="/notifications/api.php" onsubmit="return confirm('Mark all as read?');">
        <input type="hidden" name="action" value="mark_all_read">
        <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
        <button class="btn small" type="submit">Mark all read</button>
      </form>
    </div>
  </div>

  <?php if (!$list): ?>
    <p class="muted">No notifications yet.</p>
  <?php else: ?>
    <ul class="list">
      <?php foreach ($list as $n): ?>
        <li class="list-item" style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
          <div>
            <div style="font-weight:700;">
              <?php echo sanitize($n['title'] ?: $n['type']); ?>
            </div>
            <?php if (!empty($n['body'])): ?>
              <div class="muted"><?php echo nl2br(sanitize($n['body'])); ?></div>
            <?php endif; ?>
            <div class="small muted">
              <?php echo sanitize(substr((string)$n['created_at'],0,16)); ?>
              <?php if (!empty($n['url'])): ?>
                • <a href="<?php echo sanitize($n['url']); ?>">Open</a>
              <?php endif; ?>
              <?php if (!$n['is_read']): ?>
                • <span class="badge">NEW</span>
              <?php endif; ?>
            </div>
          </div>
          <?php if (!$n['is_read']): ?>
            <form method="post" action="/notifications/api.php">
              <input type="hidden" name="action" value="mark_read">
              <input type="hidden" name="id" value="<?php echo (int)$n['id']; ?>">
              <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
              <button class="btn small" type="submit">Mark read</button>
            </form>
          <?php endif; ?>
        </li>
      <?php endforeach; ?>
    </ul>
  <?php endif; ?>
</section>
<?php include __DIR__ . '/../includes/footer.php'; ?>
