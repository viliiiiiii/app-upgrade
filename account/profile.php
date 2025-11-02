<?php
declare(strict_types=1);

require_once __DIR__ . '/../helpers.php';
require_login();

/* ---------- pick a PDO that actually has `users` ---------- */
function pick_users_pdo(): PDO {
    // Try default (punchlist) first — that's where your `users` table is
    try {
        $pdo = get_pdo();
        $pdo->query('SELECT 1 FROM users LIMIT 1'); // will throw if table missing
        return $pdo;
    } catch (Throwable $e) {
        // Fallback to 'core' if default didn't have the table
        try {
            $pdo2 = get_pdo('core');
            $pdo2->query('SELECT 1 FROM users LIMIT 1');
            return $pdo2;
        } catch (Throwable $e2) {
            // Re-throw the original for clearer context
            throw $e;
        }
    }
}

function fetch_user(PDO $pdo, int $id): ?array {
    $st = $pdo->prepare('SELECT `id`,`email`,`password_hash`,`role`,`created_at` FROM `users` WHERE `id` = ?');
    $st->execute([$id]);
    $u = $st->fetch(PDO::FETCH_ASSOC);
    return $u ?: null;
}

$errors = [];
$me     = current_user();
$userId = (int)($me['id'] ?? 0);

try {
    $pdo  = pick_users_pdo();
    $user = fetch_user($pdo, $userId);
    if (!$user) {
        http_response_code(404);
        exit('User not found.');
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo '<h1>Profile error</h1><p>Could not access the users table. '
       . 'Make sure it exists on the default database (punchlist) or adjust the connection.</p>';
    // Uncomment if you want to see exact error (dev only):
    // echo '<pre>'.htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8').'</pre>';
    exit;
}

/* ---------- POST handlers ---------- */
if (is_post()) {
    if (!verify_csrf_token($_POST[CSRF_TOKEN_NAME] ?? null)) {
        $errors[] = 'Invalid CSRF token.';
    } else {
        $action = (string)($_POST['action'] ?? '');

        if ($action === 'change_email') {
            $newEmail = trim((string)($_POST['email'] ?? ''));
            if ($newEmail === '') {
                $errors[] = 'Email is required.';
            } elseif (!filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
                $errors[] = 'Please enter a valid email address.';
            } else {
                try {
                    $st = $pdo->prepare('SELECT 1 FROM `users` WHERE `email` = ? AND `id` <> ? LIMIT 1');
                    $st->execute([$newEmail, $userId]);
                    if ($st->fetchColumn()) {
                        $errors[] = 'That email is already in use.';
                    }
                } catch (Throwable $e) {
                    $errors[] = 'Could not validate email uniqueness.';
                }
            }

            if (!$errors) {
                try {
                    $oldEmail = (string)$user['email'];
                    $st = $pdo->prepare('UPDATE `users` SET `email` = ? WHERE `id` = ?');
                    $st->execute([$newEmail, $userId]);
                    if (function_exists('log_event')) {
                        log_event('user.email_change', 'user', $userId, ['old' => $oldEmail, 'new' => $newEmail]);
                    }
                    if (isset($_SESSION['user']) && is_array($_SESSION['user'])) {
                        $_SESSION['user']['email'] = $newEmail;
                    }
                    redirect_with_message('/account/profile.php', 'Email updated.', 'success');
                } catch (Throwable $e) {
                    $errors[] = 'Failed to update email.';
                }
            }
        }

        if ($action === 'change_password') {
            $current = (string)($_POST['current_password'] ?? '');
            $new     = (string)($_POST['new_password'] ?? '');
            $confirm = (string)($_POST['confirm_password'] ?? '');

            if ($current === '' || $new === '' || $confirm === '') {
                $errors[] = 'All password fields are required.';
            } elseif (!password_verify($current, (string)$user['password_hash'])) {
                $errors[] = 'Your current password is incorrect.';
            } elseif (strlen($new) < 8) {
                $errors[] = 'New password must be at least 8 characters.';
            } elseif ($new !== $confirm) {
                $errors[] = 'New password and confirmation do not match.';
            }

            if (!$errors) {
                try {
                    $hash = password_hash($new, PASSWORD_DEFAULT);
                    $st = $pdo->prepare('UPDATE `users` SET `password_hash` = ? WHERE `id` = ?');
                    $st->execute([$hash, $userId]);
                    if (function_exists('log_event')) {
                        log_event('user.password_change', 'user', $userId);
                    }
                    redirect_with_message('/account/profile.php', 'Password updated.', 'success');
                } catch (Throwable $e) {
                    $errors[] = 'Failed to update password.';
                }
            }
        }
    }

    // Refresh row after POST (unless we redirected)
    try { $user = fetch_user($pdo, $userId) ?? $user; } catch (Throwable $e) {}
}

/* ---------- View ---------- */
$title = 'My Profile';
include __DIR__ . '/../includes/header.php';
?>
<section class="card">
  <div class="card-header">
    <div class="title">My Profile</div>
    <div class="meta">User #<?php echo (int)$user['id']; ?> · Joined <?php echo sanitize(substr((string)$user['created_at'], 0, 16)); ?></div>
  </div>

  <?php if ($errors): ?>
    <div class="flash flash-error"><?php echo sanitize(implode(' ', $errors)); ?></div>
  <?php endif; ?>

  <div class="grid two">
    <form method="post" class="card">
      <h2>Account</h2>
      <label>Email
        <input type="email" name="email" required value="<?php echo sanitize((string)$user['email']); ?>">
      </label>
      <label>Role
        <input type="text" value="<?php echo sanitize((string)$user['role']); ?>" disabled>
      </label>
      <input type="hidden" name="action" value="change_email">
      <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
      <div class="form-actions">
        <button class="btn primary" type="submit">Save Email</button>
      </div>
    </form>

    <form method="post" class="card">
      <h2>Change Password</h2>
      <label>Current password
        <input type="password" name="current_password" required autocomplete="current-password">
      </label>
      <label>New password
        <input type="password" name="new_password" required autocomplete="new-password" minlength="8" placeholder="At least 8 characters">
      </label>
      <label>Confirm new password
        <input type="password" name="confirm_password" required autocomplete="new-password">
      </label>
      <input type="hidden" name="action" value="change_password">
      <input type="hidden" name="<?php echo CSRF_TOKEN_NAME; ?>" value="<?php echo csrf_token(); ?>">
      <div class="form-actions">
        <button class="btn primary" type="submit">Update Password</button>
      </div>
    </form>
  </div>
</section>

<?php include __DIR__ . '/../includes/footer.php';
