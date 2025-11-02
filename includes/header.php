<?php
if (!isset($title)) { $title = APP_TITLE; }
$roleKey = current_user_role_key();
$me = current_user();
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

/** Small helper */
function bc_s($s){ return sanitize($s); }

/** Build breadcrumbs for known routes */
function build_breadcrumbs(string $path): array {
  $crumbs = [
    ['label' => 'Dashboard', 'href' => '/index.php'],
  ];

  // Normalize
  $script = basename($path);
  $dir    = trim(dirname($path), '/');

  // Tasks
  if ($script === 'tasks.php' || preg_match('#^task_#', $script)) {
    $crumbs[] = ['label' => 'Tasks', 'href' => '/tasks.php'];

    if ($script === 'task_view.php' && isset($_GET['id'])) {
      $id = (int)$_GET['id'];
      $crumbs[] = ['label' => "Task #{$id}", 'href' => null];
    } elseif ($script === 'task_edit.php') {
      $id = isset($_GET['id']) ? (int)$_GET['id'] : null;
      if ($id) {
        $crumbs[] = ['label' => "Task #{$id}", 'href' => "/task_view.php?id={$id}"];
        $crumbs[] = ['label' => 'Edit', 'href' => null];
      } else {
        $crumbs[] = ['label' => 'New Task', 'href' => null];
      }
    }
  }

  // Rooms
  if ($script === 'rooms.php' || preg_match('#^rooms(/|$)#', $path)) {
    $crumbs[] = ['label' => 'Rooms', 'href' => '/rooms.php'];
  }

  // Inventory
  if ($script === 'inventory.php' || preg_match('#^inventory(/|$)#', $path)) {
    $crumbs[] = ['label' => 'Inventory', 'href' => '/inventory.php'];
  }

  // Notes
  if (str_starts_with($dir, 'notes') || $dir === 'notes') {
    $crumbs[] = ['label' => 'Notes', 'href' => '/notes/index.php'];
    if ($script === 'view.php' && isset($_GET['id'])) {
      $id = (int)$_GET['id'];
      $crumbs[] = ['label' => "Note #{$id}", 'href' => null];
    } elseif ($script === 'edit.php') {
      $id = isset($_GET['id']) ? (int)$_GET['id'] : null;
      if ($id) {
        $crumbs[] = ['label' => "Note #{$id}", 'href' => "/notes/view.php?id={$id}"];
        $crumbs[] = ['label' => 'Edit', 'href' => null];
      } else {
        $crumbs[] = ['label' => 'New Note', 'href' => null];
      }
    } elseif ($script === 'index.php') {
      // just "Notes" already added
    }
  }

  // Account
  if (str_starts_with($dir, 'account') || $dir === 'account') {
    $crumbs[] = ['label' => 'Account', 'href' => '/account/profile.php'];
    if ($script === 'profile.php') {
      $crumbs[] = ['label' => 'Profile', 'href' => null];
    }
  }

  // Admin
  if (str_starts_with($dir, 'admin') || $dir === 'admin') {
    $crumbs[] = ['label' => 'Admin', 'href' => '/admin/activity.php'];
    if ($script === 'users.php')      $crumbs[] = ['label' => 'Users', 'href' => null];
    if ($script === 'sectors.php')    $crumbs[] = ['label' => 'Sectors', 'href' => null];
    if ($script === 'activity.php')   $crumbs[] = ['label' => 'Activity', 'href' => null];
    if ($script === 'settings.php')   $crumbs[] = ['label' => 'Settings', 'href' => null];
  }

  // If we only have Dashboard and we’re on Dashboard, keep it as one crumb
  // Otherwise, try to add a fall-back current page from $title if needed
  if (count($crumbs) === 1 && ($path !== '/' && $path !== '/index.php')) {
    $label = $script ?: 'Page';
    $crumbs[] = ['label' => $label, 'href' => null];
  }

  return $crumbs;
}

$breadcrumbs = build_breadcrumbs($path);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title><?php echo bc_s($title); ?> - <?php echo bc_s(APP_TITLE); ?></title>
  <link rel="stylesheet" href="/assets/css/app.css?v=pro-1.0">
  <link rel="icon" href="/assets/favicon.ico">
  <meta name="theme-color" content="#f6f9ff">
  <style>
    /* Lightweight breadcrumb styling (move to app.css later if you want) */
    .breadcrumbs { margin: 10px 0 14px; font-size: 13px; color: #475569; }
    .breadcrumbs ol {
      list-style:none; padding:0; margin:0; display:flex; flex-wrap:wrap; gap:6px;
      align-items:center;
    }
    .breadcrumbs li { display:flex; align-items:center; gap:6px; }
    .breadcrumbs a {
      color:#1d4ed8; text-decoration:none; border-bottom:1px solid #93c5fd;
    }
    .breadcrumbs li + li::before {
      content:"/"; color:#94a3b8;
    }
    .breadcrumbs [aria-current="page"] {
      color:#0f172a; font-weight:600; border-bottom: none;
    }
  </style>
</head>
<body>
<header class="navbar">
  <div class="navbar__inner container">
    <a href="/index.php" class="brand" aria-label="<?php echo bc_s(APP_TITLE); ?>">
      <img src="/assets/logo.png" alt="" class="brand__logo">
      <span class="brand__title"><?php echo bc_s(APP_TITLE); ?></span>
    </a>

    <!-- Mobile toggle -->
    <button id="navToggle" class="nav-toggle" aria-label="Open menu" aria-expanded="false" aria-controls="navPanel">
      <span class="bar"></span><span class="bar"></span><span class="bar"></span>
    </button>

    <!-- Collapsible panel -->
    <div id="navPanel" class="nav-panel">
      <nav aria-label="Main">
        <ul class="nav">
          <li>
            <a class="nav__link<?= ($path === '/' || $path === '/index.php') ? ' is-active' : '' ?>"
               <?= ($path === '/' || $path === '/index.php') ? 'aria-current="page"' : '' ?>
               href="/index.php">Dashboard</a>
          </li>

          <li>
            <a class="nav__link<?= preg_match('#^/(tasks\.php|task_)#', $path) ? ' is-active' : '' ?>"
               <?= preg_match('#^/(tasks\.php|task_)#', $path) ? 'aria-current="page"' : '' ?>
               href="/tasks.php">Tasks</a>
          </li>

          <li>
            <a class="nav__link<?= preg_match('#^/rooms(\.php|/|$)#', $path) ? ' is-active' : '' ?>"
               <?= preg_match('#^/rooms(\.php|/|$)#', $path) ? 'aria-current="page"' : '' ?>
               href="/rooms.php">Rooms</a>
          </li>

          <li>
            <a class="nav__link<?= preg_match('#^/inventory(\.php|/|$)#', $path) ? ' is-active' : '' ?>"
               <?= preg_match('#^/inventory(\.php|/|$)#', $path) ? 'aria-current="page"' : '' ?>
               href="/inventory.php">Inventory</a>
          </li>

          <li>
            <a class="nav__link<?= preg_match('#^/notes(/|$)#', $path) ? ' is-active' : '' ?>"
               <?= preg_match('#^/notes(/|$)#', $path) ? 'aria-current="page"' : '' ?>
               href="/notes/index.php">Notes</a>
          </li>
          <?php if ($roleKey === 'root'): ?>
            <li class="nav__sep" aria-hidden="true"></li>

            <li>
              <a class="nav__link<?= preg_match('#^/admin/users(\.php|/|$)#', $path) ? ' is-active' : '' ?>"
                 <?= preg_match('#^/admin/users(\.php|/|$)#', $path) ? 'aria-current="page"' : '' ?>
                 href="/admin/users.php">Users</a>
            </li>

            <li>
              <a class="nav__link<?= preg_match('#^/admin/sectors(\.php|/|$)#', $path) ? ' is-active' : '' ?>"
                 <?= preg_match('#^/admin/sectors(\.php|/|$)#', $path) ? 'aria-current="page"' : '' ?>
                 href="/admin/sectors.php">Sectors</a>
            </li>

            <li>
              <a class="nav__link<?= preg_match('#^/admin/activity(\.php|/|$)#', $path) ? ' is-active' : '' ?>"
                 <?= preg_match('#^/admin/activity(\.php|/|$)#', $path) ? 'aria-current="page"' : '' ?>
                 href="/admin/activity.php">Activity</a>
            </li>
          <?php endif; ?>
        </ul>
      </nav>

      <div class="nav-user">
            <a class="nav__link" href="/notifications/index.php" style="position:relative">
  🔔
  <span id="notifDot" style="display:none;position:absolute;top:-2px;right:-6px;background:#ef4444;color:#fff;border-radius:999px;padding:2px 6px;font-size:10px;font-weight:700;"></span>
</a>

        <?php if ($me): ?>
          <a class="nav-user__email nav-user__profile-link"
             href="/account/profile.php"
             title="Open my profile">
            <?php echo bc_s($me['email'] ?? ''); ?>
          </a>
          <a class="btn small" href="/logout.php">Logout</a>
        <?php else: ?>
          <a class="btn small" href="/login.php">Login</a>
        <?php endif; ?>
      </div>
    </div>
  </div>
</header>

<script>
document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('navToggle');
  const panel = document.getElementById('navPanel');
  if (!btn || !panel) return;
  btn.addEventListener('click', () => {
    const open = panel.classList.toggle('open');
    btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  });
});
</script>
<script>
document.addEventListener('DOMContentLoaded', () => {
  const dot = document.getElementById('notifDot');

  function render(count){
    if (count > 0) { dot.textContent = count; dot.style.display='inline-block'; }
    else { dot.style.display='none'; }
  }

  if ('EventSource' in window) {
    const es = new EventSource('/notifications/stream.php');
    es.addEventListener('count', (e) => {
      try {
        const data = JSON.parse(e.data || '{}');
        render(Number(data.count || 0));
      } catch (_) {}
    });
    es.onerror = () => { /* browser auto-reconnects; no action needed */ };
  } else {
    // Fallback: very light 30s polling if SSE not supported
    async function poll(){
      try {
        const r = await fetch('/notifications/api.php?action=unread_count',{credentials:'same-origin'});
        const j = await r.json();
        if (j && j.ok) render(Number(j.count || 0));
      } catch(_){}
      setTimeout(poll, 30000);
    }
    poll();
  }
});
</script>

<main class="container" id="app-main">
  <!-- Breadcrumbs -->
  <?php if (!empty($breadcrumbs) && is_array($breadcrumbs)): ?>
    <nav class="breadcrumbs" aria-label="Breadcrumb">
      <ol>
        <?php
          $lastIdx = count($breadcrumbs) - 1;
          foreach ($breadcrumbs as $i => $c) {
            $label = bc_s($c['label'] ?? '');
            $href  = $c['href'] ?? null;
            if ($i === $lastIdx || !$href) {
              echo '<li><span aria-current="page">'.$label.'</span></li>';
            } else {
              echo '<li><a href="'.bc_s($href).'">'.$label.'</a></li>';
            }
          }
        ?>
      </ol>
    </nav>
  <?php endif; ?>

  <?php flash_message(); ?>
