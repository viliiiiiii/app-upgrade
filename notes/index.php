<?php
declare(strict_types=1);
require_once __DIR__ . '/lib.php';
require_login();

$meId = (int)(current_user()['id'] ?? 0);
$pdo  = get_pdo();

/* ---------- Local fallbacks if helpers aren't defined ---------- */
if (!function_exists('notes__table_exists')) {
  function notes__table_exists(PDO $pdo, string $tbl): bool {
    try {
      $st = $pdo->prepare("SHOW TABLES LIKE ?");
      $st->execute([$tbl]);
      return (bool)$st->fetchColumn();
    } catch (Throwable $e) { return false; }
  }
}
if (!function_exists('notes__col_exists')) {
  function notes__col_exists(PDO $pdo, string $tbl, string $col): bool {
    try {
      $st = $pdo->prepare("SHOW COLUMNS FROM `{$tbl}` LIKE ?");
      $st->execute([$col]);
      return (bool)$st->fetchColumn();
    } catch (Throwable $e) { return false; }
  }
}

/* ---------- Detect optional schema features ---------- */
$hasSharesTbl  = notes__table_exists($pdo, 'notes_shares');
$sharesHasUser = $hasSharesTbl && notes__col_exists($pdo, 'notes_shares', 'user_id');
$sharesHasOld  = $hasSharesTbl && notes__col_exists($pdo, 'notes_shares', 'shared_with');
$sharesCol     = $sharesHasUser ? 'user_id' : ($sharesHasOld ? 'shared_with' : null);

$hasNoteDate   = notes__col_exists($pdo, 'notes', 'note_date');
$hasCreatedAt  = notes__col_exists($pdo, 'notes', 'created_at');
$hasPhotosTbl  = notes__table_exists($pdo, 'note_photos');
$hasCommentsTbl= notes__table_exists($pdo, 'note_comments');

/* ---------- Filters ---------- */
$search = trim((string)($_GET['q'] ?? ''));
$from   = trim((string)($_GET['from'] ?? ''));
$to     = trim((string)($_GET['to'] ?? ''));

/* ---------- View preference: GET → cookie → default('table') ---------- */
$allowedViews = ['table', 'sticky'];
if (isset($_GET['view']) && in_array($_GET['view'], $allowedViews, true)) {
  $view = $_GET['view'];
} elseif (isset($_COOKIE['notes_view']) && in_array($_COOKIE['notes_view'], $allowedViews, true)) {
  $view = $_COOKIE['notes_view'];
} else {
  $view = 'table';
}
/* Persist cookie (1 year) so server renders preferred view on first paint */
@setcookie('notes_view', $view, time() + 31536000, '/', '', false, true);

$where  = [];
$params = [];

/* Text filter */
if ($search !== '') {
  $where[]        = '(n.title LIKE :q OR COALESCE(n.body,"") LIKE :q)';
  $params[':q']   = '%'.$search.'%';
}
/* Date filters */
if ($hasNoteDate && $from !== '') { $where[] = 'n.note_date >= :from'; $params[':from'] = $from; }
if ($hasNoteDate && $to   !== '') { $where[] = 'n.note_date <= :to';   $params[':to']   = $to;   }

/* ---------- Visibility (non-admin semantics) ---------- */
/* Only owner or explicitly shared-with-me. If shares table/column missing, show own notes only. */
if ($sharesCol) {
  $where[] = "(n.user_id = :me_owner_where
              OR EXISTS (SELECT 1 FROM notes_shares s
                         WHERE s.note_id = n.id
                           AND s.{$sharesCol} = :me_share_where))";

  // WHERE placeholders
  $params[':me_owner_where'] = $meId;
  $params[':me_share_where'] = $meId;

  // SELECT placeholder (some drivers require distinct names)
  $isSharedExpr = "EXISTS(SELECT 1 FROM notes_shares s
                          WHERE s.note_id = n.id
                            AND s.{$sharesCol} = :me_share_select) AS is_shared";
  $params[':me_share_select'] = $meId;

} else {
  $where[] = "n.user_id = :me_owner_where";
  $params[':me_owner_where'] = $meId;
  $isSharedExpr = "0 AS is_shared";
}

$whereSql = $where ? ('WHERE '.implode(' AND ', $where)) : '';

/* ---------- Other selectable columns ---------- */
$photoCountExpr = $hasPhotosTbl
  ? "(SELECT COUNT(*) FROM note_photos p WHERE p.note_id = n.id) AS photo_count"
  : "0 AS photo_count";
$commentCountExpr = $hasCommentsTbl
  ? "(SELECT COUNT(*) FROM note_comments c WHERE c.note_id = n.id) AS comment_count"
  : "0 AS comment_count";

/* ---------- Ordering ---------- */
$orderParts = [];
if ($hasNoteDate)  { $orderParts[] = "n.note_date DESC"; }
if ($hasCreatedAt) { $orderParts[] = "n.created_at DESC"; }
$orderParts[] = "n.id DESC";
$orderSql = " ORDER BY ".implode(', ', $orderParts)." LIMIT 200";

/* ---------- Final SQL ---------- */
$sql = "SELECT
          n.*,
          (n.user_id = :me_owner_select) AS is_owner,
          {$isSharedExpr},
          {$photoCountExpr},
          {$commentCountExpr}
        FROM notes n
        {$whereSql}
        {$orderSql}";
$params[':me_owner_select'] = $meId;

$rows = [];
try {
  $st = $pdo->prepare($sql);
  $st->execute($params);
  $rows = $st->fetchAll();
} catch (Throwable $e) {
  error_log("Notes index query failed: " . $e->getMessage());
  $rows = [];
}

/* ---------- Helper: build toggle URL preserving filters ---------- */
function toggle_view_url(string $targetView): string {
  $q = $_GET;
  $q['view'] = $targetView;
  return 'index.php?' . http_build_query($q);
}

$title = 'Notes';
include __DIR__ . '/../includes/header.php';
?>
<section class="card">
  <div class="card-header">
    <div class="title">Notes</div>
    <div class="actions" style="display:flex; gap:.5rem; flex-wrap:wrap;">
      <a class="btn js-toggle-view"
         href="<?= $view === 'sticky' ? toggle_view_url('table') : toggle_view_url('sticky'); ?>">
        <?= $view === 'sticky' ? 'Table View' : 'Sticky View'; ?>
      </a>
      <a class="btn primary" href="new.php">New Note</a>
    </div>
  </div>

  <form method="get" class="grid three" action="index.php" autocomplete="off">
    <input type="hidden" name="view" value="<?= sanitize($view); ?>">
    <label>Search
      <input type="text" name="q" value="<?= sanitize($search); ?>" placeholder="Title or text">
    </label>
    <label>From
      <input type="date" name="from" value="<?= sanitize($from); ?>" <?= $hasNoteDate ? '' : 'disabled'; ?>>
    </label>
    <label>To
      <input type="date" name="to" value="<?= sanitize($to); ?>" <?= $hasNoteDate ? '' : 'disabled'; ?>>
    </label>
    <div class="form-actions">
      <button class="btn" type="submit">Filter</button>
      <a class="btn secondary" href="index.php?view=<?= $view === 'sticky' ? 'sticky' : 'table'; ?>">Reset</a>
    </div>
  </form>
</section>

<section class="card">


  <?php if (!$rows): ?>
    <p class="muted">No notes yet.</p>

  <?php elseif ($view === 'sticky'): ?>
    <!-- ===== Sticky Notes Grid ===== -->
    <div class="sticky-grid">
      <?php foreach ($rows as $n): ?>
        <?php
          $id     = (int)$n['id'];
          $date   = $n['note_date'] ?? (isset($n['created_at']) ? substr((string)$n['created_at'],0,10) : '');
          $titleV = (string)$n['title'];
          $body   = (string)($n['body'] ?? '');
          $pc     = (int)($n['photo_count'] ?? 0);
          $cc     = (int)($n['comment_count'] ?? 0);
          $isSh   = !empty($n['is_shared']) && empty($n['is_owner']);
          $colorClass = 'c' . (($id % 6) + 1);
          $tiltDeg    = (($id % 5) - 2) * 1.2; // -2.4 .. +2.4 deg
          $trim = function(string $s, int $limit=280): string {
            if (function_exists('mb_strimwidth')) return (string)mb_strimwidth($s, 0, $limit, '…');
            return strlen($s) > $limit ? substr($s,0,$limit-2).'…' : $s;
          };
        ?>
        <article class="postit <?= $colorClass; ?>" style="--tilt: <?= htmlspecialchars((string)$tiltDeg, ENT_QUOTES, 'UTF-8'); ?>deg;">
          <div class="tape" aria-hidden="true"></div>

          <header class="postit-head">
            <span class="postit-date"><?= sanitize($date); ?></span>
            <?php if ($isSh): ?><span class="badge">Shared</span><?php endif; ?>
          </header>

          <h3 class="postit-title">
            <a href="view.php?id=<?= $id; ?>"><?= sanitize($titleV); ?></a>
          </h3>

          <?php if ($body !== ''): ?>
            <p class="postit-body"><?= nl2br(sanitize($trim($body))); ?></p>
          <?php else: ?>
            <p class="postit-body muted">No text.</p>
          <?php endif; ?>

          <footer class="postit-meta">
            <span class="meta-pill" title="Photos">📷 <?= $pc; ?></span>
            <span class="meta-pill" title="Replies">💬 <?= $cc; ?></span>
            <?php if (notes_can_edit($n)): ?>
              <a class="btn tiny" href="edit.php?id=<?= $id; ?>">Edit</a>
            <?php endif; ?>
          </footer>
        </article>
      <?php endforeach; ?>
    </div>

  <?php else: ?>
    <!-- ===== Classic Table ===== -->
    <table class="table">
      <thead>
        <tr><th>Date</th><th>Title</th><th>Photos</th><th>Replies</th><th class="text-right">Actions</th></tr>
      </thead>
      <tbody>
      <?php foreach ($rows as $n): ?>
        <tr>
          <td data-label="Date">
            <?php
              $d = $n['note_date'] ?? null;
              if (!$d && isset($n['created_at'])) $d = substr((string)$n['created_at'], 0, 10);
              echo sanitize((string)$d);
            ?>
          </td>
          <td data-label="Title">
            <?= sanitize($n['title']); ?>
            <?php if (!empty($n['is_shared']) && empty($n['is_owner'])): ?>
              <span class="badge">Shared</span>
            <?php endif; ?>
          </td>
          <td data-label="Photos"><?= (int)($n['photo_count'] ?? 0); ?></td>
          <td data-label="Replies"><?= (int)($n['comment_count'] ?? 0); ?></td>
          <td class="text-right">
            <a class="btn small" href="view.php?id=<?= (int)$n['id']; ?>">View</a>
            <?php if (notes_can_edit($n)): ?>
              <a class="btn small" href="edit.php?id=<?= (int)$n['id']; ?>">Edit</a>
            <?php endif; ?>
          </td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  <?php endif; ?>
</section>

<!-- ===== Sticky View Styles (move into your main CSS if you prefer) ===== -->
<style>
.sticky-grid{
  display:grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}
@media (min-width: 780px){ .sticky-grid{ grid-template-columns: repeat(3,1fr); } }
@media (min-width: 1100px){ .sticky-grid{ grid-template-columns: repeat(4,1fr); } }

.postit{
  position:relative;
  background:#fffbe6; /* default paper */
  border:1px solid #f0e6a6;
  border-radius:16px;
  padding:1rem;
  box-shadow: 0 6px 18px rgba(0,0,0,.06), 0 2px 0 rgba(0,0,0,.04) inset;
  transform: rotate(var(--tilt, 0deg));
  transition: transform .15s ease, box-shadow .15s ease;
  will-change: transform;
  min-height: 220px;
  display:flex; flex-direction:column; gap:.5rem;
}
.postit:hover{
  transform: rotate(0deg) translateY(-2px);
  box-shadow: 0 15px 28px rgba(0,0,0,.08);
}

/* Tape effect */
.postit .tape{
  position:absolute; top:-10px; left:50%; transform: translateX(-50%) rotate(-2deg);
  width:80px; height:24px; background:rgba(255,255,255,.6);
  border:1px solid rgba(0,0,0,.05);
  box-shadow: 0 6px 10px rgba(0,0,0,.05);
  border-radius:4px;
}

/* Headers & body */
.postit-head{ display:flex; align-items:center; justify-content:space-between; gap:.5rem; }
.postit-date{ font-size:.8rem; color:#6b7280; }
.postit-title{ font-size:1rem; line-height:1.2; margin:0; }
.postit-title a{ text-decoration:none; color:#111827; }
.postit-title a:hover{ text-decoration:underline; }
.postit-body{ margin:.25rem 0 .5rem; color:#111827; }

/* Footer meta */
.postit-meta{ margin-top:auto; display:flex; align-items:center; justify-content:flex-start; gap:.5rem; flex-wrap:wrap; }
.meta-pill{
  display:inline-flex; align-items:center; gap:.25rem;
  border:1px solid #e7ecf3; border-radius:999px; padding:.2rem .5rem; font-size:.8rem; background:#fff;
}

/* Color variants (gentle pastels) */
.postit.c1{ background:#fff9db; border-color:#ffe27a; }
.postit.c2{ background:#e7fff3; border-color:#b8f3d2; }
.postit.c3{ background:#eaf4ff; border-color:#bfd9ff; }
.postit.c4{ background:#fff0f6; border-color:#ffc4da; }
.postit.c5{ background:#f3fff0; border-color:#c7f7bc; }
.postit.c6{ background:#f5f0ff; border-color:#dacbff; }

/* Tiny button */
.btn.tiny{ padding:.2rem .45rem; font-size:.75rem; border-radius:8px; }
</style>

<!-- ===== Persist view in localStorage & apply on first visit ===== -->
<script>
(() => {
  const CURRENT = '<?= $view === 'sticky' ? 'sticky' : 'table' ?>';

  // Store current choice so next visits remember it
  try { localStorage.setItem('notes_view', CURRENT); } catch (e) {}

  // If user clicks toggle, pre-store the next view immediately
  document.addEventListener('click', (e) => {
    const a = e.target.closest('.js-toggle-view');
    if (!a) return;
    try {
      const url = new URL(a.href, location.href);
      const next = url.searchParams.get('view') || 'table';
      localStorage.setItem('notes_view', next);
    } catch (e) {}
  });

  // First visit with no ?view=: use localStorage to choose and replace URL once
  (function applyInitialPreference() {
    const params = new URLSearchParams(location.search);
    const hasParam = params.has('view');
    if (hasParam) return;
    try {
      const pref = localStorage.getItem('notes_view');
      if (pref && (pref === 'table' || pref === 'sticky') && pref !== CURRENT) {
        const u = new URL(location.href);
        u.searchParams.set('view', pref);
        location.replace(u.toString());
      }
    } catch (e) {}
  })();
})();
</script>

<?php include __DIR__ . '/../includes/footer.php';
