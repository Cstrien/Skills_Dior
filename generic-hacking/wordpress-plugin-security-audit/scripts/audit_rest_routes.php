<?php
/**
 * audit_rest_routes.php — static WordPress plugin REST attack-surface auditor.
 *
 * Scans a plugin directory for register_rest_route() registrations and reports:
 *   - routes whose args lack a permission_callback / ROUTE_PERMISSION_CALLBACK (public by default)
 *   - permission callbacks that return true unconditionally (perm-always-true)
 *   - registrar-wrapper gating signals (requires_admin / ROUTE_REQUIRES_ADMIN / current_user_can / is_admin)
 *
 * Heuristic/static — ALWAYS live-verify flagged routes on an installed lab copy:
 *   GET /wp-json/                → routes registered for the current (anon) user
 *   "rest_no_route" 404          → not registered for anon (wrapper skipped it) — NOT a finding
 *   401 rest_forbidden           → registered + auth-gated
 *   200 with data                → confirmed unauth surface
 *
 * Usage: php audit_rest_routes.php /path/to/plugin
 * Exit codes: 0 = scanned, 1 = bad usage, 2 = no PHP files found.
 */

$dir = $argv[1] ?? null;
if (! $dir || ! is_dir($dir)) {
    fwrite(STDERR, "usage: php audit_rest_routes.php <plugin-dir>\n");
    exit(1);
}

$rii = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
);

$gateSignals = ['requires_admin', 'ROUTE_REQUIRES_ADMIN', 'current_user_can', 'is_admin'];
$results     = [];

foreach ($rii as $f) {
    if (! $f->isFile() || strtolower($f->getExtension()) !== 'php') {
        continue;
    }
    $src = @file_get_contents($f->getPathname());
    if ($src === false || strpos($src, 'register_rest_route') === false) {
        continue;
    }

    $pos = 0;
    while (($pos = strpos($src, 'register_rest_route', $pos)) !== false) {
        $line = 1 + substr_count(substr($src, 0, $pos), "\n");

        // Literal namespace/path when present; else mark dynamic (variables/constants).
        $win  = substr($src, $pos, 700);
        $ns = $path = 'dynamic';
        if (preg_match("/register_rest_route\\(\\s*['\"]([^'\"]+)['\"]\\s*,\\s*['\"]([^'\"]+)['\"]/", $win, $m)) {
            [$ns, $path] = [$m[1], $m[2]];
        } elseif (preg_match("/register_rest_route\\(\\s*([A-Za-z_\\\\:\\$]+)/", $win, $m2)) {
            $ns = $m2[1];
        }

        // Context window: args arrays are often built BEFORE the call.
        $start = max(0, $pos - 1400);
        $ctx   = substr($src, $start, 4200);

        $hasPerm  = (strpos($ctx, 'permission_callback') !== false)
                 || (strpos($ctx, 'ROUTE_PERMISSION_CALLBACK') !== false);
        $permTrue = $hasPerm && (bool) preg_match(
            '/permission[^;{]{0,200}?function\\s*\\([^)]*\\)\\s*(use\\s*\\([^)]*\\))?\\s*\\{[^}]{0,120}return\\s+true\\s*;/s',
            $ctx
        );
        if (! $permTrue && $hasPerm) {
            $permTrue = (bool) preg_match('/__return_true/', $ctx);
        }

        $gates = [];
        foreach ($gateSignals as $g) {
            if (strpos($ctx, $g) !== false) {
                $gates[] = $g;
            }
        }

        $verdict = ! $hasPerm ? 'NO-PERM(public-default)' : ($permTrue ? 'PERM=ALWAYS-TRUE' : 'perm=custom');
        $results[] = sprintf(
            "%s:%d | %s | %s | %s | gate=%s",
            substr($f->getPathname(), strlen(rtrim($dir, '/')) + 1),
            $line,
            $ns,
            $path,
            $verdict,
            $gates ? implode('+', $gates) : 'none'
        );

        $pos += 19; // strlen('register_rest_route')
    }
}

if (! $results) {
    echo "No register_rest_route() calls found.\n";
    exit(2);
}

echo "=== REST route audit: {$dir} ===\n";
foreach ($results as $r) {
    echo $r, "\n";
}
$nop = count(array_filter($results, fn ($r) => strpos($r, 'NO-PERM') !== false));
$alt = count(array_filter($results, fn ($r) => strpos($r, 'PERM=ALWAYS-TRUE') !== false));
echo "---\n";
echo "NO-PERM candidates (manual-review list, live-verify each): {$nop}\n";
echo "PERM=ALWAYS-TRUE candidates: {$alt}\n";
echo "Reminder: check the registrar wrapper's default permission + requires_admin semantics\n";
echo "before trusting any of this — and confirm on an installed lab copy via /wp-json/.\n";
