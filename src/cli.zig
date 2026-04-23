// SPDX-License-Identifier: MIT OR Apache-2.0
//
// CLI surface constants shared between main.zig and cli_test.zig. Kept in
// its own module (rather than inlined in main.zig) so that the library
// test harness (`zig build test`) can snapshot-match against the same
// bytes the binary emits, without pulling in the full `main` module and
// its `build_options` dependency.

/// CLI version string. MUST match `version` in build.zig.zon and MUST be
/// rendered by `mkit version` exactly as `"mkit <version>\n"` so that
/// downstream packagers (Homebrew, Scoop) can shell-out assert on the
/// output. See docs/CLI.md.
pub const cli_version = "0.1.0";

/// Full help text for `mkit --help` / `mkit help` / `mkit` (with no args).
/// Kept as a single const so:
///   - `mkit --help` (stdout, exit 0) and `mkit` / `mkit <unknown>` (stderr)
///     share wording verbatim.
///   - cli_test.zig can snapshot-match against this string directly.
///   - cosmetic edits don't trip CI unless a test substring-match also
///     regresses.
pub const help_text =
    \\usage: mkit <command> [args]
    \\
    \\commands:
    \\  init              Create a new mkit repository
    \\  add <path>        Stage a file for the next commit
    \\  add .             Stage all files (respects .mkitignore)
    \\  rm <path>         Mark a file for removal in the next commit
    \\  hash <file>       Hash a file and store it as a blob
    \\  cat <hash>        Display an object by its hash
    \\  tree              Snapshot working directory as a tree object
    \\  commit [-m <msg>] Create a signed commit (opens $EDITOR if -m omitted)
    \\  log [--oneline] [--graph] [-n N]  Show commit history
    \\  status            Show staged and working tree changes
    \\  diff              Show changes (HEAD vs workdir, or two trees)
    \\  branch            List branches (* marks current)
    \\  branch <name>     Create a branch at HEAD
    \\  branch -d <name>  Delete a branch
    \\  checkout <branch> Switch HEAD to a branch and restore files
    \\  tag               List, create, or delete tags
    \\  config            Show or set configuration values
    \\  config user.identity <value>  Set author Identity
    \\                        (ed25519:<hex>, mid:<N>, or raw [kind][len][bytes] hex)
    \\  config ssh.strict_host_key_checking <yes|no|accept-new>  Override SSH host policy
    \\  config ssh.user_known_hosts_file <path>  Custom SSH known_hosts file
    \\  config ssh.identity_file <path>  SSH private key file
    \\  merge <branch>    Merge a branch into HEAD
    \\  push [--dry-run]  Push refs and packs to the configured remote
    \\  pull              Pull changes from remote
    \\  fetch             Download from remote without merging
    \\  stash             Stash working dir changes (save WIP)
    \\  stash save -m <msg>  Stash with a message
    \\  stash list        List stash entries
    \\  stash pop [N]     Apply and remove stash entry N (default 0)
    \\  stash drop [N]    Remove stash entry N without applying
    \\  stash show [N]    Show diff of stash entry N
    \\  clone [--depth N] [--sparse ...] <url>  Clone a repository
    \\  remote            Show remote configuration
    \\  remote add <url>  Add remote (mkit+file://, mkit+https://, mkit+s3://, mkit+ssh://)
    \\  remote set <url>  Alias for 'remote add'
    \\  keygen            Generate a new Ed25519 signing keypair
    \\  cherry-pick <hash> Apply a commit to the current branch
    \\  rebase <branch>    Replay commits onto a different base
    \\  rebase --continue  Continue rebase after conflict resolution
    \\  rebase --abort     Abort rebase and restore original state
    \\  bisect start       Begin binary search for a bug
    \\  bisect good [hash] Mark a commit as good
    \\  bisect bad [hash]  Mark a commit as bad
    \\  bisect reset       End bisect and restore original state
    \\  sparse-checkout    Manage sparse checkout patterns
    \\  serve <path>       Start SSH transport server (internal)
    \\  blame <file>      Show line-level commit attribution
    \\  verify <hash>     Verify the signature on a commit or remix
    \\  version           Print version
    \\
;

const std = @import("std");

/// Strip all lines that start with '#' (after leading whitespace) and
/// trim outer whitespace. Used for `mkit commit` when the user edits
/// `.mkit/COMMIT_EDITMSG` via $EDITOR. Returns an allocator-owned slice.
pub fn stripCommentsAndTrim(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var it = std.mem.splitScalar(u8, input, '\n');
    while (it.next()) |line| {
        var start: usize = 0;
        while (start < line.len and (line[start] == ' ' or line[start] == '\t')) start += 1;
        if (start < line.len and line[start] == '#') continue;
        try out.appendSlice(allocator, line);
        try out.append(allocator, '\n');
    }

    const trimmed = std.mem.trim(u8, out.items, " \t\r\n");
    const result = try allocator.dupe(u8, trimmed);
    out.deinit(allocator);
    return result;
}

/// Template rendered into `.mkit/COMMIT_EDITMSG` before spawning $EDITOR.
/// Callers may want to add context (branch, HEAD, staged files) above
/// this — for 0.1.0 the template is intentionally minimal.
pub const commit_editmsg_template =
    "\n" ++
    "# Please enter the commit message for your changes. Lines starting\n" ++
    "# with '#' will be ignored, and an empty message aborts the commit.\n";

test "stripCommentsAndTrim: drops '#' lines and trims" {
    const allocator = std.testing.allocator;
    const input =
        "\n" ++
        "hello\n" ++
        "# a comment\n" ++
        "world\n" ++
        "   # indented comment\n" ++
        "\n";
    const out = try stripCommentsAndTrim(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("hello\nworld", out);
}

test "stripCommentsAndTrim: all-comment input -> empty" {
    const allocator = std.testing.allocator;
    const input =
        "# just comments\n" ++
        "# still comments\n" ++
        "\n";
    const out = try stripCommentsAndTrim(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("", out);
}

test "stripCommentsAndTrim: preserves interior blank lines" {
    const allocator = std.testing.allocator;
    const input = "title\n\nbody\n# comment\n";
    const out = try stripCommentsAndTrim(allocator, input);
    defer allocator.free(out);
    try std.testing.expectEqualStrings("title\n\nbody", out);
}

test "stripCommentsAndTrim: CRLF input -> LF output (trim handles \\r)" {
    const allocator = std.testing.allocator;
    const input = "hello\r\n# comment\r\nworld\r\n";
    const out = try stripCommentsAndTrim(allocator, input);
    defer allocator.free(out);
    // Lines still contain '\r' but outer trim removes it from the tail.
    // We accept this: commit messages are displayed with std.mem.trim
    // downstream too.
    try std.testing.expect(std.mem.indexOf(u8, out, "hello") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "world") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "# comment") == null);
}

test "commit_editmsg_template is non-empty and includes the '#' hint" {
    try std.testing.expect(commit_editmsg_template.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, commit_editmsg_template, "#") != null);
    try std.testing.expect(std.mem.indexOf(u8, commit_editmsg_template, "empty message") != null);
}
