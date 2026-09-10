# changelog.d

Changelog entries for changes which have not been released yet.

A change which is worth mentioning to users of the SDK adds a file to this
directory in the same PR as the change itself. When a release is made, the
entries are merged into `CHANGELOG.md` on the release branch and removed from
this directory.

This way the changelog is written while the change is fresh, by the person who
made it, and two branches never conflict over the same lines in `CHANGELOG.md`.

## Writing an entry

Create `changelog.d/<some-descriptive-name>.md`. The name only has to be unique
and is not shown anywhere; name it after the change, e.g.
`fix-32bit-busy-spin.md` or `stream-statistics.md`.

The file contains one or more sections, written exactly as they should appear in
`CHANGELOG.md`:

```markdown
### Bug fixes
 * Fixed a busy spin in the event queue thread on 32 bit platforms. The
   absolute deadline given to `pthread_cond_timedwait` was narrowed to `long`
   before being divided, which on a 32 bit target placed it in 1970.
```

The valid sections are, in the order they appear in a released version:

 * `### Breaking changes` — users have to change their code or their data.
 * `### Added` — new API, new options, new functionality.
 * `### Changed` — changed behaviour, deprecations, dependency upgrades.
 * `### Removed` — removed API or functionality.
 * `### Bug fixes` — fixes.
 * `### Security` — fixes with a security impact.

Sub-bullets are written as ` * * `, like in `CHANGELOG.md`.

A single entry may use several sections, which is the normal case for a change
that both adds something and breaks something:

```markdown
### Breaking changes
 * The IAM state `fingerprint` field has been replaced by `fingerprints`.

### Added
 * `nm_iam_add_user_fingerprint()` for adding a fingerprint to a user.
```

Write the entry for someone upgrading the SDK: what changed for them, and what
they have to do about it. An entry which only makes sense to us ("refactored
`nc_stream`") is better left out.

## Making a release

Releases are made on a release branch (`5.15`, `5.16`, ...) and the assembled
`CHANGELOG.md` lives on that branch. The entries are folded into it by hand — or
by an AI agent given this section — as follows:

1. Check out the release branch and verify that the changes being released, and
   their entry files, are on it.
2. Read every `changelog.d/*.md` except this `00README.md`.
3. Build one new block headed `## [<version>] <YYYY-MM-DD>`, e.g.
   `## [5.16.0] 2026-09-10`. Note the bare date: the pre-5.11 versions further
   down `CHANGELOG.md` write ` - ` before the date, do not imitate those.
4. In that block, write the sections in the order listed above, leaving out the
   ones nobody wrote. Bullets from different entry files under the same section
   are concatenated, in filename order. Keep the wording verbatim: a release
   merges and orders entries, it does not rewrite them.
5. Insert the block directly under the `# Changelog` title, above the previous
   version's `## [...]` heading, with a blank line on either side.
6. `git rm` every entry file read in step 2, and only those.
7. Commit the changelog and the removals together as `changelog for <version>`,
   then tag and release as usual.

A bugfix which is cherry-picked from `master` to a release branch brings its
entry file along, so it is consumed twice: once on the release branch for the
patch release, and once on `master` for the next minor release. That is
intended — the fix is in both releases, so it belongs in both changelogs.
