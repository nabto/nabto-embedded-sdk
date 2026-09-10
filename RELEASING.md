# Releasing

This describes how a change reaches the users of the SDK once it is on
`master`: which release branches are owed a bugfix, and how a release is made.

Which branches are maintained is described in [BRANCHES.md](BRANCHES.md). How
changelog entries are written and how a release assembles them into
`CHANGELOG.md` is described in
[changelog.d/00README.md](changelog.d/00README.md).

## Getting a fix into a release

A fix is made on `master` first, with its `changelog.d/` entry in the same pull
request; a fix which exists only on a release branch is lost the next time a
minor is cut from `master`.

Once the fix is on `master`, look up in [BRANCHES.md](BRANCHES.md) which release
branches still receive patches and cherry-pick the fix to each of them. A fix
with a security impact goes to every branch listed as patched; other fixes go to
the branches where they matter.

```
git checkout 5.15 && git pull
git checkout -b fix-busy-spin-5.15
git cherry-pick -x <the commit on master>
```

Cherry-pick the commit which carries the change, not the merge commit of the
pull request, and use `-x` so the new commit records where it came from. Open a
pull request from that branch into the release branch.

The cherry-pick brings the `changelog.d/` entry file with it, so the same entry
is consumed twice: once for the patch release on the release branch, and once
for the next minor release on `master`. That is intended, see
[changelog.d/00README.md](changelog.d/00README.md).

The fix reaches users when the release branch is released, see
[Making a release](#making-a-release).

## Making a release

A patch release such as `5.15.2` is made on the existing release branch. A minor
release such as `5.16.0` starts by cutting the release branch from `master`:

```
git checkout master && git pull
git checkout -b 5.16
git push -u origin 5.16
```

From here the two are the same procedure. `5.15.2` is used as the example.

**1. Make the rc branch.** All release preparation happens on a branch named
after the version being released:

```
git checkout 5.15 && git pull
git checkout -b 5.15.2-rc
```

**2. Update the changelog.** Fold the `changelog.d/` entries into
`CHANGELOG.md` and remove the entry files, following the steps in
[changelog.d/00README.md](changelog.d/00README.md). Commit the assembled
changelog and the removals together as `changelog for 5.15.2`.

**3. Let CI pass.** Push the rc branch. Every workflow in `.github/workflows/`
runs on any push, so the rc branch is built and tested exactly as the release
will be. Do not tag before it is green.

**4. Tag.** The tag goes on the tip of the rc branch:

```
git tag v5.15.2
git push origin v5.15.2
```

The `v` prefix is required: `cmake-scripts/nabto_version.cmake` strips the first
character of the tag to form the version number. The version is derived from the
tag alone, so nothing in the source has to be bumped - but a build only picks up
the release version if the working tree is clean and `HEAD` is exactly on the
tag, otherwise the version falls back to `0.0.0-branch...`.

Tags of the form `v5.2.0-rc.0` are published pre-releases and unrelated to the
rc branch, which is only release preparation.

**5. Publish the GitHub release.** Create a release for the tag on GitHub. This
is what produces the artifacts: the upload jobs in `source_release.yml` and
`build_artifacts.yml` only run for a published release, so pushing the tag on
its own attaches neither `nabto-embedded-sdk.zip` nor the application binaries.

**6. Merge back into the release branch.** Open a pull request from `5.15.2-rc`
into `5.15`. The rc branch exists so that anything committed only for the
release can be dropped before it reaches the release branch; this SDK does not
alter files for a release, so the rc branch is merged as it is. If a release
ever does need something removed, branch `mergeback/v5.15.2` off the rc branch,
remove it there and open the pull request from that branch instead.

Merge with a merge commit or a fast-forward. Squashing or rebasing rewrites the
tagged commit and leaves `v5.15.2` pointing at a commit which is not on the
release branch.

**7. Finish up.** For a minor release, open a pull request against `master`
removing the entry files the release consumed - they were released from the new
branch, and if they stay on `master` the next minor lists them a second time.
The entries of cherry-picked bugfixes are the exception and stay on `master`, as
described above. Finally update the table in [BRANCHES.md](BRANCHES.md) with the
new latest release, and for a minor release with the new branch and the date the
previous minor is patched until.
