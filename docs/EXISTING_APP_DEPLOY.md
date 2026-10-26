# Existing application deployments

`repeat-deploy.yml` is a separate, opt-in code-only release path. The legacy
`deploy.yml` provisioning behavior is unchanged. Never use that old playbook as
a fallback for a refused repeat deployment.

## Contract

Run against exactly one inventory host and supply a reviewed, secret-free
`repeat_deploy_profile` mapping. Bind it to the SHA-256 of that server's
`/etc/machine-id`, the existing public application root, PHP minor/FPM socket,
all owned Supervisor groups and their exact existing config hashes, owned
Nginx names and baseline HTTP status on both ports, and a verified backup
reference. Never put environment/config values, credentials or private keys in
the profile. Keep real client profiles in the private application repository.

Build the immutable artifact from committed Git objects:

```sh
python3 scripts/build-existing-release.py --repo /checkout/app --commit "$CI_COMMIT_SHA" --output release
```

Use `release/manifest.json` as `candidate_manifest` and the archive digest in
`release/artifact.json` as `source_archive_sha256`. The first enrollment also
needs a reviewed `live_manifest` of the current code. Following a successful
release, root-owned `/var/lib/ansible-deploy/existing/<project>/current.json`
records the verified manifest. Later candidates must include that commit in
Git ancestry; stale pipelines cannot silently roll back newer deployments.

Invoke the preflight (the default makes no production writes):

```sh
ansible-playbook -i inventory repeat-deploy.yml --limit app-host -e @private-profile.yml -e repeat_deploy_source_archive=release/source.tar.gz
```

After reviewing that receipt and authorizing the exact release, append
`-e repeat_deploy_apply=true`. Ansible `--check` is refused explicitly; use the
normal preflight instead. Pin this package to a reviewed Git commit in CI.

## Preserved runtime

The executor keeps the existing public symlink, physical application path,
`.env`/storage inodes, worker groups/options/counts, PHP/FPM selection and cron
contents. It serializes apply operations with a host lock. It stages source
permissions as 0644/0755, retains required executable bits and does not traverse
runtime symlinks to chmod customer data. Explicit `preserve_copy_paths` and
`preserve_link_paths` cover generated assets and non-Git runtime components;
unclassified files in application/public trees cause a refusal. Standard
`public/storage` links are retained automatically only inside the existing
storage anchor. No source or private runtime data is uploaded to Git.

Both source manifests and the archive digest are checked. Free space must
cover source extraction, the copied vendor/preserved tree and the configured
reserve (default 1 GiB). Composer JSON/lock must be semantically unchanged;
this first code-only mode refuses dependency upgrades and authoritative
Composer classmaps. A separately reviewed vendor release is required for those.
It does not run Composer, migrations, seeders, frontend builds, route/event
cache commands, cache flushes, initial provisioning or external business calls.

When no configuration source or typed delta changes, the existing default
config cache is preserved byte-for-byte with its mode and ownership. A changed
config, bootstrap or provider source requires a nonempty explicit typed
`config_change_hashes` scope. Bootstrap then uses distinct temporary cache
paths and a private, per-run `LARAVEL_STORAGE_PATH` tree. Only explicitly
reviewed typed config nodes are promoted into a copy of the old cache; every
other old node must remain equal in PHP type and value. Credentials,
DB/queue/cache/session settings and coordination/concurrency are never delta
allowlisted. Unknown app providers can execute code during boot: review those
providers before enrolling an application.

## Cutover and recovery

Pause only the owned cron entry, wait for natural completion of owned Artisan
producers, close all owned HTTP names with a temporary 503, signal only owned
queue workers with USR2, wait for reserved jobs to reach zero and require every
selected Supervisor process to be STOPPED/PID0 before switching directories.
After the HTTP gate closes, the existing private full FPM status listener must
prove that no request for the exact app script path remains in flight. A missing
status reader, unknown active script, wrong pool or incomplete response refuses
the release. No FPM restart is part of a release.

No force kill, job replay or reservation clearing is used. Restart the same
owned groups, verify source/anchors/public baseline, then restore cron.

Any failure after a source switch re-closes ingress, drains and stops the actual
new workers (including explicit BACKOFF/FATAL/EXITED reconciliation), restores
the previous source/cache and starts the old topology. Before-switch busy work
resumes the same original worker PIDs. Catchable termination follows recovery.
If safe recovery cannot be proven, leave a hold receipt; never force overwrite.
SIGKILL/power loss requires an operator to inspect the private receipt and
actual processes before recovery. Do not rerun blindly.

Private control receipts and previous/failed release directories are retained;
there is no automated pruning. In-root storage and environment anchors remain
in the retained previous directory, so deleting it would delete live data.
A successful technical canary proves this release mechanism only; it does not
claim customer acceptance of business workflows.

## Supported connections and status enrollment

The default queue adapter supports native `queue:work` on existing MySQL
database queues. An explicit `queue_adapter: native_redis` profile enables the
separate bounded adapter only for the reviewed Contact default/backfill and
Salesbots default topologies. It freezes the Laravel-resolved Redis
host/port/database/prefix tuple before applying a cutover and counts only with
native `LLEN`/`ZCARD`; it never reads queue payloads. Other Redis apps, DB URLs,
Unix sockets, prefixed SQL tables, replicas and nonempty PDO options are
refused before mutation.

The reviewed profile must specify `fpm_pool`, `fpm_status_path` and the existing
`fpm_status_socket` under a root-owned 0700 parent. It is a private FastCGI status
listener, never a public Nginx endpoint. Status enrollment is a separately
reviewed infrastructure change and is not inferred or performed by this role.

Two additional runtime shapes are opt-in and must be pinned in the reviewed
profile. The ordinary single `nginx_config` and user crontab (`cron_user`)
behavior remains the default.

For an application whose two owned vhosts are split across two files, use
`nginx_configs` with exactly two distinct `/etc/nginx/` paths and
`nginx_config_hashes` with the expected SHA-256 for each path. Preflight checks
the combined server-name set for an exact match to `server_names`, rejects any
foreign name or non-Unix/mismatched FastCGI binding, and snapshots both files.
Apply gates both files as one generation, runs one `nginx -t` and one reload,
then restores both files together on rollback. Any unexpected file or entry
point drift refuses the release.

For a scheduler in `/etc/cron.d`, use all of `cron_file`, `cron_file_sha256`,
`cron_file_owner`, `cron_file_group`, `cron_file_mode` (four-digit octal text),
and `cron_file_scheduler_user`. The file must be a regular file directly under
`/etc/cron.d`, have the exact expected hash and metadata, and contain exactly
one matching `artisan schedule:run` row with that scheduler-user column and
the reviewed PHP binary. Pause and restore use a hash-checked compare-and-swap
on only that file. A failed check never falls back to a global or per-user
crontab.

## Pinned common source and verified LFS assets

The builder accepts `--common-checkout` only for the existing
`packages/leolnid/common` Gitlink. It materializes the exact commit from the
application tree, reading Git objects rather than the checkout HEAD or dirty
files. An absent, unused, nested or unsupported Gitlink is refused before an
artifact is created. This option does not resolve or update dependencies.

Git LFS pointers are materialized only from an existing LFS object or hydrated
file whose SHA-256 OID and byte length both match. Missing or mismatched content
is refused before artifact creation. The manifest hashes the actual binary
content and records the pinned common commit and LFS object metadata.

A standalone Supervisor selector is accepted only by its exact configured
name when the reviewed group expects exactly one process. Multi-process groups
still require their exact `group:process` selectors.

## CI adoption

The reusable include lives at `.gitlab/ci/repeat-existing-app.yml`. An
application adopts it only after review by pinning that include URL and
`REPEAT_DEPLOY_PACKAGE_REF` to the same 40-character package commit. Its
`.deploy/runtime-profile.json` stores only the reviewed server enrollment and
old-live baseline; the build job creates a new candidate manifest and archive
from `CI_COMMIT_SHA`, materializing the application's Common Gitlink only when
the Git tree contains that exact gitlink. The candidate is never copied into
the enrollment file. The builder excludes the entire `.deploy/` tree and the
legacy `packages/leolnid/common-deploy/` provisioning tree from the production
archive.

Artifact creation runs as a non-deploying job. On the default branch, a manual
read-only preflight must complete before the separate manual apply becomes
available. SSH host verification is strict and uses the committed
`.deploy/known_hosts`; no runtime key scan or disabled host checking is used.
Legacy provisioning/setup jobs remain separate and are not invoked by this
include. A refusal has no automatic legacy fallback.
