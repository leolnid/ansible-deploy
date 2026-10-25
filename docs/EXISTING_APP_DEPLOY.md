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

The final config cache is built only in a fresh private `APP_CONFIG_CACHE`
path while the old default cache remains present. Effective configuration is
strictly equal except explicit typed old/new digest deltas at reviewed existing
paths, or explicitly allowed path values resolving to the same data inode.
Credentials, DB/queue/cache/session settings and coordination/concurrency are
never delta allowlisted. Unknown app providers can execute code during boot:
review those providers before enrolling an application.

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

This v1 supports native `queue:work` on existing MySQL database queues only.
Redis, DB URLs, Unix sockets, prefixed tables, replicas and nonempty PDO options
are refused before mutation. A future Redis adapter needs its own reservation,
drain and recovery review; this package does not claim all 26 CI pipelines are
already adopted.

The reviewed profile must specify `fpm_pool`, `fpm_status_path` and the existing
`fpm_status_socket` under a root-owned 0700 parent. It is a private FastCGI status
listener, never a public Nginx endpoint. Status enrollment is a separately
reviewed infrastructure change and is not inferred or performed by this role.
