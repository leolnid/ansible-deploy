#!/usr/bin/env python3
"""Existing-app release executor. Output is metadata only; never config values.

No provisioning, migrations, asset build, environment rewrite, global restart,
cache flush or topology generation is part of this executor.
"""
from __future__ import annotations
import argparse, copy, datetime, fcntl, hashlib, json, os, pathlib, re, secrets
import shutil, signal, stat, subprocess, sys, tarfile, time, pwd, grp, importlib.util

class Refuse(RuntimeError):
    pass

def pinned_module(name,filename,expected):
    path=pathlib.Path(__file__).with_name(filename)
    if path.is_symlink()or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:raise Refuse('pinned_runtime_module_drift')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

NATIVE_CONFIG_SHA='c7418a4ce94ea696993ec84575c754fddaf4119f057be3a24129664f41a7cd7f'
_native_config=pinned_module('repeat_native_configuration','native_configuration.py',NATIVE_CONFIG_SHA)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def digest(path):
    return sha(pathlib.Path(path).read_bytes())

def path_value(value):
    if not isinstance(value, str) or not value.startswith('/') or any(c in value for c in '\n\n\0'):
        raise Refuse('invalid_absolute_path')
    p = pathlib.Path(value)
    if '..' in p.parts or p == pathlib.Path('/'):
        raise Refuse('unsafe_absolute_path')
    return p

def source_path(value):
    if not isinstance(value, str) or not value or value.startswith('/') or '..' in pathlib.PurePosixPath(value).parts or '\\' in value:
        raise Refuse('unsafe_source_path')
    return value

def validate_profile(p):
    if not isinstance(p, dict) or p.get('schema_version') != 1:
        raise Refuse('unsupported_profile_schema')
    required = ['project', 'application_root', 'php_cli', 'php_minor', 'fpm_socket',
                'server_names', 'public_baselines', 'worker_groups',
                'supervisor_config_hashes', 'live_manifest', 'candidate_manifest',
                'source_archive_sha256', 'backup_reference', 'server_identity_sha256']
    if any(k not in p for k in required):
        raise Refuse('incomplete_profile')
    if ('nginx_config' in p) == ('nginx_configs' in p):
        raise Refuse('exactly_one_nginx_profile_mode_required')
    if 'nginx_config' in p:
        path_value(p['nginx_config'])
        if not p['nginx_config'].startswith('/etc/nginx/') or 'nginx_config_hashes' in p:
            raise Refuse('nginx_scope_required')
    else:
        paths = p['nginx_configs']
        hashes = p.get('nginx_config_hashes')
        if (not isinstance(paths, list) or len(paths) != 2 or
                any(not isinstance(value, str) or not value.startswith('/etc/nginx/') for value in paths) or
                len(set(paths)) != 2 or
                not isinstance(hashes, dict) or set(hashes) != set(paths) or
                any(not re.fullmatch(r'[0-9a-f]{64}', value) for value in hashes.values())):
            raise Refuse('exact_two_hashed_nginx_configs_required')
        for value in paths:
            path_value(value)
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}', p['project']):
        raise Refuse('invalid_project')
    for name in ['application_root', 'php_cli', 'fpm_socket']:
        path_value(p[name])
    if not any(p['application_root'].startswith(root) for root in ['/var/www/', '/home/user/www/', '/srv/']):
        raise Refuse('application_root_outside_supported_scope')
    if not re.fullmatch(r'8\.[0-9]+', p['php_minor']):
        raise Refuse('explicit_php_minor_required')
    if not isinstance(p['server_names'], list) or not p['server_names'] or len(set(p['server_names'])) != len(p['server_names']):
        raise Refuse('invalid_owned_server_names')
    for host in p['server_names']:
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}[a-z0-9]', host) or '..' in host:
            raise Refuse('wildcard_or_invalid_server_name')
        baseline = p['public_baselines'].get(host)
        if not isinstance(baseline, dict) or set(baseline) != {'80', '443'} or any(type(x) is not int or not 200 <= x < 500 for x in baseline.values()):
            raise Refuse('explicit_readonly_baseline_required')
    if not isinstance(p['worker_groups'], dict) or not p['worker_groups']:
        raise Refuse('owned_worker_groups_required')
    for group, count in p['worker_groups'].items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', group) or type(count) is not int or not 1 <= count <= 64:
            raise Refuse('invalid_worker_group')
    for name, value in p['supervisor_config_hashes'].items():
        if not name.startswith('/etc/supervisor/conf.d/') or not name.endswith('.conf') or not re.fullmatch(r'[0-9a-f]{64}', value):
            raise Refuse('invalid_supervisor_scope')
    if not re.fullmatch(r'[0-9a-f]{64}', p['server_identity_sha256']):
        raise Refuse('server_identity_required')
    for name in ['live_manifest', 'candidate_manifest']:
        m = p[name]
        if not isinstance(m, dict) or not re.fullmatch(r'[0-9a-f]{40,64}', m.get('candidate_commit', '')) or not m.get('files'):
            raise Refuse('source_manifest_required')
        for rel, value in m['files'].items():
            source_path(rel)
            if not re.fullmatch(r'[0-9a-f]{64}', value):
                raise Refuse('invalid_source_digest')
    if not re.fullmatch(r'[0-9a-f]{64}', p['source_archive_sha256']) or not isinstance(p['backup_reference'], str) or not p['backup_reference']:
        raise Refuse('artifact_and_existing_backup_required')
    for key, pair in p.get('config_change_hashes', {}).items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}', key) or key.split('.')[0] in ['database','queue','cache','session'] or key in ['app.key','app.env','app.debug','app.url'] or re.search(r'password|secret|token|credentials|coordination|concurrency',key,re.I):
            raise Refuse('protected_configuration_delta_forbidden')
        if not isinstance(pair,dict) or set(pair)!={'old','new'} or any(not re.fullmatch(r'[0-9a-f]{64}',h) for h in pair.values()):
            raise Refuse('exact_typed_configuration_delta_hashes_required')
    if 'fpm_status_socket' in p:
        if not str(path_value(p['fpm_status_socket'])).startswith('/run/'):
            raise Refuse('private_runtime_status_socket_required')
    if 'fpm_status_path' in p and not re.fullmatch(r'/[A-Za-z0-9_/-]{1,100}',p['fpm_status_path']):
        raise Refuse('invalid_existing_fpm_status_path')
    if 'fpm_pool' in p and not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}',p['fpm_pool']):
        raise Refuse('invalid_existing_fpm_pool')
    for value in p.get('same_inode_config_paths',[]):
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}',value):
            raise Refuse('explicit_config_path_required')
    for rel in p.get('preserve_copy_paths', []) + p.get('preserve_link_paths', []):
        source_path(rel)
        if rel.split('/')[0] in ['.env', 'storage', 'vendor', 'bootstrap']:
            raise Refuse('protected_paths_are_not_optional_preserve_paths')
    for key, default in [('drain_timeout',120),('start_timeout',35)]:
        if type(p.get(key,default)) not in [int,float] or not 0 < p.get(key,default) <= 600:
            raise Refuse('invalid_bounded_timeout')
    if type(p.get('minimum_free_bytes',1024**3)) is not int or p.get('minimum_free_bytes',1024**3) < 0:
        raise Refuse('invalid_free_space_reserve')
    cron_file_fields = {'cron_file', 'cron_file_sha256', 'cron_file_owner', 'cron_file_group', 'cron_file_mode', 'cron_file_scheduler_user'}
    present_cron_file_fields = cron_file_fields & set(p)
    if present_cron_file_fields:
        if present_cron_file_fields != cron_file_fields or 'cron_user' in p:
            raise Refuse('complete_dedicated_cron_file_profile_required')
        if (any(not isinstance(p[field], str) for field in cron_file_fields) or
                not re.fullmatch(r'/etc/cron\.d/[A-Za-z0-9_.-]{1,128}', p['cron_file']) or
                p['cron_file'].endswith('/.') or p['cron_file'].endswith('/..') or
                not re.fullmatch(r'[0-9a-f]{64}', p['cron_file_sha256']) or
                not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,30}', p['cron_file_owner']) or
                not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,30}', p['cron_file_group']) or
                p['cron_file_mode'] not in ['0644', '0600'] or
                not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,30}', p['cron_file_scheduler_user'])):
            raise Refuse('invalid_dedicated_cron_file_scope')
    allowed = set(required) | {'schema_version','nginx_config','nginx_configs','nginx_config_hashes','cron_user', *cron_file_fields,'preserve_copy_paths','preserve_link_paths','same_inode_config_paths','drain_timeout','start_timeout','minimum_free_bytes','config_change_hashes','fpm_status_path','fpm_pool','fpm_status_socket','queue_adapter'}
    if set(p) - allowed:
        raise Refuse('unknown_profile_field')
    if p.get('queue_adapter','database')not in ['database','native_redis']:raise Refuse('unsupported_explicit_queue_adapter')
    forbidden = ['run_migrations', 'run_seeders', 'build_assets', 'manage_supervisor', 'manage_cron', 'update_env', 'flush_live_cache', 'setup_server']
    if any(p.get(k) for k in forbidden):
        raise Refuse('provisioning_or_business_mutation_not_supported')
    return p

class ExistingRelease:
    def __init__(self, profile, archive):
        self.p = copy.deepcopy(validate_profile(profile))
        self.entry = path_value(profile['application_root'])
        self.root = self.entry.resolve(strict=True)
        if not any(str(self.root).startswith(prefix) for prefix in ['/var/www/','/home/user/www/','/srv/']):
            raise Refuse('resolved_application_root_outside_scope')
        self.archive = pathlib.Path(archive)
        self.phase = 'preflight'
        self.stage = None
        self.old_root = None
        self.cron_paused = False
        self.gated = False
        self.swapped = False
        self.old_moved = False
        self.workers_stopped = False
        self.pause_requested = False
        self.report = {'project': profile['project'], 'candidate_sha': profile['candidate_manifest']['candidate_commit'], 'database_changes': False, 'notifications_sent': 0, 'manual_business_requests': 0}

    def run(self, args, *, input=None, cwd=None, timeout=40, allowed=(0,), env=None, umask=None):
        q = subprocess.run(args, input=input, cwd=cwd, env=env, capture_output=True, timeout=timeout, umask=-1 if umask is None else umask)
        if q.returncode not in allowed:
            raise Refuse('command_failed_' + pathlib.Path(args[0]).name)
        return q.stdout

    def system_path(self, value):
        return path_value(value)

    def nginx_profile_paths(self):
        return self.p['nginx_configs'] if 'nginx_configs' in self.p else [self.p['nginx_config']]

    def nginx_path_in_scope(self, target):
        return str(target).startswith('/etc/nginx/')

    def nginx_snapshot(self):
        snapshots = {}
        for configured in self.nginx_profile_paths():
            entry = self.system_path(configured)
            entry_lstat = entry.lstat()
            entry_target = os.readlink(entry) if entry.is_symlink() else None
            target = entry.resolve(strict=True)
            if not self.nginx_path_in_scope(target) or not target.is_file():
                raise Refuse('nginx_target_outside_scope')
            metadata = target.stat()
            content = target.read_bytes()
            current = {'entry': entry, 'entry_lstat': entry_lstat, 'entry_target': entry_target,
                       'path': target, 'stat': metadata, 'before': content, 'before_sha': sha(content)}
            if 'nginx_configs' in self.p and self.p['nginx_config_hashes'][configured] != current['before_sha']:
                raise Refuse('nginx_config_hash_mismatch')
            snapshots[configured] = current
        if len({str(value['path']) for value in snapshots.values()}) != len(snapshots):
            raise Refuse('nginx_config_targets_must_be_distinct')
        return snapshots

    def check_nginx_snapshot(self, allowed_hashes=None):
        for configured, snapshot in self.nginx_snapshots.items():
            entry = snapshot['entry']
            current_entry = entry.lstat()
            current_target = os.readlink(entry) if entry.is_symlink() else None
            if (entry.is_symlink() != (snapshot['entry_target'] is not None) or
                    (snapshot['entry_target'] is not None and current_entry.st_ino != snapshot['entry_lstat'].st_ino) or
                    current_target != snapshot['entry_target'] or
                    entry.resolve(strict=True) != snapshot['path']):
                raise Refuse('nginx_entrypoint_was_changed')
            current_sha = digest(snapshot['path'])
            accepted = (allowed_hashes or {}).get(configured, {snapshot['before_sha']})
            if current_sha not in accepted:
                raise Refuse('nginx_config_changed_during_stage')

    @staticmethod
    def make_nginx_gate(content):
        blocks = list(re.finditer(rb'\bserver\s*\{', content))
        names = re.findall(rb'\bserver_name\s+([^;]+);', content)
        if not names or len(blocks) != len(names):
            raise Refuse('nginx_server_structure_not_supported')
        gated = content
        for block in reversed(blocks):
            gated = gated[:block.end()] + b'\n return 503; # reviewed repeat deployment\n' + gated[block.end():]
        return gated

    def prepare_nginx(self):
        self.nginx_snapshots = self.nginx_snapshot()
        if 'nginx_configs' not in self.p:
            _, snapshot = next(iter(self.nginx_snapshots.items()))
            self.nginx_entry = snapshot['entry']
            self.nginx_entry_lstat = snapshot['entry_lstat']
            self.nginx_entry_target = snapshot['entry_target']
            self.nginx_path = snapshot['path']
            self.nginx_stat = snapshot['stat']
            self.nginx_before = snapshot['before']
        all_names = set()
        all_bindings = []
        self.nginx_gates = {}
        if 'nginx_configs' not in self.p:
            _, snapshot = next(iter(self.nginx_snapshots.items()))
            content = snapshot['before']
            names = re.findall(rb'\bserver_name\s+([^;]+);', content)
            if not names or {part.decode() for row in names for part in row.split()} != set(self.p['server_names']):
                raise Refuse('nginx_contains_foreign_or_wildcard_names')
            bindings = re.findall(rb'fastcgi_pass\s+unix:([^;]+);', content)
            if not bindings or any(pathlib.Path(binding.decode()).resolve()!=path_value(self.p['fpm_socket']).resolve() for binding in bindings):
                raise Refuse('owned_vhost_fpm_binding_mismatch')
            self.nginx_gates[next(iter(self.nginx_snapshots))] = self.make_nginx_gate(content)
            self.nginx_gate = self.nginx_gates[next(iter(self.nginx_snapshots))]
            return self.nginx_snapshots
        for configured, snapshot in self.nginx_snapshots.items():
            content = snapshot['before']
            names = re.findall(rb'\bserver_name\s+([^;]+);', content)
            if not names:
                raise Refuse('nginx_contains_no_owned_server_names')
            tokens = [part.decode('ascii', 'strict') for row in names for part in row.split()]
            if any(host not in self.p['server_names'] for host in tokens):
                raise Refuse('nginx_contains_foreign_or_wildcard_names')
            all_names.update(tokens)
            self.nginx_gates[configured] = self.make_nginx_gate(content)
            bindings = re.findall(rb'\bfastcgi_pass\s+([^;]+);', content)
            for binding in bindings:
                if not binding.startswith(b'unix:'):
                    raise Refuse('owned_vhost_fpm_binding_mismatch')
                all_bindings.append(binding[5:])
        if all_names != set(self.p['server_names']):
            raise Refuse('nginx_owned_hostname_union_mismatch')
        if not all_bindings or any(pathlib.Path(s.decode()).resolve()!=path_value(self.p['fpm_socket']).resolve() for s in all_bindings):
            raise Refuse('owned_vhost_fpm_binding_mismatch')
        return self.nginx_snapshots

    def prepare_cron_file(self):
        self.cron_file_path = self.system_path(self.p['cron_file'])
        self.cron_file_path_lstat = self.cron_file_path.lstat()
        self.cron_file_stat = self.cron_file_metadata(self.cron_file_path)
        self.cron_before = self.cron_file_path.read_bytes()
        self.cron_before_sha = sha(self.cron_before)
        if self.cron_before_sha != self.p['cron_file_sha256']:
            raise Refuse('dedicated_cron_file_hash_mismatch')
        lines = self.cron_before.splitlines(keepends=True)
        matches = []
        for i, line in enumerate(lines):
            if not line.strip() or line.lstrip().startswith(b'#'):
                continue
            fields = line.split()
            if len(fields) < 8:
                continue
            if any(re.search(re.escape(str(root).encode()) + rb'(?=/|\s|;|$)', line) for root in [self.entry, self.root]) and b'artisan schedule:run' in line:
                matches.append((i, fields))
        if (len(matches) != 1 or matches[0][1][5].decode('ascii', 'strict') != self.p['cron_file_scheduler_user'] or
                self.p['php_cli'].encode() not in lines[matches[0][0]] or
                b'artisan schedule:run' not in lines[matches[0][0]]):
            raise Refuse('exact_single_dedicated_scheduler_row_required')
        self.cron_file_scheduler_line = matches[0][0]
        paused = lines.copy()
        paused[self.cron_file_scheduler_line] = b'# REVIEWED_REPEAT_DEPLOY_PAUSE ' + paused[self.cron_file_scheduler_line]
        self.cron_paused_content = b''.join(paused)
        self.cron_paused_sha = sha(self.cron_paused_content)
        self.cron_file_current_sha = self.cron_before_sha
        return self.cron_before

    def checkpoint(self):
        if self.control is not None:
            target = self.control / 'receipt.json'
            target.write_text(json.dumps({**self.report, 'phase': self.phase}, indent=2))
            target.chmod(0o600)

    def php(self, code, args=(), *, cache=None, bootstrap=False):
        argv = [self.p['php_cli'], '-d', 'display_errors=0', '-r', code, *map(str, args)]
        if hasattr(self, 'uid'):
            env_args = ['APP_CONFIG_CACHE=' + str(cache)] if cache is not None else []
            argv = ['sudo', '-u', '#' + str(self.uid), 'env', *env_args, *argv]
        return self.run(argv)

    def config(self, root):
        code = "$c=require $argv[1].'/bootstrap/cache/config.php';echo json_encode($c,JSON_THROW_ON_ERROR);"
        return json.loads(self.php(code, [root]))

    def manifest(self, root, manifest):
        for rel, expected in manifest['files'].items():
            if self.user_managed_path(rel):
                continue
            path = root / source_path(rel)
            if not path.is_file():
                raise Refuse('missing_manifest_file')
            data = path.read_bytes()
            if manifest.get('normalization_by_path', {}).get(rel) == 'crlf_to_lf':
                data = data.replace(b'\n', b'\n')
            if sha(data) != expected:
                raise Refuse('source_manifest_drift')

    @staticmethod
    def user_managed_path(rel):
        prefix = 'public/filemanager/uploads'
        return rel == prefix or rel.startswith(prefix + '/')

    def effective_preserve_copy_paths(self):
        paths = list(self.p.get('preserve_copy_paths', []))
        uploads = self.root / 'public/filemanager/uploads'
        if uploads.is_symlink():
            if 'public/filemanager/uploads' not in self.p.get('preserve_link_paths', []):
                raise Refuse('customer_upload_directory_symlink_requires_explicit_profile')
        if uploads.exists():
            if uploads.is_symlink():
                pass
            elif not uploads.is_dir():
                raise Refuse('customer_upload_directory_type_unsupported')
            elif 'public/filemanager/uploads' not in paths:
                paths.append('public/filemanager/uploads')
        return paths

    def user_managed_tree_fingerprint(self, root):
        root = pathlib.Path(root)
        result = {}
        def visit(path, relative):
            info = path.lstat()
            metadata = [info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_mtime_ns]
            if path.is_symlink():
                result[relative] = ['symlink', os.readlink(path), metadata]
            elif path.is_dir():
                result[relative] = ['directory', metadata]
                for child in sorted(path.iterdir()):
                    visit(child, relative + '/' + child.name)
            elif path.is_file():
                result[relative] = ['file', digest(path), metadata]
            else:
                raise Refuse('unsupported_customer_upload_artifact_type')
        visit(root, '.')
        return result

    def current_user_managed_uploads_fingerprint(self):
        uploads = self.root/'public/filemanager/uploads'
        if not uploads.exists() and not uploads.is_symlink():
            return None
        return self.user_managed_tree_fingerprint(uploads)

    def preserve_user_managed_metadata(self, source, destination):
        source, destination = pathlib.Path(source), pathlib.Path(destination)
        if source.is_dir() and not source.is_symlink():
            for child in source.iterdir():
                self.preserve_user_managed_metadata(child, destination/child.name)
        info = source.lstat()
        os.chown(destination, info.st_uid, info.st_gid, follow_symlinks=False)
        if not source.is_symlink():
            destination.chmod(stat.S_IMODE(info.st_mode))
        os.utime(destination, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)

    def statuses(self):
        rows = {}
        for group, count in self.p['worker_groups'].items():
            data = self.run(['supervisorctl', 'status', group + ':*'], allowed=(0, 3)).decode()
            selected = []
            for line in data.splitlines():
                fields = line.split()
                if len(fields) < 2 or not (fields[0].startswith(group + ':') or count == 1 and fields[0] == group):
                    raise Refuse('unexpected_supervisor_status')
                m = re.search(r'\bpid (\d+)', line)
                selected.append((fields[0], fields[1], int(m[1]) if m else 0))
            if len(selected) != count:
                raise Refuse('supervisor_topology_drift')
            rows.update({name: {'state': state, 'pid': pid} for name, state, pid in selected})
        return rows

    def own_queue_pids(self):
        result = {}
        for item in pathlib.Path('/proc').iterdir():
            if not item.name.isdigit():
                continue
            try:
                args = (item / 'cmdline').read_bytes().split(b'\0')
                if b'queue:work' not in args:
                    continue
                artisans = [pathlib.Path(x.decode()) for x in args if x.endswith(b'/artisan')]
                if any(x.resolve() == self.root / 'artisan' for x in artisans):
                    result[int(item.name)] = args
            except (FileNotFoundError, ProcessLookupError, PermissionError, UnicodeError):
                continue
        return result

    def workers(self):
        rows = self.statuses()
        pids = self.own_queue_pids()
        if any(x['state'] != 'RUNNING' or x['pid'] not in pids for x in rows.values()) or set(pids) != {x['pid'] for x in rows.values()}:
            raise Refuse('worker_scope_or_state_drift')
        specs = {}
        for row in rows.values():
            pid = row['pid']
            if pathlib.Path(os.readlink('/proc/' + str(pid) + '/exe')).resolve() != pathlib.Path(self.p['php_cli']).resolve():
                raise Refuse('wrong_worker_php')
            argv = [x.decode() for x in pids[pid] if x]
            i = argv.index('queue:work')
            connection = argv[i + 1] if len(argv) > i + 1 and not argv[i + 1].startswith('-') else self.cfg['queue']['default']
            conf = self.cfg['queue']['connections'].get(connection)
            if not isinstance(conf, dict) or conf.get('driver') != 'database':
                raise Refuse('only_existing_database_queue_supported')
            queues = conf['queue']
            for j, value in enumerate(argv):
                if value.startswith('--queue='):
                    queues = value.partition('=')[2]
                elif value == '--queue':
                    queues = argv[j + 1]
            names = queues.split(',')
            if any(not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', x) for x in names):
                raise Refuse('invalid_owned_queue')
            specs.setdefault(connection, set()).update(names)
        return rows, {key: sorted(value) for key, value in specs.items()}

    @staticmethod
    def validate_opcache_values(info, overrides):
        parsed={}
        for key in ['opcache.enable','opcache.validate_timestamps','opcache.revalidate_freq']:
            rows=re.findall(r'^'+re.escape(key)+r'\s*=>\s*(\S+)\s*=>\s*(\S+)\s*$',info,re.M)
            if len(rows)!=1 or rows[0][0]!=rows[0][1]:
                raise Refuse('unverifiable_fpm_opcache_configuration')
            parsed[key]=rows[0][0]
        parsed.update(overrides)
        if parsed['opcache.validate_timestamps'].lower() not in ['on','1','yes','true']:
            raise Refuse('fpm_opcache_timestamp_validation_required')
        if not parsed['opcache.revalidate_freq'].isdigit() or not 0<=int(parsed['opcache.revalidate_freq'])<=5:
            raise Refuse('bounded_fpm_opcache_revalidation_required')
        if parsed['opcache.enable'].lower() not in ['on','off','0','1','yes','no','true','false']:
            raise Refuse('unverifiable_fpm_opcache_enable')
        return int(parsed['opcache.revalidate_freq'])+2

    def fpm_opcache_guard(self):
        folder=pathlib.Path('/etc/php')/self.p['php_minor']/'fpm'
        overrides={};selected=0
        for file in (folder/'pool.d').glob('*.conf'):
            section=None
            for line in file.read_text().splitlines():
                stripped=line.strip()
                if not stripped or stripped.startswith(';'):continue
                if stripped.startswith('[') and stripped.endswith(']'):
                    section=stripped[1:-1];continue
                if section!=self.p['fpm_pool']:continue
                if re.match(r'include\s*=',stripped):
                    raise Refuse('nested_selected_pool_include_unsupported')
                if re.match(r'listen\s*=',stripped):
                    selected+=1
                    if pathlib.Path(stripped.split('=',1)[1].strip()).resolve()!=path_value(self.p['fpm_socket']).resolve():
                        raise Refuse('selected_opcache_pool_socket_mismatch')
                match=re.match(r'php_(?:admin_)?value\[(opcache\.[A-Za-z_]+)\]\s*=\s*(.*?)\s*$',stripped)
                if match:
                    if match[1] not in ['opcache.enable','opcache.validate_timestamps','opcache.revalidate_freq']:
                        continue
                    if match[1]in overrides:raise Refuse('ambiguous_opcache_pool_override')
                    overrides[match[1]]=match[2]
        if selected!=1:
            raise Refuse('exact_selected_opcache_pool_required')
        nginx_expanded=self.run(['nginx','-T'])
        if re.search(rb'fastcgi_param\s+PHP_(?:ADMIN_)?VALUE\b',nginx_expanded):
            raise Refuse('request_php_ini_overrides_unsupported')
        if list(self.root.rglob('.user.ini')):
            raise Refuse('per_directory_php_ini_unsupported')
        info=self.run(['/usr/sbin/php-fpm'+self.p['php_minor'],'-i']).decode()
        delay=self.validate_opcache_values(info,overrides)
        files=[folder/'php.ini',*(folder/'conf.d').glob('*'),*(folder/'pool.d').glob('*.conf')]
        self.fpm_config_hashes={str(file):digest(file) for file in files if file.is_file()}
        self.opcache_delay=delay
        self.report['fpm_opcache_timestamp_validation']=True
        self.report['opcache_wait_seconds']=delay

    def validate_queue_connections(self):
        for connection in self.queue_specs:
            queue = self.cfg['queue']['connections'][connection]
            if queue.get('driver') != 'database' or not re.fullmatch(r'[A-Za-z0-9_]+',queue.get('table','')):
                raise Refuse('unsupported_existing_queue_connection')
            db = self.cfg['database']['connections'][queue.get('connection') or self.cfg['database']['default']]
            if db.get('driver') != 'mysql' or db.get('url') or db.get('unix_socket') or db.get('prefix') or db.get('options') or db.get('read') or db.get('write'):
                raise Refuse('unsupported_database_dsn_or_options')
            if not isinstance(db.get('host'),str) or not isinstance(db.get('database'),str) or not isinstance(db.get('username'),str) or not str(db.get('port',3306)).isdigit():
                raise Refuse('unsupported_database_address')
            if db.get('charset','utf8mb4') not in ['utf8','utf8mb4']:
                raise Refuse('unsupported_database_charset')

    def fpm_status(self):
        path = self.p.get('fpm_status_path')
        if not path or not self.p.get('fpm_pool') or not self.p.get('fpm_status_socket') or not shutil.which('cgi-fcgi'):
            raise Refuse('existing_fpm_full_status_required_unsupported')
        socket=path_value(self.p['fpm_status_socket'])
        if socket.parent.is_symlink() or socket.parent.stat().st_uid!=0 or stat.S_IMODE(socket.parent.stat().st_mode)!=0o700 or not stat.S_ISSOCK(socket.stat().st_mode):
            raise Refuse('root_only_existing_status_socket_required')
        env = {'PATH':'/usr/bin:/bin','SCRIPT_NAME':path,'SCRIPT_FILENAME':path,
               'REQUEST_METHOD':'GET','QUERY_STRING':'full&json','REQUEST_URI':path+'?full&json',
               'SERVER_PROTOCOL':'HTTP/1.1','GATEWAY_INTERFACE':'CGI/1.1','CONTENT_LENGTH':'0'}
        raw = self.run(['cgi-fcgi','-bind','-connect',str(socket)],env=env)
        body = re.split(rb'\n?\n\n?\n',raw,maxsplit=1)
        if len(body)!=2:
            raise Refuse('invalid_existing_fpm_status_response')
        status = json.loads(body[1])
        if status.get('pool')!=self.p['fpm_pool'] or not isinstance(status.get('processes'),list) or len(status['processes'])!=status.get('total processes'):
            raise Refuse('incomplete_or_wrong_fpm_full_status')
        return status

    def active_fpm_requests(self,status):
        active=[]
        if type(status.get('listen queue')) is not int or status['listen queue']<0:
            raise Refuse('fpm_listen_queue_coverage_required')
        if status['listen queue']:
            active.append('pending_fpm_requests')
        for row in status['processes']:
            if row.get('state')=='Idle':
                continue
            uri = row.get('request uri','').split('?',1)[0]
            if uri == self.p['fpm_status_path']:
                continue
            script = row.get('script')
            if not isinstance(script,str) or not script.startswith('/'):
                raise Refuse('unidentifiable_active_fpm_script')
            script_path = pathlib.Path(script)
            if any(script_path.is_relative_to(root) for root in [self.entry,self.root]):
                active.append(row.get('pid'))
        return active

    def drain_fpm(self):
        until=time.monotonic()+self.p.get('drain_timeout',120)
        while self.active_fpm_requests(self.fpm_status()):
            if time.monotonic()>until:
                raise Refuse('owned_fpm_request_drain_timeout_no_force')
            time.sleep(.25)

    def counts(self):
        # Credentials never leave this short-lived PHP process.
        code = r'''$c=require $argv[1];$spec=json_decode($argv[2],true,512,JSON_THROW_ON_ERROR);$out=['jobs'=>0,'reserved'=>0];foreach($spec as $name=>$queues){$q=$c['queue']['connections'][$name];if($q['driver']!=='database'||!preg_match('/^[A-Za-z0-9_]+$/D',$q['table']))exit(21);$d=$c['database']['connections'][$q['connection']??$c['database']['default']];if(!empty($d['prefix']))exit(22);$p=new PDO('mysql:host='.$d['host'].';port='.($d['port']??3306).';dbname='.$d['database'].';charset='.($d['charset']??'utf8mb4'),$d['username'],$d['password'],[PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION]);$s=$p->prepare('SELECT COUNT(*) n,COALESCE(SUM(reserved_at IS NOT NULL),0) r FROM `'.$q['table'].'` WHERE queue IN ('.implode(',',array_fill(0,count($queues),'?')).')');$s->execute($queues);$x=$s->fetch(PDO::FETCH_ASSOC);$out['jobs']+=(int)$x['n'];$out['reserved']+=(int)$x['r'];}echo json_encode($out);'''
        return json.loads(self.php(code, [self.queue_cache, json.dumps(self.queue_specs)]))

    def producers(self):
        result = []
        for proc in pathlib.Path('/proc').iterdir():
            if not proc.name.isdigit():
                continue
            try:
                args = (proc / 'cmdline').read_bytes().split(b'\0')
                if b'queue:work' in args:
                    continue
                own = any(x.endswith(b'/artisan') and pathlib.Path(x.decode()).resolve() == self.root / 'artisan' for x in args)
                own = own or b'artisan' in args and pathlib.Path(os.readlink(proc / 'cwd')).resolve() == self.root
                if own:
                    result.append(int(proc.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError, UnicodeError):
                continue
        return result

    def drain_producers(self):
        until = time.monotonic() + self.p.get('drain_timeout', 120)
        while self.producers():
            if time.monotonic() > until:
                raise Refuse('own_producer_drain_timeout_no_force')
            time.sleep(.25)

    def stopped(self):
        rows = self.statuses()
        if any(x['state'] != 'STOPPED' or x['pid'] != 0 for x in rows.values()) or self.own_queue_pids() or self.counts()['reserved']:
            raise Refuse('actual_stopped_and_idle_required')
        for name in rows:
            value = self.run(['supervisorctl', 'pid', name], allowed=(0, 7))
            if value.strip() != b'0':
                raise Refuse('stopped_pid_not_zero')

    def quiesce(self):
        rows = self.statuses()
        running = {name: x for name, x in rows.items() if x['state'] == 'RUNNING'}
        pids = self.own_queue_pids()
        if any(x['pid'] not in pids for x in running.values()):
            raise Refuse('unexpected_running_worker')
        self.pause_requested = True
        for name in running:
            self.run(['supervisorctl', 'signal', 'USR2', name])
        until = time.monotonic() + self.p.get('drain_timeout', 120)
        while self.counts()['reserved']:
            now = self.statuses()
            if any(now[name]['pid'] != value['pid'] for name, value in running.items()):
                raise Refuse('worker_pid_changed_while_draining')
            if time.monotonic() > until:
                raise Refuse('busy_queue_no_force_no_replay')
            time.sleep(.5)
        for name, row in self.statuses().items():
            if name in running and row['pid'] != running[name]['pid']:
                raise Refuse('worker_pid_drift_before_stop')
            # Explicitly stop BACKOFF/FATAL/EXITED as well; PID0 alone is not STOPPED.
            self.run(['supervisorctl', 'stop', name], allowed=(0, 1, 2))
        self.stopped()
        self.workers_stopped = True

    def start(self):
        for name in self.statuses():
            self.run(['supervisorctl', 'start', name], allowed=(0, 1, 2))
        until = time.monotonic() + self.p.get('start_timeout', 35)
        while time.monotonic() < until:
            rows = self.statuses()
            if all(x['state'] == 'RUNNING' for x in rows.values()):
                self.workers()
                self.workers_stopped = False
                self.pause_requested = False
                return
            time.sleep(.5)
        raise Refuse('selected_worker_start_failed')

    def http(self, host, port):
        url = ('https' if port == '443' else 'http') + '://' + host + '/'
        return int(self.run(['curl', '--noproxy', '*', '--resolve', host + ':' + port + ':127.0.0.1', '-ks', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5', url]))

    def public_codes(self):
        return {host: {port: self.http(host, port) for port in ['80', '443']} for host in self.p['server_names']}

    def await_public_baseline(self, receipt_key):
        until=time.monotonic()+10
        stable=0
        observations=[]
        self.report[receipt_key]=observations
        while time.monotonic()<until:
            codes=self.public_codes()
            observations.append(codes)
            if any(value>=500 and value!=503 for row in codes.values() for value in row.values()):
                raise Refuse('new_release_public_baseline_failed')
            stable=stable+1 if codes==self.p['public_baselines'] else 0
            if stable>=2:return
            time.sleep(.25)
        raise Refuse('new_release_public_baseline_failed')

    def restore_nginx_public(self, receipt_key):
        previous=self.nginx_worker_pids()
        if 'nginx_configs' in self.p:
            self.nginx({key: row['before'] for key, row in self.nginx_snapshots.items()})
        else:
            self.nginx(self.nginx_before)
        until=time.monotonic()+10
        while any(pathlib.Path('/proc',str(pid)).exists() for pid in previous):
            if time.monotonic()>until:
                raise Refuse('restored_nginx_generation_not_drained')
            time.sleep(.25)
        self.report[receipt_key]={'previous_worker_pids':sorted(previous),'current_worker_pids':sorted(self.nginx_worker_pids())}

    def nginx(self, content):
        if 'nginx_configs' in self.p:
            self.nginx_multi(content)
            return
        self.atomic(self.nginx_path, content, self.nginx_stat)
        self.run(['nginx', '-t'])
        self.run(['systemctl', 'reload', 'nginx'])

    def nginx_multi(self, contents):
        if not isinstance(contents, dict) or set(contents) != set(self.nginx_snapshots):
            raise Refuse('incomplete_nginx_generation')
        previous_hashes = {key: {row['before_sha'], sha(self.nginx_gates[key])}
                           for key, row in self.nginx_snapshots.items()}
        self.check_nginx_snapshot(previous_hashes)
        written = []
        try:
            for key, snapshot in self.nginx_snapshots.items():
                current = digest(snapshot['path'])
                expected = {snapshot['before_sha'], sha(self.nginx_gates[key])}
                if current not in expected:
                    raise Refuse('nginx_config_changed_before_atomic_write')
                target_sha = sha(contents[key])
                if current != target_sha:
                    self.atomic(snapshot['path'], contents[key], snapshot['path'].stat())
                    written.append(key)
            if any(digest(snapshot['path']) != sha(contents[key]) for key, snapshot in self.nginx_snapshots.items()):
                raise Refuse('nginx_generation_changed_before_validation')
            self.run(['nginx', '-t'])
            if any(digest(snapshot['path']) != sha(contents[key]) for key, snapshot in self.nginx_snapshots.items()):
                raise Refuse('nginx_generation_changed_before_reload')
        except BaseException:
            try:
                for key in reversed(written):
                    snapshot = self.nginx_snapshots[key]
                    if digest(snapshot['path']) != sha(contents[key]):
                        raise Refuse('nginx_partial_write_restore_refused')
                    self.atomic(snapshot['path'], snapshot['before'], snapshot['path'].stat())
                self.run(['nginx', '-t'])
            except BaseException as restore_error:
                self.gated = True
                raise Refuse('nginx_partial_generation_restore_failed') from restore_error
            raise
        # A failed reload may still have switched generations, so mark the
        # gate before invoking systemd and let the outer rollback restore both.
        if contents == self.nginx_gates:
            self.gated = True
        self.run(['systemctl', 'reload', 'nginx'])

    def nginx_worker_pids(self):
        rows=set()
        for p in pathlib.Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                command=(p/'cmdline').read_bytes().replace(b'\0',b' ').strip()
                if command.startswith(b'nginx: worker process'):rows.add(int(p.name))
            except OSError:pass
        return rows

    def gate(self):
        previous_workers=self.nginx_worker_pids()
        self.gated = True
        self.nginx(self.nginx_gates if 'nginx_configs' in self.p else self.nginx_gate)
        for _ in range(25):
            if all(value == 503 for row in self.public_codes().values() for value in row.values()):
                deadline=time.monotonic()+self.p.get('drain_timeout',120)
                while any(pathlib.Path('/proc',str(pid)).exists() for pid in previous_workers):
                    if time.monotonic()>deadline:
                        raise Refuse('previous_nginx_requests_not_drained_no_force')
                    time.sleep(.25)
                return
            time.sleep(.2)
        raise Refuse('owned_http_gate_not_confirmed')

    def cron(self, content):
        if 'cron_file' in self.p:
            target_sha = sha(content)
            if target_sha == self.cron_paused_sha:
                expected_sha = self.cron_before_sha
            elif target_sha == self.cron_before_sha:
                expected_sha = self.cron_paused_sha
            else:
                raise Refuse('unreviewed_dedicated_cron_generation')
            self.write_cron_file(content, expected_sha, target_sha)
            return
        self.run(['crontab', '-u', self.p.get('cron_user', 'www-data'), '-'], input=content)

    def cron_file_metadata(self, path):
        if path.is_symlink() or not path.is_file():
            raise Refuse('dedicated_cron_file_must_be_regular')
        metadata = path.stat()
        try:
            expected_uid = pwd.getpwnam(self.p['cron_file_owner']).pw_uid
            expected_gid = grp.getgrnam(self.p['cron_file_group']).gr_gid
        except KeyError as error:
            raise Refuse('dedicated_cron_file_owner_unknown') from error
        if (metadata.st_uid != expected_uid or metadata.st_gid != expected_gid or
                f'{stat.S_IMODE(metadata.st_mode):04o}' != self.p['cron_file_mode']):
            raise Refuse('dedicated_cron_file_metadata_mismatch')
        return metadata

    def write_cron_file(self, content, expected_sha, target_sha):
        path = self.cron_file_path
        metadata = self.cron_file_metadata(path)
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(path, flags)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            current = os.read(fd, metadata.st_size + 1)
            current_stat = os.fstat(fd)
            path_stat = path.stat()
            if (sha(current) != expected_sha or sha(path.read_bytes()) != expected_sha or
                    current_stat.st_ino != path_stat.st_ino or current_stat.st_dev != path_stat.st_dev):
                raise Refuse('dedicated_cron_file_compare_and_swap_refused')
            self.atomic(path, content, metadata)
            # Record the completed atomic transition before any post-write
            # checks can raise, so the caller's rollback knows what to undo.
            self.cron_paused = target_sha == self.cron_paused_sha
            self.cron_file_current_sha = target_sha
        finally:
            os.close(fd)
        if digest(path) != target_sha:
            raise Refuse('dedicated_cron_file_write_verification_failed')
        self.cron_file_metadata(path)

    def atomic(self, path, data, metadata):
        path = pathlib.Path(path)
        tmp = path.with_name('.' + path.name + '.repeat-' + secrets.token_hex(8))
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.fchown(fd, metadata.st_uid, metadata.st_gid)
            os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if tmp.exists():
                tmp.unlink()

    def state_path(self):
        return pathlib.Path('/var/lib/ansible-deploy/existing')/self.p['project']/'current.json'

    def trusted_state_directory(self, create=False):
        path = self.state_path().parent
        for part in reversed([path, *path.parents]):
            if not part.exists():
                if create:
                    part.mkdir(mode=0o700)
                else:
                    continue
            if part.is_symlink() or not part.is_dir() or part.stat().st_uid != 0 or part.stat().st_mode & 0o022:
                raise Refuse('untrusted_recorded_state_directory')
        if path.exists() and stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise Refuse('private_recorded_state_directory_required')

    def recorded_manifest(self):
        self.trusted_state_directory()
        path=self.state_path()
        if not path.exists():
            return
        if path.is_symlink() or path.stat().st_uid!=0 or stat.S_IMODE(path.stat().st_mode)!=0o600 or path.parent.stat().st_uid!=0 or stat.S_IMODE(path.parent.stat().st_mode)!=0o700:
            raise Refuse('untrusted_recorded_deployment_state')
        state=json.loads(path.read_text())
        if state.get('application_root')!=str(self.entry) or state.get('runtime_root')!=str(self.root) or state.get('server_identity_sha256')!=self.p['server_identity_sha256']:
            raise Refuse('recorded_deployment_scope_mismatch')
        self.p['live_manifest']=state['source_manifest']
        validate_profile(self.p)

    def persist_state(self):
        path=self.state_path()
        self.trusted_state_directory(create=True)
        self.state_before = path.read_bytes() if path.exists() else None
        data=json.dumps({'schema_version':1,'application_root':str(self.entry),'runtime_root':str(self.root),'server_identity_sha256':self.p['server_identity_sha256'],'source_manifest':self.p['candidate_manifest'],'receipt':self.report},indent=2).encode()
        tmp=path.with_name('.current-'+secrets.token_hex(8))
        fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        self.state_write_started = True
        os.replace(tmp,path)

    def preflight(self):
        if digest('/etc/machine-id')!=self.p['server_identity_sha256']:
            raise Refuse('wrong_server_identity')
        self.recorded_manifest()
        live_sha=self.p['live_manifest']['candidate_commit'];candidate_sha=self.p['candidate_manifest']['candidate_commit']
        if live_sha!=candidate_sha and live_sha not in self.p['candidate_manifest'].get('ancestor_commits',[]):
            raise Refuse('candidate_must_include_current_live_commit')
        if not self.root.is_dir() or not (self.root / '.env').is_file() or not (self.root / 'storage').is_dir():
            raise Refuse('existing_app_and_anchors_required')
        if digest(self.archive) != self.p['source_archive_sha256']:
            raise Refuse('source_archive_digest_mismatch')
        self.manifest(self.root, self.p['live_manifest'])
        version = self.php('echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;').decode()
        if version != self.p['php_minor'] or not stat.S_ISSOCK(path_value(self.p['fpm_socket']).stat().st_mode):
            raise Refuse('selected_php_or_fpm_not_ready')
        self.queue_cache = self.root / 'bootstrap/cache/config.php'
        self.uid, self.gid = self.queue_cache.stat().st_uid, self.queue_cache.stat().st_gid
        if self.uid == 0:
            raise Refuse('nonroot_application_configuration_owner_required')
        self.cfg = self.config(self.root)
        if stat.S_IMODE(self.queue_cache.stat().st_mode) != 0o640 or stat.S_IMODE((self.root / '.env').stat().st_mode) not in [0o600, 0o640]:
            raise Refuse('protected_env_cache_modes_required')
        self.uid, self.gid = self.queue_cache.stat().st_uid, self.queue_cache.stat().st_gid
        self.worker_rows, self.queue_specs = self.workers()
        self.validate_queue_connections()
        self.counts()
        self.active_fpm_requests(self.fpm_status())
        self.prepare_nginx()
        self.fpm_opcache_guard()
        self.supervisor_hashes = {name: digest(name) for name in self.p['supervisor_config_hashes']}
        if self.supervisor_hashes != self.p['supervisor_config_hashes']:
            raise Refuse('supervisor_configuration_drift')
        if 'cron_file' in self.p:
            self.prepare_cron_file()
        else:
            self.cron_before = self.run(['crontab', '-u', self.p.get('cron_user', 'www-data'), '-l'])
            lines = self.cron_before.splitlines(keepends=True)
            match = []
            for i, line in enumerate(lines):
                if line.lstrip().startswith(b'#'):
                    continue
                if any(re.search(re.escape(str(root).encode()) + rb'(?=/|\s|;|$)', line) for root in [self.entry, self.root]):
                    match.append(i)
            if len(match) != 1 or b'artisan schedule:run' not in lines[match[0]] or self.p['php_cli'].encode() not in lines[match[0]]:
                raise Refuse('exact_single_existing_php_scheduler_required')
            paused = lines.copy()
            paused[match[0]] = b'# REVIEWED_REPEAT_DEPLOY_PAUSE ' + paused[match[0]]
            self.cron_paused_content = b''.join(paused)
        if self.public_codes() != self.p['public_baselines']:
            raise Refuse('public_baseline_drift')
        self.env_anchor = (self.root / '.env').resolve()
        self.storage_anchor = (self.root / 'storage').resolve()
        self.anchor_inodes = {'env': self.env_anchor.stat().st_ino, 'storage': self.storage_anchor.stat().st_ino}
        self.env_hash = digest(self.env_anchor)
        self.old_cache = self.queue_cache.read_bytes()
        self.standard_public_storage = (self.root/'public/storage').is_symlink() and (self.root/'public/storage').resolve().is_relative_to(self.storage_anchor)
        self.configuration_source_changes={name for name in set(self.p['live_manifest']['files'])|set(self.p['candidate_manifest']['files'])if self.p['live_manifest']['files'].get(name)!=self.p['candidate_manifest']['files'].get(name)and(name.startswith(('config/','app/Providers/'))or name in['bootstrap/providers.php','bootstrap/app.php'])}
        if self.configuration_source_changes and not self.p.get('config_change_hashes'):raise Refuse('explicit_typed_configuration_scope_required')
        if self.p.get('queue_adapter')=='native_redis'and(self.configuration_source_changes or self.p.get('config_change_hashes')):raise Refuse('redis_configuration_delta_requires_separate_review')
        self.check_untracked_runtime()
        self.report.update(status='PREFLIGHT_PASS',own_processes=len(self.worker_rows),worker_groups=len(self.p['worker_groups']),actual_runtime_root=str(self.root))
        return self.report

    def check_untracked_runtime(self):
        known = set(self.p['live_manifest']['files'])
        copy_paths = self.effective_preserve_copy_paths()
        self.user_managed_uploads_fingerprint = self.current_user_managed_uploads_fingerprint()
        preserved = copy_paths + self.p.get('preserve_link_paths', [])
        automatic = ['bootstrap/cache', 'packages/leolnid/common-deploy', 'public/filemanager/uploads']
        if self.standard_public_storage:
            automatic.append('public/storage')
        prefixes = preserved + automatic
        for folder in ['app','bootstrap','config','database','routes','resources','lang','public','packages']:
            start = self.root/folder
            if not start.is_dir():
                continue
            for current, dirs, files in os.walk(start, followlinks=False):
                for name in list(dirs):
                    rel = str((pathlib.Path(current)/name).relative_to(self.root))
                    if name == '.git' or any(rel == p or rel.startswith(p+'/') for p in prefixes):
                        dirs.remove(name)
                    elif (pathlib.Path(current)/name).is_symlink() and rel not in known:
                        raise Refuse('unclassified_runtime_symlink')
                for name in files:
                    rel = str((pathlib.Path(current)/name).relative_to(self.root))
                    if rel not in known and not any(rel == p or rel.startswith(p+'/') for p in prefixes):
                        raise Refuse('unclassified_runtime_file_requires_profile')

    def tree_fingerprint(self,path):
        path=pathlib.Path(path)
        out={}
        def visit(p,rel):
            if p.is_symlink():out[rel]=['symlink',os.readlink(p)];return
            if p.is_dir():
                out[rel]=['directory']
                for c in sorted(p.iterdir()):visit(c,rel+'/'+c.name)
            elif p.is_file():out[rel]=['file',digest(p)]
            else:raise Refuse('unsupported_preserved_artifact_type')
        visit(path,'.')
        return out

    def prepare(self):
        self.phase = 'stage_prepare'
        copy_paths = self.effective_preserve_copy_paths()
        if self.current_user_managed_uploads_fingerprint() != self.user_managed_uploads_fingerprint:
            raise Refuse('customer_uploads_changed_after_preflight')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.stage = self.root.parent / ('.' + self.p['project'] + '-candidate-' + stamp + '-' + secrets.token_hex(4))
        self.old_root = self.root.parent / ('.' + self.p['project'] + '-previous-' + stamp + '-' + secrets.token_hex(4))
        self.control = self.root.parent / ('.' + self.p['project'] + '-deployment-' + stamp + '-' + secrets.token_hex(4))
        self.control.mkdir(mode=0o700)
        self.checkpoint()
        if shutil.disk_usage(self.root.parent).free < self.p.get('minimum_free_bytes', 1024 ** 3):
            raise Refuse('insufficient_release_space')
        self.stage.mkdir(mode=0o755)
        with tarfile.open(self.archive) as archive:
            members = archive.getmembers()
            copy_roots=[self.root/'vendor',*[self.root/x for x in copy_paths]]
            copy_size=0
            for copy_root in copy_roots:
                for current,dirs,files in os.walk(copy_root,followlinks=False):
                    copy_size += sum((pathlib.Path(current)/name).lstat().st_size for name in files)
            required=sum(max(0,x.size) for x in members)+copy_size+self.p.get('minimum_free_bytes',1024**3)
            if shutil.disk_usage(self.root.parent).free < required:
                raise Refuse('insufficient_staged_release_and_reserve_space')
            for member in members:
                rel = source_path(member.name.rstrip('/'))
                parts = pathlib.PurePosixPath(rel).parts
                if self.user_managed_path(rel):
                    raise Refuse('customer_uploads_must_not_be_in_release_artifact')
                if '.git' in parts or any(x in ['.env','auth.json','ansible.key'] for x in parts) or parts[0] in ['storage','vendor'] or rel.startswith('bootstrap/cache/') and not rel.endswith('.gitignore'):
                    raise Refuse('protected_or_secret_artifact_member')
                if member.isdev() or member.isfifo() or member.islnk():
                    raise Refuse('unsupported_artifact_member')
                if member.issym():
                    target = self.stage / pathlib.PurePosixPath(rel).parent / member.linkname
                    if not target.resolve().is_relative_to(self.stage):
                        raise Refuse('artifact_symlink_escape')
            archive.extractall(self.stage, members=members, filter='data')
        if list(self.stage.rglob('.user.ini')):
            raise Refuse('candidate_per_directory_php_ini_unsupported')
        # Code-only deployments deliberately do not run Composer or frontend tools.
        for name in ['composer.json', 'composer.lock']:
            if json.loads((self.stage / name).read_text()) != json.loads((self.root / name).read_text()):
                raise Refuse('dependency_change_requires_separate_reviewed_vendor_release')
        if 'setClassMapAuthoritative(true)' in (self.root / 'vendor/composer/autoload_real.php').read_text():
            raise Refuse('authoritative_classmap_requires_separate_reviewed_vendor_release')
        shutil.copytree(self.root / 'vendor', self.stage / 'vendor', symlinks=True)
        self.links = {'.env': self.env_anchor, 'storage': self.storage_anchor}
        if self.standard_public_storage:
            self.links['public/storage'] = (self.root/'public/storage').resolve()
        self.preserved_copy_fingerprints={}
        for rel in copy_paths:
            src, dst = self.root / rel, self.stage / rel
            if dst.exists() or dst.is_symlink() or not src.exists():
                raise Refuse('ambiguous_preserved_artifact')
            if src.is_symlink():
                raise Refuse('preserved_symlink_must_be_a_runtime_link')
            self.preserved_copy_fingerprints[rel]=self.tree_fingerprint(src)
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            if rel == 'public/filemanager/uploads':
                self.preserve_user_managed_metadata(src, dst)
                if self.user_managed_tree_fingerprint(dst) != self.user_managed_uploads_fingerprint:
                    raise Refuse('customer_uploads_metadata_or_content_changed_during_copy')
            if self.tree_fingerprint(dst) != self.preserved_copy_fingerprints[rel]:
                raise Refuse('preserved_artifact_copy_mismatch')
        for rel in self.p.get('preserve_link_paths', []):
            self.links[rel] = (self.root / rel).resolve(strict=True)
        for rel, anchor in self.links.items():
            target = self.stage / rel
            if target.exists() or target.is_symlink():
                raise Refuse('artifact_overlaps_existing_runtime_anchor')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(anchor, target_is_directory=anchor.is_dir())
        for root, dirs, files in os.walk(self.stage, followlinks=False):
            for name in dirs + files:
                path = pathlib.Path(root) / name
                if path.is_symlink():
                    continue
                if self.user_managed_path(path.relative_to(self.stage).as_posix()):
                    continue
                mode = 0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644
                os.chown(path, self.uid, self.gid)
                path.chmod(mode)
                if path.is_file():
                    old=self.root/path.relative_to(self.stage)
                    fresh=int(time.time())
                    if old.is_file() and int(old.stat().st_mtime)==fresh:fresh+=1
                    os.utime(path,(fresh,fresh))
        os.chown(self.stage, self.uid, self.gid)
        cache_dir = self.stage / 'bootstrap/cache'
        cache_dir.mkdir(parents=True, exist_ok=True)
        os.chown(cache_dir, self.uid, self.gid)
        cache_dir.chmod(0o755)
        cache_file = cache_dir/'config.php'
        if cache_file.exists():
            raise Refuse('artifact_must_not_supply_default_cache')
        cache_file.write_bytes(self.old_cache)
        os.chown(cache_file,self.uid,self.gid)
        cache_file.chmod(0o640)
        self.manifest(self.stage, self.p['candidate_manifest'])
        self.php("require $argv[1].'/vendor/composer/platform_check.php';", [self.stage])
        self.report.update(stage=str(self.stage),retained_previous_release=str(self.old_root))
        self.checkpoint()

    def config_equal(self, old, new, path=''):
        key=path.lstrip('.')
        delta=self.p.get('config_change_hashes',{}).get(key)
        if delta is not None:
            canonical=lambda value:sha(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode())
            return canonical(old)==delta['old'] and canonical(new)==delta['new']
        if type(old) is not type(new):
            return False
        if isinstance(old, dict):
            return old.keys() == new.keys() and all(self.config_equal(old[k], new[k], path + '.' + str(k)) for k in old)
        if isinstance(old, list):
            return len(old) == len(new) and all(self.config_equal(a, b, path + '[]') for a, b in zip(old, new))
        if old == new:
            return True
        # Only path-valued fields that resolve to the very same retained data are
        # mechanically equivalent. Never rewrite configuration values at runtime.
        if key in self.p.get('same_inode_config_paths', []) and isinstance(old, str) and isinstance(new, str):
            a, b = pathlib.Path(old), pathlib.Path(new)
            return a.is_absolute() and b.is_absolute() and a.exists() and b.exists() and a.stat().st_dev == b.stat().st_dev and a.stat().st_ino == b.stat().st_ino
        return False

    def build_config(self):
        self.phase='protected_final_config'
        cache=self.root/'bootstrap/cache/config.php'
        if not self.configuration_source_changes and not self.p.get('config_change_hashes'):
            if cache.read_bytes()!=self.old_cache or stat.S_IMODE(cache.stat().st_mode)!=0o640 or(cache.stat().st_uid,cache.stat().st_gid)!=(self.uid,self.gid):raise Refuse('preserved_configuration_drift')
            self.report['configuration_strategy']='preserved_exact_existing_config'
            return
        temp=cache.with_name('.repeat-config-'+secrets.token_hex(8)+'.php');self.temp_cache=temp
        private={key:cache.with_name('.repeat-'+kind+'-'+secrets.token_hex(8)+'.php')for key,kind in [('APP_CONFIG_CACHE','config'),('APP_SERVICES_CACHE','services'),('APP_PACKAGES_CACHE','packages'),('APP_EVENTS_CACHE','events'),('APP_ROUTES_CACHE','routes')]};private['APP_CONFIG_CACHE']=temp
        storage=cache.parent/('.repeat-private-storage-'+secrets.token_hex(8));storage.mkdir(mode=0o700);os.chown(storage,self.uid,self.gid)
        for name in ['framework','framework/cache','framework/cache/data','framework/views','framework/sessions','logs','app']:
            folder=storage/name;folder.mkdir(mode=0o700,exist_ok=True);os.chown(folder,self.uid,self.gid)
        self.report['private_bootstrap_storage_retained']=str(storage)
        prefix=['unshare','--net','setpriv','--reuid='+str(self.uid),'--regid='+str(self.gid),'--init-groups','env','LARAVEL_STORAGE_PATH='+str(storage),*[k+'='+str(v)for k,v in private.items()],self.p['php_cli']]
        probe="require $argv[1].'/vendor/autoload.php';$a=require $argv[1].'/bootstrap/app.php';echo json_encode([$a->getCachedConfigPath(),$a->getCachedServicesPath(),$a->getCachedPackagesPath(),$a->getCachedEventsPath(),$a->getCachedRoutesPath(),$a->storagePath()]);"
        try:
            if json.loads(self.run(prefix+['-r',probe,str(self.root)]))!=[str(v)for v in private.values()]+[str(storage)]:raise Refuse('private_cache_and_storage_paths_required')
            self.run(prefix+['artisan','config:cache','--quiet'],cwd=self.root,umask=0o077)
            if cache.read_bytes()!=self.old_cache:raise Refuse('default_cache_changed_before_validated_promotion')
            temp.chmod(0o600)
            allowed=self.p.get('config_change_hashes',{})
            if allowed:
                _native_config.merge_native_config_nodes(self,cache,temp,allowed)
            if not _native_config.native_config_proof(self,cache,temp,allowed):raise Refuse('unreviewed_native_effective_configuration_change')
            if not allowed:
                temp.unlink();self.temp_cache=None
                self.report['configuration_strategy']='private_bootstrap_exact_effective_config_preserved'
                return
            os.chown(temp,self.uid,self.gid);temp.chmod(0o640);now=int(time.time());now+=int(now==int(cache.stat().st_mtime));os.utime(temp,(now,now));os.replace(temp,cache);self.temp_cache=None
            self.report['configuration_strategy']='native_reviewed_nodes_only_private_storage'
        except _native_config.ConfigurationRefuse as error:raise Refuse(str(error))from error
        finally:
            for path in private.values():
                if path.exists():path.unlink()

    def cutover(self):
        self.phase = 'fresh_live_guards'
        self.manifest(self.root,self.p['live_manifest'])
        if self.env_hash != digest(self.env_anchor) or self.old_cache != (self.root/'bootstrap/cache/config.php').read_bytes() or self.supervisor_hashes != {p:digest(p) for p in self.supervisor_hashes}:
            raise Refuse('protected_runtime_drift')
        if 'nginx_configs' in self.p:
            self.check_nginx_snapshot()
        elif self.nginx_before != self.nginx_path.read_bytes():
            raise Refuse('protected_runtime_drift')
        if 'cron_file' in self.p:
            if digest(self.cron_file_path) != self.cron_before_sha:
                raise Refuse('dedicated_cron_file_changed_during_stage')
            self.cron_file_metadata(self.cron_file_path)
        elif self.cron_before != self.run(['crontab','-u',self.p.get('cron_user','www-data'),'-l']):
            raise Refuse('protected_runtime_drift')
        if getattr(self,'fpm_config_hashes',{}) != {p:digest(p) for p in getattr(self,'fpm_config_hashes',{})}:
            raise Refuse('fpm_configuration_changed_during_stage')
        if any(self.tree_fingerprint(self.root/rel)!=h for rel,h in self.preserved_copy_fingerprints.items()):
            raise Refuse('preserved_artifacts_changed_during_stage_build')
        if self.current_user_managed_uploads_fingerprint() != self.user_managed_uploads_fingerprint:
            raise Refuse('customer_uploads_changed_during_stage_build')
        rows,_ = self.workers()
        if rows != self.worker_rows:
            raise Refuse('worker_pid_changed_before_cutover')
        self.phase = 'own_cron_and_producer_drain'
        self.cron(self.cron_paused_content)
        self.cron_paused = True
        self.drain_producers()
        self.phase = 'owned_http_gate_and_worker_idle'
        self.gate()
        self.drain_fpm()
        self.quiesce()
        self.stopped()
        if self.current_user_managed_uploads_fingerprint() != self.user_managed_uploads_fingerprint:
            raise Refuse('customer_uploads_changed_at_cutover_boundary')
        if ('public/filemanager/uploads' in self.preserved_copy_fingerprints and
                self.user_managed_tree_fingerprint(self.stage/'public/filemanager/uploads') != self.user_managed_uploads_fingerprint):
            raise Refuse('staged_customer_uploads_changed_at_cutover_boundary')
        self.phase = 'atomic_release_cutover'
        self.root.rename(self.old_root)
        self.old_moved = True
        self.queue_cache = self.old_root/'bootstrap/cache/config.php'
        for rel, original in self.links.items():
            anchor = self.old_root/original.relative_to(self.root) if original.is_relative_to(self.root) else original
            link = self.stage/rel
            link.unlink()
            link.symlink_to(anchor,target_is_directory=anchor.is_dir())
        self.stage.rename(self.root)
        self.swapped = True
        if ('public/filemanager/uploads' in self.preserved_copy_fingerprints and
                self.user_managed_tree_fingerprint(self.root/'public/filemanager/uploads') != self.user_managed_uploads_fingerprint):
            raise Refuse('customer_uploads_not_preserved_in_cutover')
        self.build_config()
        if digest(self.root/'.env') != self.env_hash or (self.root/'.env').stat().st_ino != self.anchor_inodes['env'] or (self.root/'storage').stat().st_ino != self.anchor_inodes['storage']:
            raise Refuse('runtime_anchor_changed')
        self.manifest(self.root,self.p['candidate_manifest'])
        self.phase = 'start_owned_topology'
        self.start()
        time.sleep(getattr(self,'opcache_delay',0))
        self.restore_nginx_public('cutover_nginx_generations')
        self.gated = False
        self.await_public_baseline('public_cutover_observations')
        self.cron(self.cron_before)
        self.cron_paused = False
        if self.supervisor_hashes != {p:digest(p) for p in self.supervisor_hashes}:
            raise Refuse('supervisor_was_changed')
        self.manifest(self.root,self.p['candidate_manifest'])
        if hasattr(self, 'nginx_snapshots'):
            self.check_nginx_snapshot()
        self.phase = 'verified'
        self.report.update(status='PASS',completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),own_processes=len(self.statuses()),env_storage_same_inodes=True,supervisor_and_cron_topology_unchanged=True,source_permissions_normalized_in_stage_only=True,backup_reference=self.p['backup_reference'])
        self.checkpoint()
        self.persist_state()
        return self.report

    def rollback(self):
        self.phase = 'rollback'
        if self.swapped:
            if not self.cron_paused:
                self.cron(self.cron_paused_content)
                self.cron_paused = True
            if not self.gated:
                self.gate()
            self.drain_fpm()
            self.drain_producers()
            # Always reconcile actual states, even after a partially failed start.
            self.quiesce()
            self.stopped()
            failed = self.control/'failed-release'
            self.root.rename(failed)
            self.old_root.rename(self.root)
            self.swapped=False;self.old_moved=False
            self.queue_cache = self.root/'bootstrap/cache/config.php'
            self.manifest(self.root,self.p['live_manifest'])
        elif self.old_moved:
            self.stopped()
            self.old_root.rename(self.root)
            self.swapped=False;self.old_moved=False
            self.queue_cache = self.root/'bootstrap/cache/config.php'
        if self.workers_stopped or self.pause_requested and any(x['state'] != 'RUNNING' for x in self.statuses().values()):
            self.quiesce()
            self.stopped()
            self.start()
        elif self.pause_requested:
            rows = self.statuses()
            if rows != self.worker_rows:
                raise Refuse('cannot_resume_changed_worker_pids')
            for name in rows:
                self.run(['supervisorctl','signal','CONT',name])
        if self.gated:
            time.sleep(getattr(self,'opcache_delay',0))
            self.restore_nginx_public('rollback_nginx_generations')
            self.gated = False
            self.await_public_baseline('public_rollback_observations')
        if self.cron_paused:
            self.cron(self.cron_before)
            self.cron_paused = False
        if getattr(self, 'state_write_started', False):
            path = self.state_path()
            self.trusted_state_directory()
            if self.state_before is None:
                path.unlink(missing_ok=True)
            else:
                self.atomic(path, self.state_before, path.stat())
            self.state_write_started = False
        self.report['rollback_complete'] = True
        self.checkpoint()

    def execute(self, apply=False):
        self.control = None
        self.preflight()
        if not apply:
            return {**self.report,'status':'PREFLIGHT_ONLY','production_changed':False}
        lock_dir = pathlib.Path('/run/lock')
        fd=os.open(lock_dir/'amorenat-existing-repeat-deploy.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        if os.fstat(fd).st_uid!=0 or not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd);raise Refuse('untrusted_host_deployment_lock')
        with os.fdopen(fd,'a+b') as lock:
            os.fchmod(lock.fileno(),0o600)
            fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.preflight()
            try:
                self.prepare()
                return self.cutover()
            except BaseException as exc:
                self.report.update(status='FAIL',failed_phase=self.phase,error_class=type(exc).__name__)
                try:
                    self.rollback()
                except BaseException as recovery:
                    self.report.update(hold_no_forced_rewrite=True,rollback_error_class=type(recovery).__name__)
                    self.checkpoint()
                raise

def release_for(profile,archive):
    release=ExistingRelease(profile,archive)
    if profile.get('queue_adapter','database')=='database':return release
    if profile['project']not in['contact-channel','salesbots']:raise Refuse('redis_project_not_allowlisted')
    module=pinned_module('repeat_native_redis','s2_native_redis_queue_mixin.py','d1c0ff39e2ddcc19a36e5eb00737bc1d6a4bd88a1449187a4b40d066d6597a4f')
    adapter=pathlib.Path(__file__).with_name('s2_native_redis_queue_adapter.php');raw=adapter.read_bytes()
    if adapter.is_symlink()or sha(raw)!='ac2332daf66355ba84c286f5ad59cbef23ee1d105d2611ca1f4974f66a383414':raise Refuse('pinned_native_redis_adapter_drift')
    class RedisRelease(module.NativeRedisQueueMixin,ExistingRelease):
        NativeQueueRefuse=Refuse
        def validate_queue_connections(self):
            module.NativeRedisQueueMixin.validate_queue_connections(self)
            queues,count={'contact-channel':({'default','backfill'},2),'salesbots':({'default'},1)}[self.p['project']]
            if{q for selected in self.queue_specs.values()for q in selected}!=queues or len(self.worker_rows)!=count:raise Refuse('redis_owned_topology_drift')
    release.__class__=RedisRelease;release.bind_native_redis_adapter(raw.decode('utf-8'));return release

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True)
    parser.add_argument('--archive',required=True)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args(argv)
    release = None
    def cancelled(signum, frame):
        raise Refuse('deployment_cancelled')
    for sig in [signal.SIGTERM,signal.SIGHUP]:
        signal.signal(sig,cancelled)
    try:
        profile = json.loads(pathlib.Path(args.profile).read_text())
        release = release_for(profile,args.archive)
        print(json.dumps(release.execute(args.apply)))
        return 0
    except BaseException as exc:
        receipt = release.report if release is not None else {}
        reason=str(exc) if isinstance(exc,Refuse) and re.fullmatch(r'[a-z0-9_]{1,120}',str(exc)) else 'execution_failed'
        print(json.dumps({**receipt,'status':'FAIL','error_class':type(exc).__name__,'error_code':reason}))
        return 1

if __name__ == '__main__':
    sys.exit(main())
