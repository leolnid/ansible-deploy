import copy, hashlib, importlib.util, io, json, os, pathlib, shutil, tarfile, tempfile, unittest
import grp, pwd, stat
from unittest import mock
MODULE=pathlib.Path(__file__).resolve().parents[2]/'roles/RepeatDeploy/files/repeat_deploy.py'
spec=importlib.util.spec_from_file_location('repeat_deploy',MODULE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FIXTURE_ROOT=pathlib.Path(os.environ.get('REPEAT_DEPLOY_TEST_ROOT',tempfile.gettempdir())).resolve()

def h(data):return hashlib.sha256(data).hexdigest()

class SandboxRelease(m.ExistingRelease):
    def __init__(self,p,archive,base,*,failure=None,reserved=0):
        # The production executor only accepts app roots under /var/www,
        # /home/user/www or /srv. Validate all fields against the synthetic
        # /srv path, then bind this test instance to its private fixture tree.
        # The production validator itself remains unchanged and is separately
        # tested to refuse the /root fixture path.
        synthetic_root='/srv/repeat-deploy-private-fixture/application'
        sandbox_profile=copy.deepcopy(p);sandbox_profile['application_root']=synthetic_root
        original_resolve=pathlib.Path.resolve
        def resolve_synthetic(path,strict=False):
            if str(path)==synthetic_root:return pathlib.Path(synthetic_root)
            return original_resolve(path,strict=strict)
        with mock.patch.object(pathlib.Path,'resolve',resolve_synthetic):super().__init__(sandbox_profile,archive)
        self.p['application_root']=p['application_root'];self.entry=pathlib.Path(p['application_root']);self.root=self.entry.resolve(strict=True)
        self.base=base;self.state_temp=tempfile.TemporaryDirectory(prefix='.repeat-state-',dir=FIXTURE_ROOT);self.failure=failure;self.reserved=reserved;self.events=[];self.next_pid=2000;self.failed_start_once=False
        self.states={f'{group}:{group}_{i:02}':{'state':'RUNNING','pid':1000+len(self.states) if hasattr(self,'states') else 1000+i} for group,n in p['worker_groups'].items() for i in range(n)}
        for i,row in enumerate(self.states.values()):row['pid']=1000+i
        self.cron_current=b'* * * * * cd '+str(self.entry).encode()+b' && /usr/bin/php8.5 artisan schedule:run\n'
        self.fake_cfg={'app':{'name':'synthetic'},'queue':{'default':'database'},'view':{'compiled':'same'}}
        self.fresh_cfg=copy.deepcopy(self.fake_cfg)
        if failure=='config':self.fresh_cfg['queue']['default']='unreviewed'
    def preflight(self):
        self.manifest(self.root,self.p['live_manifest']);self.cfg=copy.deepcopy(self.fake_cfg);self.queue_cache=self.root/'bootstrap/cache/config.php';self.old_cache=self.queue_cache.read_bytes();self.uid=os.getuid();self.gid=os.getgid();self.env_anchor=(self.root/'.env').resolve();self.storage_anchor=(self.root/'storage').resolve();self.env_hash=m.digest(self.env_anchor);self.anchor_inodes={'env':self.env_anchor.stat().st_ino,'storage':self.storage_anchor.stat().st_ino};self.worker_rows,self.queue_specs=self.workers();self.nginx_path=self.base/'nginx.conf';self.nginx_before=self.nginx_path.read_bytes();self.nginx_stat=self.nginx_path.stat();self.nginx_gate=self.nginx_before+b'\nreturn 503;\n';self.cron_before=self.cron_current;self.cron_paused_content=b'# own deployment pause\n';self.supervisor_hashes={str(self.base/'supervisor.conf'):m.digest(self.base/'supervisor.conf')};self.standard_public_storage=False;self.check_untracked_runtime();self.configuration_source_changes={name for name in set(self.p['live_manifest']['files'])|set(self.p['candidate_manifest']['files'])if self.p['live_manifest']['files'].get(name)!=self.p['candidate_manifest']['files'].get(name)and(name.startswith(('config/','app/Providers/'))or name in['bootstrap/providers.php','bootstrap/app.php'])};self.report['status']='PREFLIGHT_PASS';return self.report
    def state_path(self):return pathlib.Path(self.state_temp.name)/'state/current.json'
    def trusted_state_directory(self,create=False):
        # The Linux runner intentionally keeps everything beneath /root, whose
        # mode on the S1 host is 0775. Production validation checks all system
        # ancestors; this test-only mirror treats the dedicated 0700 fixture
        # root as its trust anchor and checks every directory below it.
        root=FIXTURE_ROOT;path=self.state_path().parent
        if root not in path.parents or root.is_symlink() or not root.is_dir() or root.stat().st_uid!=0 or root.stat().st_mode&0o022 or (root.stat().st_mode&0o777)!=0o700:
            raise m.Refuse('untrusted_recorded_state_directory')
        relative=path.relative_to(root);parts=[root]
        for item in relative.parts:parts.append(parts[-1]/item)
        for part in parts[1:]:
            if not part.exists():
                if create:part.mkdir(mode=0o700)
                else:continue
            if part.is_symlink() or not part.is_dir() or part.stat().st_uid!=0 or part.stat().st_mode&0o022:
                raise m.Refuse('untrusted_recorded_state_directory')
        if path.exists() and path.stat().st_mode&0o777!=0o700:raise m.Refuse('private_recorded_state_directory_required')
    def recorded_manifest(self):
        original_validate=m.validate_profile
        def validate_sandbox_profile(profile):
            sandbox_profile=copy.deepcopy(profile);sandbox_profile['application_root']='/srv/repeat-deploy-private-fixture/application'
            checked=original_validate(sandbox_profile);checked['application_root']=profile['application_root'];return checked
        with mock.patch.object(m,'validate_profile',validate_sandbox_profile):return super().recorded_manifest()
    def workers(self):return copy.deepcopy(self.states),{'database':['default','backfill']}
    def statuses(self):return copy.deepcopy(self.states)
    def own_queue_pids(self):return {x['pid']:[] for x in self.states.values() if x['state']=='RUNNING'}
    def counts(self):return {'jobs':2 if self.reserved else 0,'reserved':self.reserved}
    def producers(self):return []
    def nginx_worker_pids(self):return set()
    def fpm_status(self):return {'pool':'fixture','listen queue':0,'total processes':1,'processes':[{'pid':1,'state':'Idle','script':'-'}]}
    def drain_fpm(self):return super().drain_fpm()
    def public_codes(self):
        code=503 if b'return 503' in self.nginx_path.read_bytes() else 500 if self.failure=='public' and self.swapped else 200
        return {host:{'80':code,'443':code} for host in self.p['server_names']}
    def php(self,code,args=(),**kwargs):
        if '$c=require' in code:return json.dumps(self.fresh_cfg).encode()
        return b''
    def run(self,args,*,input=None,**kwargs):
        self.events.append(tuple(args))
        if args[0]=='crontab':
            if args[-1]=='-l':return self.cron_current
            self.cron_current=input;return b''
        if args[0]=='supervisorctl':
            action,name=args[1],args[-1]
            if action=='pid':return str(self.states[name]['pid']).encode()
            if action=='stop':self.states[name]={'state':'STOPPED','pid':0};return b''
            if action=='start':
                if self.failure=='start' and not self.failed_start_once:
                    self.states[name]={'state':'BACKOFF','pid':0};self.failed_start_once=True;return b''
                self.next_pid+=1;self.states[name]={'state':'RUNNING','pid':self.next_pid};return b''
            return b''
        if args[0] in ['sudo','unshare']:
            target=next(x.partition('=')[2] for x in args if x.startswith('APP_CONFIG_CACHE='))
            if any('getCachedConfigPath' in x for x in args):return json.dumps([x.partition('=')[2] for x in args if x.startswith(('APP_CONFIG_CACHE=','APP_SERVICES_CACHE=','APP_PACKAGES_CACHE=','APP_EVENTS_CACHE=','APP_ROUTES_CACHE='))]).encode()
            if 'config:cache' in args:pathlib.Path(target).write_bytes(b'synthetic-new-cache');return b''
        return b''
    def build_config(self):
        if self.failure=='config':raise m.Refuse('simulated_unreviewed_configuration_change')
        return super().build_config()
    def start(self):
        if self.failure=='start' and not self.failed_start_once:
            name=next(iter(self.states));self.run(['supervisorctl','start',name]);raise m.Refuse('simulated_start_backoff')
        return super().start()

class ContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='.repeat-package-test-',dir=FIXTURE_ROOT);self.base=pathlib.Path(self.tmp.name);self.live=self.base/'application';self.live.mkdir();(self.live/'app').mkdir();(self.live/'bootstrap/cache').mkdir(parents=True);(self.live/'storage/app').mkdir(parents=True);(self.live/'.env').write_bytes(b'SYNTHETIC_NOT_A_REAL_CREDENTIAL=fixture\n');(self.live/'.env').chmod(0o640);(self.live/'storage/app/customer-data.txt').write_bytes(b'synthetic-user-data');(self.live/'storage/app/customer-data.txt').chmod(0o664);(self.live/'bootstrap/cache/config.php').write_bytes(b'synthetic-old-cache');(self.live/'bootstrap/cache/config.php').chmod(0o640);(self.live/'vendor/composer').mkdir(parents=True);(self.live/'vendor/composer/autoload_real.php').write_text('<?php');(self.live/'vendor/composer/platform_check.php').write_text('<?php');(self.base/'nginx.conf').write_bytes(b'server { server_name fixture.example.invalid; }');(self.base/'supervisor.conf').write_bytes(b'synthetic-existing-topology')
        self.user_upload=self.live/'public/filemanager/uploads/416255.png'
        self.old={'app/Marker.php':b'<?php // old\n','composer.json':b'{"require":{"php":"^8.5"}}\n','composer.lock':b'{"packages":[]}\n','bootstrap/app.php':b'<?php // synthetic bootstrap\n'}
        self.new={**self.old,'app/Marker.php':b'<?php // new\n'}
        for name,data in self.old.items():p=self.live/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
        self.archive=self.base/'source.tar.gz'
        with tarfile.open(self.archive,'w:gz') as t:
            for name,data in self.new.items():
                data=data.replace(b'\n',b'\n');info=tarfile.TarInfo(name);info.size=len(data);info.mode=0o666;t.addfile(info,io.BytesIO(data))
        manifest=lambda files,sha:{'candidate_commit':sha*40,'files':{n:h(v.replace(b'\n',b'\n')) for n,v in files.items()},'normalization_by_path':{n:'crlf_to_lf' for n in files}}
        self.profile={'schema_version':1,'project':'fixture','application_root':str(self.live),'php_cli':'/usr/bin/php8.5','php_minor':'8.5','fpm_socket':'/run/php/php8.5-fpm.sock','nginx_config':'/etc/nginx/sites-enabled/fixture.conf','server_names':['fixture.example.invalid'],'public_baselines':{'fixture.example.invalid':{'80':200,'443':200}},'worker_groups':{'fixture':1},'supervisor_config_hashes':{'/etc/supervisor/conf.d/fixture.conf':'a'*64},'live_manifest':manifest(self.old,'a'),'candidate_manifest':manifest(self.new,'b'),'source_archive_sha256':m.digest(self.archive),'backup_reference':'synthetic-verified-backup','server_identity_sha256':'c'*64,'fpm_status_path':'/existing-status','fpm_pool':'fixture','minimum_free_bytes':0,'drain_timeout':.01,'start_timeout':.01}
    def tearDown(self):
        target=self.base.resolve();assert target.parent==FIXTURE_ROOT and target.name.startswith('.repeat-package-test-');self.tmp.cleanup()
    def release(self,**kwargs):
        release=SandboxRelease(self.profile,self.archive,self.base,**kwargs)
        self.addCleanup(release.state_temp.cleanup)
        return release
    def apply(self,r):
        r.control=None;r.preflight()
        try:r.prepare();return r.cutover()
        except BaseException:r.rollback();raise
    def assert_original(self,r):
        self.assertEqual((self.live/'app/Marker.php').read_bytes(),self.old['app/Marker.php']);self.assertEqual((self.live/'.env').read_bytes(),b'SYNTHETIC_NOT_A_REAL_CREDENTIAL=fixture\n');self.assertEqual((self.live/'storage/app/customer-data.txt').read_bytes(),b'synthetic-user-data');self.assertEqual(r.cron_current,r.cron_before);self.assertEqual(r.nginx_path.read_bytes(),r.nginx_before);self.assertTrue(all(x['state']=='RUNNING' for x in r.statuses().values()))
        if self.user_upload.exists():self.assertEqual(self.user_upload.read_bytes(),b'customer upload differs from tracked Git blob')
    def special_profile(self):
        profile=copy.deepcopy(self.profile);profile.pop('nginx_config')
        http_path='/etc/nginx/sites-available/fixture-http.conf';https_path='/etc/nginx/sites-available/fixture-https.conf'
        profile['nginx_configs']=[http_path,https_path]
        self.http_config=b'server { listen 80; server_name fixture.example.invalid; }\n'
        self.https_config=b'server { listen 443 ssl; server_name fixture.example.invalid; location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.5-fpm.sock; } }\n'
        self.special_http=self.base/'fixture-http.conf';self.special_https=self.base/'fixture-https.conf'
        self.special_http.write_bytes(self.http_config);self.special_https.write_bytes(self.https_config)
        for path in [self.special_http,self.special_https]:path.chmod(0o644)
        profile['nginx_config_hashes']={http_path:h(self.http_config),https_path:h(self.https_config)}
        self.cron_file=self.base/'flowwow-ms.cron'
        self.cron_original=(b'# root-owned dedicated file\n* * * * * '+pwd.getpwuid(os.getuid()).pw_name.encode()+b' cd '+str(self.live).encode()+b' && /usr/bin/php8.5 artisan schedule:run >/dev/null 2>&1\n')
        self.cron_file.write_bytes(self.cron_original);self.cron_file.chmod(0o644)
        profile.update(cron_file='/etc/cron.d/fixture',cron_file_sha256=h(self.cron_original),cron_file_owner=pwd.getpwuid(os.getuid()).pw_name,cron_file_group=grp.getgrgid(os.getgid()).gr_name,cron_file_mode='0644',cron_file_scheduler_user=pwd.getpwuid(os.getuid()).pw_name)
        return profile
    def prepare_special_ports(self,r):
        mapping={'/etc/nginx/sites-available/fixture-http.conf':self.special_http,'/etc/nginx/sites-available/fixture-https.conf':self.special_https,'/etc/cron.d/fixture':self.cron_file}
        r.system_path=lambda value:mapping[value]
        r.nginx_path_in_scope=lambda target:True
        r.prepare_nginx();r.prepare_cron_file()
        return r
    def test_success_preserves_anchor_inodes_and_runtime_permissions(self):
        env=(self.live/'.env').stat().st_ino;storage=(self.live/'storage').stat().st_ino;r=self.release();out=self.apply(r);self.assertEqual(out['status'],'PASS');self.assertEqual((self.live/'.env').stat().st_ino,env);self.assertEqual((self.live/'storage').stat().st_ino,storage);self.assertEqual((self.live/'app/Marker.php').stat().st_mode&0o777,0o644);self.assertEqual((self.live/'storage/app/customer-data.txt').stat().st_mode&0o777,0o664);self.assertEqual((self.live/'bootstrap/cache/config.php').stat().st_mode&0o777,0o640);self.assertTrue(r.old_root.is_dir());self.assertEqual(r.cron_current,r.cron_before)
    def test_tracked_customer_upload_is_preserved_outside_the_candidate_manifest(self):
        self.user_upload.parent.mkdir(parents=True);self.user_upload.write_bytes(b'customer upload differs from tracked Git blob')
        self.user_upload.chmod(0o640);os.utime(self.user_upload,ns=(1700000000000000000,1700000000000000000))
        expected_metadata=(self.user_upload.stat().st_uid,self.user_upload.stat().st_gid,stat.S_IMODE(self.user_upload.stat().st_mode),self.user_upload.stat().st_mtime_ns)
        r=self.release();upload='public/filemanager/uploads/416255.png'
        r.p['live_manifest']['files'][upload]=h(b'older tracked Git version')
        out=self.apply(r)
        staged=self.live/upload
        self.assertEqual(out['status'],'PASS');self.assertEqual(staged.read_bytes(),b'customer upload differs from tracked Git blob')
        actual=staged.stat();self.assertEqual((actual.st_uid,actual.st_gid,stat.S_IMODE(actual.st_mode),actual.st_mtime_ns),expected_metadata)
        self.assertNotIn(upload,r.p['candidate_manifest']['files'])
        self.assertEqual(r.preserved_copy_fingerprints["public/filemanager/uploads"],r.tree_fingerprint(self.live/'public/filemanager/uploads'))
    def test_crlf_manifest_normalization_uses_real_crlf_bytes(self):
        rel='app/CrLfFixture.php';self.live.joinpath(rel).write_bytes(b'line one\r\nline two\r\n')
        r=self.release();manifest={'files':{rel:h(b'line one\nline two\n')},'normalization_by_path':{rel:'crlf_to_lf'}}
        r.manifest(self.live,manifest)
    def test_customer_upload_change_after_preflight_refuses_before_staging(self):
        self.user_upload.parent.mkdir(parents=True);self.user_upload.write_bytes(b'customer upload before preflight')
        r=self.release();r.preflight();self.user_upload.write_bytes(b'customer upload received during preflight')
        with self.assertRaisesRegex(m.Refuse,'customer_uploads_changed_after_preflight'):
            r.prepare()
        self.assertEqual(self.user_upload.read_bytes(),b'customer upload received during preflight')
        self.assertIsNone(getattr(r,'stage',None));self.assertEqual(r.events,[])
    def test_new_upload_directory_after_preflight_refuses_before_staging(self):
        r=self.release();r.preflight();self.user_upload.parent.mkdir(parents=True);self.user_upload.write_bytes(b'first customer upload')
        with self.assertRaisesRegex(m.Refuse,'customer_uploads_changed_after_preflight'):
            r.prepare()
        self.assertEqual(self.user_upload.read_bytes(),b'first customer upload')
        self.assertIsNone(getattr(r,'stage',None));self.assertEqual(r.events,[])
    def test_upload_created_during_quiesce_refuses_before_atomic_root_switch(self):
        r=self.release();original_stopped=r.stopped;injected=False
        def stop_then_create_upload():
            nonlocal injected
            original_stopped()
            if not injected:
                injected=True;self.user_upload.parent.mkdir(parents=True);self.user_upload.write_bytes(b'upload completed during drain')
        r.stopped=stop_then_create_upload
        with self.assertRaisesRegex(m.Refuse,'customer_uploads_changed_at_cutover_boundary'):
            self.apply(r)
        self.assertTrue(injected);self.assertFalse(r.swapped);self.assertFalse(r.old_moved)
        self.assertEqual((self.live/'app/Marker.php').read_bytes(),self.old['app/Marker.php'])
        self.assertEqual(self.user_upload.read_bytes(),b'upload completed during drain')
        self.assertTrue(all(row['state']=='RUNNING' for row in r.statuses().values()))
    def test_recorded_state_advances_and_rejects_redirected_directory(self):
        r=self.release();self.apply(r)
        state=json.loads(r.state_path().read_text())
        self.assertEqual(state['source_manifest'],self.profile['candidate_manifest'])
        self.assertEqual(r.state_path().stat().st_mode&0o777,0o600)
        r.recorded_manifest();self.assertEqual(r.p['live_manifest'],self.profile['candidate_manifest'])
        r.state_path().unlink();r.state_path().parent.rmdir()
        target=self.base/'redirect';target.mkdir(mode=0o700);r.state_path().parent.symlink_to(target)
        with self.assertRaises(m.Refuse):r.recorded_manifest()
    def test_production_state_guard_rejects_group_writable_fixture_ancestor(self):
        r=self.release();path=pathlib.Path(r.state_temp.name);path.chmod(0o770)
        try:
            with self.assertRaises(m.Refuse):m.ExistingRelease.trusted_state_directory(r,create=False)
            self.assertFalse(r.state_path().parent.exists())
        finally:path.chmod(0o700)
    def test_state_commit_failure_rolls_back_state_and_source(self):
        r=self.release();original=r.persist_state
        def fail_after_replace():
            original();raise m.Refuse('simulated_state_commit_error')
        r.persist_state=fail_after_replace
        with self.assertRaises(m.Refuse):self.apply(r)
        self.assert_original(r);self.assertFalse(r.state_path().exists())
    def test_fpm_drain_identifies_only_owned_script_and_refuses_unknown(self):
        r=self.release()
        rows={'listen queue':0,'processes':[{'pid':1,'state':'Running','script':str(self.live/'public/index.php'),'request uri':'/work'},{'pid':2,'state':'Running','script':'/srv/other/public/index.php','request uri':'/work'},{'pid':3,'state':'Running','script':'-','request uri':'/existing-status?full&json'}]}
        self.assertEqual(r.active_fpm_requests(rows),[1])
        rows['listen queue']=1;self.assertEqual(r.active_fpm_requests(rows),['pending_fpm_requests',1]);rows['listen queue']=0
        rows['processes'].append({'pid':4,'state':'Running','script':'-','request uri':'/unknown'})
        with self.assertRaises(m.Refuse):r.active_fpm_requests(rows)
        with mock.patch('shutil.which',return_value=None):
            with self.assertRaises(m.Refuse):m.ExistingRelease.fpm_status(r)
    def test_database_url_socket_options_and_redis_are_refused(self):
        r=self.release();r.cfg={'database':{'default':'mysql','connections':{'mysql':{'driver':'mysql','host':'localhost','database':'synthetic','username':'synthetic'}}},'queue':{'connections':{'database':{'driver':'database','table':'jobs'}}}};r.queue_specs={'database':['default']}
        r.validate_queue_connections()
        for field,value in [('url','mysql://synthetic'),('unix_socket','/synthetic.sock'),('prefix','p_'),('options',{'1':2}),('read',{'host':'other'})]:
            db=r.cfg['database']['connections']['mysql'];db[field]=value
            with self.assertRaises(m.Refuse):r.validate_queue_connections()
            del db[field]
        r.cfg['queue']['connections']['database']['driver']='redis'
        with self.assertRaises(m.Refuse):r.validate_queue_connections()
    def test_two_successive_php_releases_have_different_file_mtimes(self):
        first=self.release();old=int((self.live/'app/Marker.php').stat().st_mtime);self.apply(first);middle=int((self.live/'app/Marker.php').stat().st_mtime);self.assertNotEqual(old,middle)
        self.profile['live_manifest']=copy.deepcopy(self.profile['candidate_manifest']);self.new['app/Marker.php']=b'<?php // next release\n'
        with tarfile.open(self.archive,'w:gz')as archive:
            for name,data in self.new.items():
                data=data.replace(b'\r\n',b'\n');item=tarfile.TarInfo(name);item.size=len(data);item.mtime=0;archive.addfile(item,io.BytesIO(data))
        self.profile['source_archive_sha256']=m.digest(self.archive);self.profile['candidate_manifest']['candidate_commit']='c'*40;self.profile['candidate_manifest']['files']['app/Marker.php']=h(self.new['app/Marker.php'])
        second=self.release();self.apply(second);self.assertNotEqual(middle,int((self.live/'app/Marker.php').stat().st_mtime));self.assertEqual((self.live/'app/Marker.php').read_bytes(),self.new['app/Marker.php'])
    def test_fpm_opcache_off_unbounded_or_ambiguous_is_refused(self):
        info='opcache.enable => On => On\nopcache.validate_timestamps => On => On\nopcache.revalidate_freq => 2 => 2\n'
        self.assertEqual(m.ExistingRelease.validate_opcache_values(info,{}),4)
        for overrides in [{'opcache.validate_timestamps':'Off'},{'opcache.revalidate_freq':'60'},{'opcache.revalidate_freq':'$unknown'}]:
            with self.assertRaises(m.Refuse):m.ExistingRelease.validate_opcache_values(info,overrides)
        with self.assertRaises(m.Refuse):m.ExistingRelease.validate_opcache_values(info+info,{})
    def test_async_nginx_reload_requires_two_stable_baseline_probes(self):
        r=self.release();baseline=r.p['public_baselines'];temporary={key:{'80':503,'443':503}for key in baseline}
        with mock.patch.object(r,'public_codes',side_effect=[temporary,baseline,baseline]),mock.patch('time.sleep'):
            r.await_public_baseline('fixture_observed')
        self.assertEqual(r.report['fixture_observed'],[temporary,baseline,baseline])
        with mock.patch.object(r,'public_codes',return_value=temporary),mock.patch('time.sleep'),mock.patch('time.monotonic',side_effect=[0,1,20]):
            with self.assertRaises(m.Refuse):r.await_public_baseline('fixture_failed')
        self.assertEqual(r.report['fixture_failed'],[temporary])
    def test_exact_standalone_supervisor_selector_only_for_single_process(self):
        r=self.release();line=b'fixture RUNNING pid 1234, uptime 0:10:00\n'
        with mock.patch.object(r,'run',return_value=line):
            result=m.ExistingRelease.statuses(r);self.assertEqual(result,{'fixture':{'state':'RUNNING','pid':1234}})
        for invalid in [b'fixture-other RUNNING pid 1234, uptime 0:10:00\n',line+line]:
            with mock.patch.object(r,'run',return_value=invalid):
                with self.assertRaises(m.Refuse):m.ExistingRelease.statuses(r)
        r.p['worker_groups']['fixture']=2
        with mock.patch.object(r,'run',return_value=line):
            with self.assertRaises(m.Refuse):m.ExistingRelease.statuses(r)
    def test_public_alias_symlink_is_not_replaced(self):
        alias=self.base/'public-app';alias.symlink_to(self.live);self.profile['application_root']=str(alias);inode=alias.lstat().st_ino;r=self.release();self.apply(r);self.assertEqual(alias.lstat().st_ino,inode);self.assertEqual(alias.resolve(),self.live)
    def test_config_failure_restores_old_cache_and_source(self):
        r=self.release(failure='config')
        with self.assertRaises(m.Refuse):self.apply(r)
        self.assert_original(r);self.assertEqual((self.live/'bootstrap/cache/config.php').read_bytes(),b'synthetic-old-cache')
    def test_no_configuration_source_delta_preserves_existing_cache_exactly(self):
        r=self.release();r.preflight();cache=r.root/'bootstrap/cache/config.php';before=(cache.read_bytes(),cache.stat().st_mode,cache.stat().st_uid,cache.stat().st_gid);events=list(r.events)
        r.build_config()
        after=cache.stat()
        self.assertEqual(cache.read_bytes(),before[0]);self.assertEqual(after.st_mode,before[1]);self.assertEqual((after.st_uid,after.st_gid),before[2:]);self.assertEqual(r.events,events)
        self.assertEqual(r.report['configuration_strategy'],'preserved_exact_existing_config')
    def test_backoff_is_stopped_explicitly_before_rollback(self):
        r=self.release(failure='start')
        with self.assertRaises(m.Refuse):self.apply(r)
        self.assert_original(r);self.assertTrue(any(x[:2]==('supervisorctl','stop') for x in r.events))
    def test_public_failure_requiesces_new_worker_before_rollback(self):
        r=self.release(failure='public')
        with self.assertRaises(m.Refuse):self.apply(r)
        self.assert_original(r)
    def test_busy_queue_resumes_same_workers_without_source_change(self):
        r=self.release(reserved=1)
        with self.assertRaises(m.Refuse):self.apply(r)
        self.assert_original(r);self.assertTrue(any('CONT' in x for x in r.events))
    def test_twelve_process_seven_group_topology_is_preserved(self):
        self.profile['worker_groups']={f'group-{i}':n for i,n in enumerate([2,2,2,3,1,1,1])};r=self.release();self.apply(r);self.assertEqual(len(r.statuses()),12);self.assertEqual(len(self.profile['worker_groups']),7)
    def test_dependency_change_fails_before_any_worker_signal(self):
        with tarfile.open(self.archive,'w:gz') as t:
            for name,data in {**self.new,'composer.lock':b'{"packages":["different"]}'}.items():
                info=tarfile.TarInfo(name);info.size=len(data);t.addfile(info,io.BytesIO(data))
        self.profile['source_archive_sha256']=m.digest(self.archive);r=self.release()
        with self.assertRaises(m.Refuse):self.apply(r)
        self.assertEqual(r.events,[]);self.assertEqual((self.live/'app/Marker.php').read_bytes(),self.old['app/Marker.php'])
    def test_unknown_runtime_file_requires_explicit_preservation(self):
        (self.live/'public').mkdir();(self.live/'public/customer.txt').write_text('synthetic');r=self.release()
        with self.assertRaises(m.Refuse):r.preflight()
        self.assertEqual(r.events,[])
    def test_source_digest_drift_refuses_before_mutation(self):
        (self.live/'app/Marker.php').write_text('unexpected');r=self.release()
        with self.assertRaises(m.Refuse):r.preflight()
        self.assertEqual(r.events,[])
    def test_absolute_paths_reject_carriage_returns(self):
        for value in ['/srv/app\rfile','/srv/app\nfile','/srv/app\0file']:
            with self.subTest(value=repr(value)),self.assertRaises(m.Refuse):m.path_value(value)
    def test_provisioning_flags_and_wildcards_are_rejected(self):
        for field,value in [('run_migrations',True),('update_env',True),('manage_supervisor',True),('server_names',['*.example.invalid'])]:
            p=copy.deepcopy(self.profile);p[field]=value
            with self.assertRaises(m.Refuse):m.validate_profile(p)
    def test_production_validator_rejects_private_root_fixture(self):
        with self.assertRaises(m.Refuse):m.validate_profile(self.profile)
    def test_special_profile_schema_requires_exact_two_hashed_nginx_files_and_complete_cron_contract(self):
        p=self.special_profile();checked=m.validate_profile({**p,'application_root':'/srv/repeat-deploy-private-fixture/application'})
        self.assertEqual(len(checked['nginx_configs']),2)
        for mutate in [
            lambda x:x.update(nginx_configs=[x['nginx_configs'][0]]),
            lambda x:x.update(nginx_config='/etc/nginx/also.conf'),
            lambda x:x['nginx_config_hashes'].pop(x['nginx_configs'][1]),
            lambda x:x.update(cron_file_sha256='not-a-sha256'),
            lambda x:x.pop('cron_file_scheduler_user'),
            lambda x:x.update(cron_file_mode='0666'),
            lambda x:x.update(cron_user='root'),
        ]:
            changed=copy.deepcopy(p);mutate(changed);changed['application_root']='/srv/repeat-deploy-private-fixture/application'
            with self.assertRaises(m.Refuse):m.validate_profile(changed)
    def test_special_ports_are_independent_opt_ins(self):
        p=self.special_profile();p['application_root']='/srv/repeat-deploy-private-fixture/application'
        only_nginx=copy.deepcopy(p)
        for field in ['cron_file','cron_file_sha256','cron_file_owner','cron_file_group','cron_file_mode','cron_file_scheduler_user']:only_nginx.pop(field)
        self.assertIn('nginx_configs',m.validate_profile(only_nginx))
        only_cron=copy.deepcopy(p);only_cron['nginx_config']='/etc/nginx/sites-available/fixture.conf';only_cron.pop('nginx_configs');only_cron.pop('nginx_config_hashes')
        self.assertIn('cron_file',m.validate_profile(only_cron))
    def test_two_file_nginx_gate_and_restore_are_one_reload_each(self):
        r=self.prepare_special_ports(self.release_for_profile(self.special_profile()))
        r.nginx_multi(r.nginx_gates)
        self.assertIn(b'return 503',self.special_http.read_bytes());self.assertIn(b'return 503',self.special_https.read_bytes())
        self.assertEqual(sum(event[:2]==('systemctl','reload') for event in r.events),1)
        r.restore_nginx_public('fixture_restore')
        self.assertEqual(self.special_http.read_bytes(),self.http_config);self.assertEqual(self.special_https.read_bytes(),self.https_config)
        self.assertEqual(sum(event[:2]==('systemctl','reload') for event in r.events),2)
    def release_for_profile(self,profile):
        r=SandboxRelease(profile,self.archive,self.base);self.addCleanup(r.state_temp.cleanup);return r
    def test_nginx_two_file_refuses_foreign_hostname_and_hash_drift_before_write(self):
        r=self.release_for_profile(self.special_profile());r.system_path=lambda value:{'/etc/nginx/sites-available/fixture-http.conf':self.special_http,'/etc/nginx/sites-available/fixture-https.conf':self.special_https,'/etc/cron.d/fixture':self.cron_file}[value];r.nginx_path_in_scope=lambda target:True
        self.special_https.write_bytes(self.https_config.replace(b'fixture.example.invalid',b'foreign.example.invalid'))
        with self.assertRaisesRegex(m.Refuse,'nginx_config_hash_mismatch'):r.nginx_snapshot()
        self.special_https.write_bytes(self.https_config);r.prepare_nginx()
        self.special_https.write_bytes(self.https_config+b'# external drift\n')
        with self.assertRaisesRegex(m.Refuse,'nginx_config_changed_during_stage'):r.nginx_multi(r.nginx_gates)
        self.assertEqual(self.special_http.read_bytes(),self.http_config)
    def test_nginx_two_file_requires_one_reviewed_fpm_binding(self):
        p=self.special_profile();changed=self.https_config.replace(b'/run/php/php8.5-fpm.sock',b'/run/php/php8.3-fpm.sock');self.special_https.write_bytes(changed);p['nginx_config_hashes']['/etc/nginx/sites-available/fixture-https.conf']=h(changed)
        r=self.release_for_profile(p);r.system_path=lambda value:{'/etc/nginx/sites-available/fixture-http.conf':self.special_http,'/etc/nginx/sites-available/fixture-https.conf':self.special_https,'/etc/cron.d/fixture':self.cron_file}[value];r.nginx_path_in_scope=lambda target:True
        with self.assertRaisesRegex(m.Refuse,'owned_vhost_fpm_binding_mismatch'):r.prepare_nginx()
    def test_partial_dual_file_nginx_write_restores_first_file_without_reload(self):
        r=self.prepare_special_ports(self.release_for_profile(self.special_profile()));original=r.atomic;calls=0
        def fail_second(path,data,metadata):
            nonlocal calls
            calls+=1
            if calls==2:raise OSError('synthetic second-file failure')
            return original(path,data,metadata)
        r.atomic=fail_second
        with self.assertRaisesRegex(OSError,'second-file failure'):r.nginx_multi(r.nginx_gates)
        self.assertEqual(self.special_http.read_bytes(),self.http_config);self.assertEqual(self.special_https.read_bytes(),self.https_config)
        self.assertFalse(any(event[:2]==('systemctl','reload') for event in r.events))
    def test_nginx_restore_refuses_external_file_drift(self):
        r=self.prepare_special_ports(self.release_for_profile(self.special_profile()));r.nginx_multi(r.nginx_gates)
        self.special_https.write_bytes(b'foreign content\n')
        with self.assertRaisesRegex(m.Refuse,'nginx_config_changed_during_stage'):r.restore_nginx_public('fixture_restore')
        self.assertIn(b'return 503',self.special_http.read_bytes());self.assertEqual(self.special_https.read_bytes(),b'foreign content\n')
    def test_dedicated_cron_exact_user_cas_pause_and_restore(self):
        r=self.prepare_special_ports(self.release_for_profile(self.special_profile()));paused=r.cron_paused_content
        r.cron(paused);self.assertEqual(self.cron_file.read_bytes(),paused);self.assertEqual(r.cron_file_current_sha,h(paused))
        r.cron(r.cron_before);self.assertEqual(self.cron_file.read_bytes(),self.cron_original)
        self.assertFalse(any(event and event[0]=='crontab' for event in r.events))
    def test_post_atomic_dedicated_cron_verification_failure_is_rolled_back(self):
        r=self.release_for_profile(self.special_profile())
        mapping={'/etc/nginx/sites-available/fixture-http.conf':self.special_http,'/etc/nginx/sites-available/fixture-https.conf':self.special_https,'/etc/cron.d/fixture':self.cron_file}
        r.system_path=lambda value:mapping[value];r.nginx_path_in_scope=lambda target:True
        preflight=r.preflight
        def prepare_special_profile():
            report=preflight();r.prepare_nginx();r.prepare_cron_file();return report
        r.preflight=prepare_special_profile
        original_digest=m.digest;injected=False
        def fail_paused_digest(path):
            nonlocal injected
            if pathlib.Path(path)==self.cron_file and self.cron_file.read_bytes()==r.cron_paused_content and not injected:
                injected=True
                return '0'*64
            return original_digest(path)
        with mock.patch.object(m,'digest',side_effect=fail_paused_digest):
            with self.assertRaisesRegex(m.Refuse,'dedicated_cron_file_write_verification_failed'):
                self.apply(r)
        self.assertTrue(injected);self.assertFalse(r.cron_paused)
        self.assertEqual(self.cron_file.read_bytes(),self.cron_original)
        self.assertEqual(self.cron_file.stat().st_mode&0o777,0o644)
        self.assertEqual(self.special_http.read_bytes(),self.http_config);self.assertEqual(self.special_https.read_bytes(),self.https_config)
    def test_dedicated_cron_refuses_wrong_user_column(self):
        p=self.special_profile();self.cron_original=self.cron_original.replace(b'www-data',b'root')
        p['cron_file_sha256']=h(self.cron_original);p['cron_file_scheduler_user']='www-data';self.cron_file.write_bytes(self.cron_original)
        r=self.release_for_profile(p);r.system_path=lambda value:self.cron_file
        with self.assertRaisesRegex(m.Refuse,'exact_single_dedicated_scheduler_row_required'):r.prepare_cron_file()
    def test_dedicated_cron_profile_sha_must_match_live_file(self):
        p=self.special_profile();p['cron_file_sha256']='0'*64;r=self.release_for_profile(p);r.system_path=lambda value:self.cron_file
        with self.assertRaisesRegex(m.Refuse,'dedicated_cron_file_hash_mismatch'):r.prepare_cron_file()
    def test_dedicated_cron_compare_and_swap_refuses_drift_before_pause_or_restore(self):
        r=self.prepare_special_ports(self.release_for_profile(self.special_profile()));self.cron_file.write_bytes(self.cron_original+b'# external\n')
        with self.assertRaisesRegex(m.Refuse,'dedicated_cron_file_compare_and_swap_refused'):r.cron(r.cron_paused_content)
        self.assertNotIn(b'REVIEWED_REPEAT_DEPLOY_PAUSE',self.cron_file.read_bytes())
        self.cron_file.write_bytes(self.cron_original);r.cron(r.cron_paused_content);self.cron_file.write_bytes(b'# outside writer\n')
        with self.assertRaisesRegex(m.Refuse,'dedicated_cron_file_compare_and_swap_refused'):r.cron(r.cron_before)
        self.assertEqual(self.cron_file.read_bytes(),b'# outside writer\n')
    def test_typed_config_is_strict_except_explicit_same_inode_path(self):
        r=self.release();self.assertFalse(r.config_equal({'n':1},{'n':'1'}));self.assertFalse(r.config_equal([1,2],[2,1]));self.assertFalse(r.config_equal({'x':False},{'x':0}))

if __name__=='__main__':unittest.main()
