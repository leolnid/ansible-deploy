import hashlib,importlib.util,json,os,pathlib,subprocess,tarfile,tempfile,unittest
MODULE=pathlib.Path(__file__).resolve().parents[2]/'scripts/build-existing-release.py'
spec=importlib.util.spec_from_file_location('builder',MODULE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
FIXTURE_ROOT=pathlib.Path(os.environ.get('REPEAT_DEPLOY_TEST_ROOT',tempfile.gettempdir())).resolve()
class BuilderTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='repeat-builder-',dir=FIXTURE_ROOT);self.base=pathlib.Path(self.tmp.name).resolve();assert self.base.parent==FIXTURE_ROOT and self.base.name.startswith('repeat-builder-');self.addCleanup(self.safe_cleanup);self.repo=self.base/'app';self.repo.mkdir();self.git(self.repo,'init','-q')
  for name,content in {'artisan':b'<?php','bootstrap/app.php':b'<?php','composer.json':b'{}','composer.lock':b'{}','.deploy/runtime-profile.json':b'{"fixture":true}','.deploy/known_hosts':b'fixture public host key','packages/leolnid/common-deploy/deploy.yml':b'fixture provisioning metadata','public/index.php':b'<?php // public entry point','public/filemanager/uploads/416255.png':b'customer-owned-upload'}.items():p=self.repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(content)
 def safe_cleanup(self):
  target=pathlib.Path(self.tmp.name).resolve();assert target==self.base and target.parent==FIXTURE_ROOT and target.name.startswith('repeat-builder-');self.tmp.cleanup()
 def git(self,repo,*args):return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.PIPE).decode().strip()
 def commit(self,repo):self.git(repo,'add','-A');self.git(repo,'-c','user.name=Fixture','-c','user.email=fixture@local.invalid','commit','-qm','synthetic fixture');return self.git(repo,'rev-parse','HEAD')
 def lfs(self):
  self.data=b'\x00\xffsynthetic binary asset\x10';self.oid=hashlib.sha256(self.data).hexdigest();p=self.repo/'public/asset.bin';p.parent.mkdir(exist_ok=True);p.write_text('version https://git-lfs.github.com/spec/v1\noid sha256:'+self.oid+'\nsize '+str(len(self.data))+'\n');return self.commit(self.repo)
 def object(self,data):
  p=self.repo/'.git/lfs/objects'/self.oid[:2]/self.oid[2:4]/self.oid;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);return p
 def payload(self,output,name):
  with tarfile.open(output/'source.tar.gz')as t:return t.extractfile(name).read()
 def test_verified_lfs_object_is_binary_not_pointer_and_reproducible(self):
  sha=self.lfs();self.object(self.data);a=self.base/'one';b=self.base/'two';one=m.build(self.repo,sha,a);two=m.build(self.repo,sha,b);self.assertEqual(self.payload(a,'public/asset.bin'),self.data);self.assertEqual(one['source_archive_sha256'],two['source_archive_sha256']);manifest=json.loads((a/'manifest.json').read_text());self.assertEqual(manifest['files']['public/asset.bin'],self.oid);self.assertEqual(manifest['lfs_payloads']['public/asset.bin']['size'],len(self.data))
 def test_missing_or_wrong_lfs_fails_before_artifact_creation(self):
  sha=self.lfs()
  for name,data in [('missing',None),('wrong',b'x'*len(self.data))]:
   if data is not None:self.object(data)
   out=self.base/name
   with self.assertRaises(ValueError):m.build(self.repo,sha,out)
   self.assertFalse(out.exists())
 def test_hydrated_worktree_requires_exact_oid_and_size(self):
  sha=self.lfs();p=self.repo/'public/asset.bin';p.write_bytes(self.data);out=self.base/'hydrated';m.build(self.repo,sha,out);self.assertEqual(self.payload(out,'public/asset.bin'),self.data);p.write_bytes(b'x'*len(self.data))
  with self.assertRaises(ValueError):m.build(self.repo,sha,self.base/'wrong-hydrated')
 def test_gitlink_materializes_pinned_git_commit_not_checkout_head_or_dirty_tree(self):
  common=self.base/'common';common.mkdir();self.git(common,'init','-q');(common/'src').mkdir();(common/'src/Item.php').write_bytes(b'<?php // pinned');(common/'composer.json').write_text('{}');pinned=self.commit(common);(common/'src/Item.php').write_bytes(b'<?php // newer HEAD');self.commit(common);(common/'src/Item.php').write_bytes(b'<?php // dirty never copied');self.git(self.repo,'add','-A');self.git(self.repo,'update-index','--add','--cacheinfo','160000,'+pinned+',packages/leolnid/common');self.git(self.repo,'-c','user.name=Fixture','-c','user.email=fixture@local.invalid','commit','-qm','pin common');sha=self.git(self.repo,'rev-parse','HEAD');out=self.base/'common-output';m.build(self.repo,sha,out,common);self.assertEqual(self.payload(out,'packages/leolnid/common/src/Item.php'),b'<?php // pinned');self.assertEqual(json.loads((out/'manifest.json').read_text())['gitlinks_materialized'],{'packages/leolnid/common':pinned})
  with self.assertRaises(ValueError):m.build(self.repo,sha,self.base/'missing-common')
 def test_unsupported_or_unused_common_and_source_symlink_refused(self):
  sha=self.commit(self.repo)
  with self.assertRaises(ValueError):m.build(self.repo,sha,self.base/'unused',self.repo)
  self.git(self.repo,'update-index','--add','--cacheinfo','120000,'+self.git(self.repo,'hash-object','artisan')+',public/link');self.git(self.repo,'-c','user.name=Fixture','-c','user.email=fixture@local.invalid','commit','-qm','unsupported symlink')
  with self.assertRaises(ValueError):m.build(self.repo,'HEAD',self.base/'symlink')
 def test_customer_managed_public_uploads_never_enter_release_archive(self):
  sha=self.commit(self.repo);out=self.base/'without-customer-uploads';m.build(self.repo,sha,out);manifest=json.loads((out/'manifest.json').read_text())
  self.assertIn('public/index.php',manifest['files']);self.assertNotIn('public/filemanager/uploads/416255.png',manifest['files'])
  with tarfile.open(out/'source.tar.gz')as archive:
   names=archive.getnames();self.assertIn('public/index.php',names);self.assertNotIn('public/filemanager/uploads/416255.png',names)
 def test_ci_enrollment_files_never_enter_the_production_release_archive(self):
  sha=self.commit(self.repo);out=self.base/'without-ci-enrollment';receipt=m.build(self.repo,sha,out);manifest=json.loads((out/'manifest.json').read_text())
  self.assertNotIn('.deploy/runtime-profile.json',manifest['files']);self.assertNotIn('.deploy/known_hosts',manifest['files'])
  self.assertNotIn('packages/leolnid/common-deploy/deploy.yml',manifest['files'])
  with tarfile.open(out/'source.tar.gz')as archive:
   names=archive.getnames();self.assertNotIn('.deploy/runtime-profile.json',names);self.assertNotIn('.deploy/known_hosts',names);self.assertNotIn('packages/leolnid/common-deploy/deploy.yml',names)
if __name__=='__main__':unittest.main()
