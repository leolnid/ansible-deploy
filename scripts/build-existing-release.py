#!/usr/bin/env python3
"""Build immutable code from Git blobs; materialize verified LFS and pinned common."""
import argparse, gzip, hashlib, io, json, pathlib, re, subprocess, tarfile
COMMON='packages/leolnid/common'

def git(repo, *args):
    return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.DEVNULL)

def safe_path(name):
    parts=pathlib.PurePosixPath(name).parts
    if not parts or name.startswith('/') or '..' in parts or chr(92) in name:
        raise ValueError('unsafe_git_path')
    if '.git' in parts or any(x in ['.env','auth.json','ansible.key'] for x in parts):
        raise ValueError('secret_named_git_entry')
    return parts

def lfs_payload(repo,name,data):
    pointer=re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([0-9]+)\n?',data.replace(b'\r\n',b'\n'))
    if pointer is None:return data,None
    oid=pointer[1].decode();size=int(pointer[2]);common=pathlib.Path(git(repo,'rev-parse','--git-common-dir').decode().strip())
    if not common.is_absolute():common=pathlib.Path(repo)/common
    obj=common/'lfs/objects'/oid[:2]/oid[2:4]/oid
    candidates=[obj,pathlib.Path(repo)/name]
    for path in candidates:
        if not path.is_file() or path.stat().st_size!=size:continue
        raw=path.read_bytes()
        if hashlib.sha256(raw).hexdigest()==oid:
            return raw,{'oid_sha256':oid,'size':size}
    raise ValueError('verified_lfs_payload_required')

def build(repo, revision, destination, common_checkout=None):
    repo=pathlib.Path(repo);destination=pathlib.Path(destination)
    commit=git(repo,'rev-parse',revision+'^{commit}').decode().strip()
    ancestors=git(repo,'rev-list','--max-count=10000',commit).decode().splitlines()[1:]
    files={};modes={};blobs={};links={};lfs={};used_common=False
    def walk(checkout,ref,prefix='',materialized=False):
        nonlocal used_common
        for row in git(checkout,'ls-tree','-rz','--full-tree',ref).split(b'\0'):
            if not row:continue
            meta,raw_name=row.split(b'\t',1);mode,kind,oid=meta.decode().split();name=raw_name.decode('utf-8');parts=safe_path(name);target=prefix+name
            if kind=='commit' and mode=='160000':
                if materialized or target!=COMMON or common_checkout is None:
                    raise ValueError('explicit_pinned_common_checkout_required')
                trusted=pathlib.Path(common_checkout).resolve(strict=True)
                git(trusted,'cat-file','-e',oid+'^{commit}')
                links[target]=oid;used_common=True;walk(trusted,oid,target+'/',True);continue
            if kind!='blob' or mode not in ['100644','100755']:raise ValueError('unsupported_git_entry')
            if materialized:
                if not(name.startswith(('src/','config/','routes/','resources/'))or name=='composer.json'):continue
            elif parts[0]in['storage','vendor','.deploy']or name.startswith('bootstrap/cache/')or parts[:3]==('packages','leolnid','common-deploy'):continue
            data,metadata=lfs_payload(checkout,name,git(checkout,'cat-file','blob',oid))
            if target in files:raise ValueError('duplicate_materialized_source_path')
            files[target]=hashlib.sha256(data).hexdigest();modes[target]=0o755 if mode=='100755'else 0o644;blobs[target]=data
            if metadata:lfs[target]=metadata
    walk(repo,commit)
    if common_checkout is not None and not used_common:raise ValueError('unused_common_checkout_not_allowed')
    if any(x not in files for x in ['artisan','bootstrap/app.php','composer.json','composer.lock']):raise ValueError('existing_laravel_source_required')
    if destination.exists() and any(destination.iterdir()):raise ValueError('new_empty_artifact_directory_required')
    destination.mkdir(parents=True,exist_ok=True)
    archive=destination/'source.tar.gz'
    with archive.open('wb')as raw:
        with gzip.GzipFile(fileobj=raw,mode='wb',filename='',mtime=0)as compressed:
            with tarfile.open(fileobj=compressed,mode='w')as target:
                for name in sorted(files):
                    item=tarfile.TarInfo(name);item.mode=modes[name];item.size=len(blobs[name]);item.mtime=0;item.uid=item.gid=0;target.addfile(item,io.BytesIO(blobs[name]))
    manifest={'candidate_commit':commit,'files':files,'normalization_by_path':{},'ancestor_commits':ancestors,'gitlinks_materialized':links,'lfs_payloads':lfs}
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    receipt={'candidate_commit':commit,'source_archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'files':len(files),'ancestor_commits':len(ancestors),'materialized_gitlinks':len(links),'verified_lfs_payloads':len(lfs)}
    (destination/'artifact.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=pathlib.Path,required=True);parser.add_argument('--commit',required=True);parser.add_argument('--output',type=pathlib.Path,required=True);parser.add_argument('--common-checkout',type=pathlib.Path);args=parser.parse_args()
    print(json.dumps(build(args.repo,args.commit,args.output,args.common_checkout)))
