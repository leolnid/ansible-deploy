#!/usr/bin/env python3
"""Build a code-only Git artifact and manifest without reading the working tree."""
import argparse, hashlib, io, json, pathlib, re, subprocess, tarfile

def git(repo, *args):
    return subprocess.check_output(['git','-C',str(repo),*args],stderr=subprocess.DEVNULL)

def build(repo, revision, destination):
    commit=git(repo,'rev-parse',revision+'^{commit}').decode().strip()
    ancestors=git(repo,'rev-list','--max-count=10000',commit).decode().splitlines()[1:]
    files={}; modes={}; blobs={}
    for row in git(repo,'ls-tree','-rz','--full-tree',commit).split(b'\0'):
        if not row:continue
        meta, raw_path=row.split(b'\t',1);mode, kind, oid=meta.decode().split();name=raw_path.decode('utf-8')
        parts=pathlib.PurePosixPath(name).parts
        if name.startswith('/') or '..' in parts or '\\' in name:raise ValueError('unsafe_git_path')
        if kind!='blob' or mode not in ['100644','100755']:raise ValueError('unsupported_git_entry')
        if '.git' in parts or any(x in ['.env','auth.json','ansible.key'] for x in parts):raise ValueError('secret_named_git_entry')
        if parts[0] in ['storage','vendor'] or name.startswith('bootstrap/cache/'):continue
        data=git(repo,'cat-file','blob',oid)
        files[name]=hashlib.sha256(data).hexdigest();modes[name]=0o755 if mode=='100755' else 0o644;blobs[name]=data
    if any(x not in files for x in ['artisan','bootstrap/app.php','composer.json','composer.lock']):raise ValueError('existing_laravel_source_required')
    destination.mkdir(parents=True,exist_ok=True)
    archive=destination/'source.tar.gz'
    with tarfile.open(archive,'w:gz') as target:
        for name in sorted(files):
            item=tarfile.TarInfo(name);item.mode=modes[name];item.size=len(blobs[name]);item.mtime=0;item.uid=item.gid=0;target.addfile(item,io.BytesIO(blobs[name]))
    manifest={'candidate_commit':commit,'files':files,'normalization_by_path':{},'ancestor_commits':ancestors}
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    receipt={'candidate_commit':commit,'source_archive_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'files':len(files),'ancestor_commits':len(ancestors)}
    (destination/'artifact.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repo',type=pathlib.Path,required=True);parser.add_argument('--commit',required=True);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
    print(json.dumps(build(args.repo,args.commit,args.output)))
