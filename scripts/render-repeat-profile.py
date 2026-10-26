#!/usr/bin/env python3
"""Bind this pipeline's Git artifact to an explicitly reviewed existing-runtime baseline."""
import argparse,json,pathlib,re,ipaddress,os

def render(enrollment,manifest,artifact,environ=None):
 allowed={'schema_version','inventory_host','profile','inventory_user','inventory_user_env','ssh_key_env'}
 if not isinstance(enrollment,dict)or set(enrollment)-allowed or not {'schema_version','inventory_host','profile'}<=set(enrollment)or enrollment['schema_version']!=1:raise ValueError('explicit_runtime_enrollment_required')
 if ('inventory_user'in enrollment)==('inventory_user_env'in enrollment):raise ValueError('exactly_one_reviewed_inventory_user_source_required')
 ipaddress.ip_address(enrollment['inventory_host'])
 if 'inventory_user' in enrollment:inventory_user=enrollment['inventory_user']
 else:
  variable=enrollment['inventory_user_env'];environment=os.environ if environ is None else environ
  if variable not in {'SSH_USER','ANSIBLE_USER'}:raise ValueError('inventory_user_environment_variable_not_allowlisted')
  inventory_user=environment.get(variable,'')
 if not re.fullmatch('[a-z_][a-z0-9_-]{0,31}',inventory_user):raise ValueError('invalid_inventory_user')
 if enrollment.get('ssh_key_env','ANSIBLE_SSH_PRIVATE_KEY')not in {'ANSIBLE_SSH_PRIVATE_KEY','SSH_PRIVATE_KEY'}:raise ValueError('ssh_key_environment_variable_not_allowlisted')
 profile=json.loads(json.dumps(enrollment['profile']))
 if not isinstance(profile,dict)or profile.get('schema_version')!=1:raise ValueError('explicit_runtime_profile_required')
 if 'candidate_manifest'in profile or'source_archive_sha256'in profile:raise ValueError('candidate_must_come_from_current_pipeline_artifact')
 if not re.fullmatch('[a-f0-9]{40}',manifest.get('candidate_commit',''))or not isinstance(manifest.get('files'),dict)or not manifest['files']:raise ValueError('candidate_manifest_invalid')
 if not re.fullmatch('[a-f0-9]{40}',artifact.get('candidate_commit',''))or not re.fullmatch('[a-f0-9]{64}',artifact.get('source_archive_sha256','')):raise ValueError('candidate_artifact_receipt_invalid')
 if manifest['candidate_commit']!=artifact['candidate_commit']:raise ValueError('artifact_commit_mismatch')
 profile['candidate_manifest']=manifest;profile['source_archive_sha256']=artifact['source_archive_sha256']
 inventory={'all':{'hosts':{'selected-app':{'ansible_host':enrollment['inventory_host'],'ansible_user':inventory_user}}}}
 return {'repeat_deploy_profile':profile},inventory

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--enrollment',required=True,type=pathlib.Path);p.add_argument('--artifact-directory',required=True,type=pathlib.Path);p.add_argument('--output-directory',required=True,type=pathlib.Path);args=p.parse_args();profile,inventory=render(json.loads(args.enrollment.read_text()),json.loads((args.artifact_directory/'manifest.json').read_text()),json.loads((args.artifact_directory/'artifact.json').read_text()));args.output_directory.mkdir(parents=True,exist_ok=True,mode=0o700);profile_file=args.output_directory/'profile.json';inventory_file=args.output_directory/'inventory.json';profile_file.write_text(json.dumps(profile,indent=2)+'\n');inventory_file.write_text(json.dumps(inventory,indent=2)+'\n');os.chmod(profile_file,0o600);os.chmod(inventory_file,0o600);print(json.dumps({'candidate_commit':profile['repeat_deploy_profile']['candidate_manifest']['candidate_commit'],'profile_from_reviewed_baseline':True,'credentials_in_profile':False}))
