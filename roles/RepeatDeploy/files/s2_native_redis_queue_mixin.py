from __future__ import annotations
import hashlib, json, os, pathlib, re, stat, subprocess

ADAPTER_SHA256='ac2332daf66355ba84c286f5ad59cbef23ee1d105d2611ca1f4974f66a383414'

class NativeRedisQueueMixin:
    """Mixin for repeat_deploy.ExistingRelease; all framework identity is frozen in RAM once."""
    NativeQueueRefuse=RuntimeError

    def bind_native_redis_adapter(self, source: str) -> None:
        raw=source.encode('utf-8')
        if hashlib.sha256(raw).hexdigest()!=ADAPTER_SHA256:
            self._redis_refuse('native_adapter_source_drift')
        self._redis_adapter_source=source

    def _redis_refuse(self, reason: str) -> None:
        raise self.NativeQueueRefuse(reason)

    @staticmethod
    def _valid_name(value: object, pattern: str) -> bool:
        return isinstance(value,str) and re.fullmatch(pattern,value) is not None

    def _freeze_framework_connections(self, aliases: set[str]) -> dict:
        redis_cfg=self.cfg.get('database',{}).get('redis',{})
        if not isinstance(redis_cfg,dict) or redis_cfg.get('client','phpredis')!='phpredis':
            self._redis_refuse('redis_client_not_native_phpredis')
        if any(alias in redis_cfg.get('clusters',{}) for alias in aliases):
            self._redis_refuse('redis_cluster_not_supported_by_bounded_adapter')
        for alias in aliases:
            conf=redis_cfg.get(alias)
            if not isinstance(conf,dict): self._redis_refuse('cached_redis_connection_missing')
            if conf.get('url') not in (None,''): self._redis_refuse('unsupported_cached_redis_url')
        php=r'''$root=$argv[1];require $root.'/vendor/autoload.php';$c=require $root.'/bootstrap/cache/config.php';$r=$c['database']['redis']??null;if(!is_array($r)||($r['client']??'phpredis')!=='phpredis')exit(31);$m=new Illuminate\Redis\RedisManager(null,'phpredis',$r);$out=[];$names=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);foreach($names as $name){$x=$m->connection($name)->client();$out[$name]=['host'=>$x->getHost(),'port'=>$x->getPort(),'database'=>$x->getDBNum(),'prefix'=>$x->getOption(Redis::OPT_PREFIX)];}echo json_encode($out,JSON_THROW_ON_ERROR);'''
        argv=[self.p['php_cli'],'-d','display_errors=0','-r',php,str(self.root)]
        if hasattr(self,'uid'): argv=['sudo','-u','#'+str(self.uid),'env',*argv]
        try:
            raw=self.run(argv,input=json.dumps(sorted(aliases),separators=(',',':')).encode(),timeout=20)
            value=json.loads(raw)
        except Exception: self._redis_refuse('framework_connection_identity_probe_failed')
        if not isinstance(value,dict) or set(value)!=aliases:
            self._redis_refuse('framework_connection_identity_invalid')
        self._redis_framework_connections=value
        self._redis_cached_config_hash=hashlib.sha256(self.queue_cache.read_bytes()).hexdigest()
        self._redis_queue_specs_frozen=True
        return value

    def workers(self):
        rows=self.statuses();pids=self.own_queue_pids()
        if any(x['state']!='RUNNING' or x['pid'] not in pids for x in rows.values()) or set(pids)!={x['pid'] for x in rows.values()}:
            self._redis_refuse('worker_scope_or_state_drift')
        specs={};aliases=set()
        for row in rows.values():
            pid=row['pid']
            if pathlib.Path(os.readlink('/proc/'+str(pid)+'/exe')).resolve()!=pathlib.Path(self.p['php_cli']).resolve():
                self._redis_refuse('wrong_worker_php')
            argv=[x.decode() for x in pids[pid] if x]
            if argv.count('queue:work')!=1:self._redis_refuse('worker_command_unrecognized')
            i=argv.index('queue:work');default=self.cfg.get('queue',{}).get('default')
            connection=argv[i+1] if len(argv)>i+1 and not argv[i+1].startswith('-') else default
            if not self._valid_name(connection,r'[A-Za-z0-9_.-]{1,100}'):
                self._redis_refuse('invalid_worker_connection')
            q=self.cfg.get('queue',{}).get('connections',{}).get(connection)
            if not isinstance(q,dict) or q.get('driver')!='redis':self._redis_refuse('queue_connection_not_redis')
            alias=q.get('connection','default')
            if not self._valid_name(alias,r'[A-Za-z0-9_.-]{1,100}'):
                self._redis_refuse('invalid_redis_alias')
            redis_cfg=self.cfg.get('database',{}).get('redis',{})
            if alias not in redis_cfg or not isinstance(redis_cfg[alias],dict):self._redis_refuse('cached_redis_connection_missing')
            if redis_cfg[alias].get('url') not in (None,''):self._redis_refuse('unsupported_cached_redis_url')
            aliases.add(alias)
            selected=q.get('queue','default');j=i+1
            while j<len(argv):
                token=argv[j]
                if token.startswith('--queue='):selected=token.partition('=')[2]
                elif token=='--queue':
                    if j+1>=len(argv):self._redis_refuse('worker_queue_unrecognized')
                    selected=argv[j+1];j+=1
                j+=1
            names=selected.split(',') if isinstance(selected,str) else []
            if not names or any(not self._valid_name(n,r'[A-Za-z0-9_.:-]{1,100}') for n in names):
                self._redis_refuse('invalid_owned_queue_name')
            specs.setdefault(connection,set()).update(names)
        if not specs:self._redis_refuse('empty_worker_queue_scope')
        frozen={k:sorted(v) for k,v in specs.items()}
        self._redis_worker_specs=frozen
        self._freeze_framework_connections(aliases)
        return rows,frozen

    def validate_queue_connections(self):
        redis_cfg=self.cfg.get('database',{}).get('redis',{})
        if not isinstance(redis_cfg,dict) or redis_cfg.get('client','phpredis')!='phpredis':
            self._redis_refuse('redis_client_not_native_phpredis')
        for connection in self._redis_worker_specs:
            queue=self.cfg.get('queue',{}).get('connections',{}).get(connection)
            if not isinstance(queue,dict) or queue.get('driver')!='redis':
                self._redis_refuse('queue_connection_not_redis')
            alias=queue.get('connection','default')
            if not self._valid_name(alias,r'[A-Za-z0-9_.-]{1,100}'):
                self._redis_refuse('invalid_redis_alias')
            if alias not in redis_cfg or not isinstance(redis_cfg[alias],dict):
                self._redis_refuse('cached_redis_connection_missing')
            if alias in redis_cfg.get('clusters',{}):
                self._redis_refuse('redis_cluster_not_supported_by_bounded_adapter')
            if redis_cfg[alias].get('url') not in (None,''):
                self._redis_refuse('unsupported_cached_redis_url')
            for name in self._redis_worker_specs[connection]:
                if not self._valid_name(name,r'[A-Za-z0-9_.:-]{1,100}'):
                    self._redis_refuse('invalid_owned_queue_name')

    def counts(self):
        if not getattr(self,'_redis_queue_specs_frozen',False):self._redis_refuse('framework_connection_identity_missing')
        if hashlib.sha256(self.queue_cache.read_bytes()).hexdigest()!=self._redis_cached_config_hash:
            self._redis_refuse('cached_config_drift')
        source=self._redis_adapter_source
        body=source.replace('<?php','',1)
        body=re.sub(r'\A\s*declare\(strict_types=1\);','',body,count=1)
        payload={'worker_specs':self._redis_worker_specs,'framework_connections':self._redis_framework_connections}
        code=body+"\ntry{$r=s2_native_redis_counts_entry($argv[1]);echo json_encode($r,JSON_THROW_ON_ERROR);}catch(Throwable $e){fwrite(STDERR,json_encode(['reason'=>s2_safe_refusal_reason($e)]));exit(2);}"
        argv=[self.p['php_cli'],'-d','display_errors=0','-r',code,str(self.root)]
        if hasattr(self,'uid'):argv=['sudo','-u','#'+str(self.uid),'env',*argv]
        try:
            raw=self.run(argv,input=json.dumps(payload,separators=(',',':')).encode(),timeout=30)
            result=json.loads(raw)
        except Exception:self._redis_refuse('native_redis_count_probe_failed')
        if not isinstance(result,dict) or result.get('framework_connection_identity_match') is not True:
            self._redis_refuse('framework_connection_identity_mismatch')
        if any(type(result.get(key)) is not int or result[key]<0 for key in ('jobs','reserved')):
            self._redis_refuse('invalid_redis_count')
        if result.get('payloads_read') is not False or result.get('data_write_commands')!=0:
            self._redis_refuse('native_redis_readonly_contract_failed')
        self._redis_last_count_proof={'framework_connection_identity_match':True,
                                      'payloads_read':False,'data_write_commands':0}
        return {'jobs':result['jobs'],'reserved':result['reserved']}
