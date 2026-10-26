"""Native typed configuration helpers shared by the existing-app deploy path."""

import hashlib,json,re

class ConfigurationRefuse(RuntimeError): pass

Refuse=ConfigurationRefuse

def cache_identity(path):
 info=path.stat();return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_size,info.st_mtime_ns)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def need(ok,code):
 if not ok:raise Refuse(code)

def native_config_proof(controller,old_path,new_path,allowed):
 code=r'''$old=require $argv[1];$new=require $argv[2];$allowed=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$missing=new stdClass;
function tagged($v,$missing){if($v===$missing)return ['type'=>'missing'];$type=get_debug_type($v);if(is_array($v)){$rows=[];foreach($v as$k=>$x)$rows[]=[['type'=>get_debug_type($k),'value'=>$k],tagged($x,$missing)];return ['type'=>'array','list'=>array_is_list($v),'entries'=>$rows];}if(is_object($v)||is_resource($v))throw new RuntimeException('Unsupported cached configuration type');return ['type'=>$type,'value'=>$v];}
function valueHash($v,$missing){return hash('sha256',json_encode(tagged($v,$missing),JSON_THROW_ON_ERROR|JSON_PRESERVE_ZERO_FRACTION));}
function same($a,$b,$path,$allowed,$missing){if(isset($allowed[$path]))return valueHash($a,$missing)===$allowed[$path]['old']&&valueHash($b,$missing)===$allowed[$path]['new'];if($a===$missing||$b===$missing)return $a===$b;if(get_debug_type($a)!==get_debug_type($b))return false;if(is_array($a)){if(array_is_list($a)!==array_is_list($b))return false;if(array_is_list($a)&&array_keys($a)!==array_keys($b))return false;foreach(array_unique(array_merge(array_keys($a),array_keys($b)))as$k){$p=$path===''?(string)$k:$path.'.'.$k;if(!same(array_key_exists($k,$a)?$a[$k]:$missing,array_key_exists($k,$b)?$b[$k]:$missing,$p,$allowed,$missing))return false;}return true;}return $a===$b;}
echo json_encode(['native_types_equal'=>same($old,$new,'',$allowed,$missing)],JSON_THROW_ON_ERROR);'''
 return json.loads(controller.run(['unshare','--net',controller.p['php_cli'],'-r',code,str(old_path),str(new_path)],input=json.dumps(allowed).encode()))['native_types_equal']

def merge_native_config_nodes(controller,old_path,fresh_path,allowed):
 need(bool(allowed),'reviewed_config_nodes_required')
 code=r"""$old=require $argv[1];$fresh=require $argv[2];$allowed=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$missing=new stdClass;
function tagged($v,$missing){if($v===$missing)return ['type'=>'missing'];$type=get_debug_type($v);if(is_array($v)){$rows=[];foreach($v as$k=>$x)$rows[]=[['type'=>get_debug_type($k),'value'=>$k],tagged($x,$missing)];return ['type'=>'array','list'=>array_is_list($v),'entries'=>$rows];}if(is_object($v)||is_resource($v))throw new RuntimeException('Unsupported cached configuration type');return ['type'=>$type,'value'=>$v];}
function valueHash($v,$missing){return hash('sha256',json_encode(tagged($v,$missing),JSON_THROW_ON_ERROR|JSON_PRESERVE_ZERO_FRACTION));}
function at($c,$path,$missing){foreach(explode('.',$path)as$k){if(!is_array($c)||!array_key_exists($k,$c))return $missing;$c=$c[$k];}return $c;}
$merged=$old;foreach($allowed as$path=>$hashes){if(!preg_match('/^[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)+$/D',$path))exit(71);$before=at($old,$path,$missing);$after=at($fresh,$path,$missing);if($after===$missing||valueHash($before,$missing)!==$hashes['old']||valueHash($after,$missing)!==$hashes['new'])exit(72);$keys=explode('.',$path);$leaf=array_pop($keys);$target=&$merged;foreach($keys as$k){if(!array_key_exists($k,$target))$target[$k]=[];if(!is_array($target[$k]))exit(73);$target=&$target[$k];}$target[$leaf]=$after;unset($target);}
$raw="<?php\nreturn ".var_export($merged,true).";\n";if(file_put_contents($argv[2],$raw,LOCK_EX)!==strlen($raw))exit(74);echo json_encode(['approved_native_nodes_applied'=>count($allowed),'unrelated_old_configuration_preserved'=>true],JSON_THROW_ON_ERROR);"""
 return json.loads(controller.run(['unshare','--net',controller.p['php_cli'],'-r',code,str(old_path),str(fresh_path)],input=json.dumps(allowed).encode()))
