<?php
declare(strict_types=1);

/**
 * Isolated, read-only queue counts for repeat-deploy adapters.
 * This file intentionally has no Laravel/Composer dependency.
 */

function s2_queue_refuse(string $reason): never
{
    throw new RuntimeException($reason);
}

function s2_safe_refusal_reason(Throwable $error): string
{
    static $known = [
        'cached_queue_config_missing', 'invalid_worker_connection', 'empty_worker_queue_scope',
        'invalid_resolved_connection', 'queue_connection_not_redis', 'invalid_redis_alias',
        'cached_redis_connection_missing', 'redis_cluster_not_supported_by_bounded_adapter',
        'redis_client_not_native_phpredis', 'invalid_configured_default_queue', 'invalid_owned_queue_name',
        'invalid_redis_options', 'invalid_redis_prefix', 'unsupported_cached_redis_transport',
        'unsupported_cached_redis_scheme', 'worker_connection_settings_conflict',
        'native_redis_client_unavailable', 'invalid_redis_tls_context', 'redis_connect_failed',
        'redis_auth_failed', 'redis_database_select_failed', 'redis_prefix_setup_failed',
        'invalid_redis_count', 'native_redis_extension_missing', 'cached_config_not_found',
        'laravel_key_derivation_source_unverified', 'invalid_adapter_input',
        'unsupported_cached_redis_url', 'framework_connection_identity_missing',
        'framework_connection_identity_invalid', 'framework_connection_identity_mismatch',
    ];
    $message = $error->getMessage();
    return in_array($message, $known, true) ? $message : 'native_redis_probe_failed';
}

function s2_laravel_key_derivation_match(string $root): bool
{
    $base = rtrim($root, '/') . '/vendor/laravel/framework/src/Illuminate/';
    $paths = [
        'Queue/RedisQueue.php',
        'Redis/Connectors/PhpRedisConnector.php',
        'Redis/RedisManager.php',
    ];
    $sources = [];
    foreach ($paths as $path) {
        $full = $base . $path;
        if (is_link($full) || !is_file($full)) {
            return false;
        }
        $sources[$path] = file_get_contents($full);
        if (!is_string($sources[$path])) {
            return false;
        }
    }
    $queue = $sources['Queue/RedisQueue.php'];
    $connector = $sources['Redis/Connectors/PhpRedisConnector.php'];
    $manager = $sources['Redis/RedisManager.php'];
    $prefixSnippet = <<<'SNIP'
setOption(Redis::OPT_PREFIX, $config['prefix'])
SNIP;
    $reservedSnippet = <<<'SNIP'
zcard($this->getQueueRedisKey($queue).':reserved')
SNIP;
    $delayedSnippet = <<<'SNIP'
zcard($this->getQueueRedisKey($queue).':delayed')
SNIP;
    $mergeSnippet = <<<'SNIP'
array_merge(Arr::except($options, 'parameters')
SNIP;
    return preg_match('/function\s+getQueue\s*\(\s*\$queue\s*\).*?return\s*\'queues:\'\s*\.\s*\$this->resolveQueue\s*\(/s', $queue) === 1
        && str_contains($connector, $prefixSnippet)
        && preg_match('/\$client->select\(\(int\) \$config\[\'database\'\]\)/', $connector) === 1
        && str_contains($manager, $mergeSnippet)
        && str_contains($queue, $reservedSnippet)
        && str_contains($queue, $delayedSnippet);
}

function s2_native_queue_specs(array $cached, array $workerSpecs, array $frameworkConnections): array
{
    if ($workerSpecs === []) {
        s2_queue_refuse('empty_worker_queue_scope');
    }
    $queue = $cached['queue'] ?? null;
    if (!is_array($queue) || !is_array($queue['connections'] ?? null)) {
        s2_queue_refuse('cached_queue_config_missing');
    }

    $resolved = [];
    foreach ($workerSpecs as $workerConnection => $names) {
        if (!is_string($workerConnection) || !preg_match('/\A[A-Za-z0-9_.-]{1,100}\z/', $workerConnection)) {
            s2_queue_refuse('invalid_worker_connection');
        }
        if (!is_array($names) || $names === []) {
            s2_queue_refuse('empty_worker_queue_scope');
        }
        $queueConnection = $workerConnection;
        if ($queueConnection === '__configured_default__') {
            $queueConnection = $queue['default'] ?? null;
        }
        if (!is_string($queueConnection) || !preg_match('/\A[A-Za-z0-9_.-]{1,100}\z/', $queueConnection)) {
            s2_queue_refuse('invalid_resolved_connection');
        }
        $queueConfig = $queue['connections'][$queueConnection] ?? null;
        if (!is_array($queueConfig) || ($queueConfig['driver'] ?? null) !== 'redis') {
            s2_queue_refuse('queue_connection_not_redis');
        }
        $redisAlias = $queueConfig['connection'] ?? 'default';
        if (!is_string($redisAlias) || !preg_match('/\A[A-Za-z0-9_.-]{1,100}\z/', $redisAlias)) {
            s2_queue_refuse('invalid_redis_alias');
        }
        $redisConfig = $cached['database']['redis']['clusters'][$redisAlias]
            ?? $cached['database']['redis'][$redisAlias]
            ?? null;
        if (!is_array($redisConfig)) {
            s2_queue_refuse('cached_redis_connection_missing');
        }
        if (isset($redisConfig['url']) && $redisConfig['url'] !== null && $redisConfig['url'] !== '') {
            // Laravel's URL parser may override host, credentials, database, and TLS settings.
            // This bounded adapter does not parse URLs; fail closed instead of counting elsewhere.
            s2_queue_refuse('unsupported_cached_redis_url');
        }
        if (isset($cached['database']['redis']['clusters'][$redisAlias])) {
            s2_queue_refuse('redis_cluster_not_supported_by_bounded_adapter');
        }
        $client = $cached['database']['redis']['client'] ?? 'phpredis';
        if ($client !== 'phpredis') {
            s2_queue_refuse('redis_client_not_native_phpredis');
        }

        $defaultQueue = $queueConfig['queue'] ?? 'default';
        if (!is_string($defaultQueue) || !preg_match('/\A[A-Za-z0-9_.:-]{1,100}\z/', $defaultQueue)) {
            s2_queue_refuse('invalid_configured_default_queue');
        }
        $queueNames = [];
        foreach ($names as $name) {
            if ($name === '__configured_default__') {
                $name = $defaultQueue;
            }
            if (!is_string($name) || !preg_match('/\A[A-Za-z0-9_.:-]{1,100}\z/', $name)) {
                s2_queue_refuse('invalid_owned_queue_name');
            }
            $queueNames[$name] = true;
        }

        $globalOptions = $cached['database']['redis']['options'] ?? [];
        $connectionOptions = $redisConfig['options'] ?? [];
        if (!is_array($globalOptions) || !is_array($connectionOptions)) {
            s2_queue_refuse('invalid_redis_options');
        }
        // Mirrors RedisManager::resolve() + PhpRedisConnector::connect():
        // connection, global options, then per-connection options; explicit
        // connection-level `prefix` wins over `options.prefix`.
        $settings = array_merge($redisConfig, $globalOptions, $connectionOptions);
        if (array_key_exists('prefix', $redisConfig)) {
            $settings['prefix'] = $redisConfig['prefix'];
        }
        $prefix = $settings['prefix'] ?? '';
        if (!is_string($prefix)) {
            s2_queue_refuse('invalid_redis_prefix');
        }
        $host = $settings['host'] ?? null;
        $port = $settings['port'] ?? 6379;
        $database = $settings['database'] ?? 0;
        $timeout = $settings['timeout'] ?? 2.5;
        $scheme = $settings['scheme'] ?? null;
        if (!is_string($host) || $host === '' || !(is_int($port) || (is_string($port) && ctype_digit($port)))
            || (int) $port < 1 || (int) $port > 65535
            || !(is_int($database) || (is_string($database) && ctype_digit($database)))
            || !is_numeric($timeout) || ($scheme !== null && !in_array($scheme, ['tcp', 'tls'], true))) {
            s2_queue_refuse('unsupported_cached_redis_transport');
        }
        if (isset($scheme) && !in_array($scheme, ['tcp', 'tls'], true)) {
            s2_queue_refuse('unsupported_cached_redis_scheme');
        }
        if (isset($scheme) && !str_contains($host, '://')) {
            $host = $scheme . '://' . $host;
        }
        $connection = [
                'host' => $host,
                'port' => (int) $port,
                'database' => (int) $database,
                'timeout' => (float) $timeout,
                'prefix' => $prefix,
                'username' => $settings['username'] ?? null,
                'password' => $settings['password'] ?? null,
                'retry_interval' => $settings['retry_interval'] ?? 0,
                'read_timeout' => $settings['read_timeout'] ?? 0,
                'context' => $settings['context'] ?? null,
            ];
        $framework = $frameworkConnections[$redisAlias] ?? null;
        if (!is_array($framework)) {
            s2_queue_refuse('framework_connection_identity_missing');
        }
        $frameworkHost = $framework['host'] ?? null;
        $frameworkPort = $framework['port'] ?? null;
        $frameworkDatabase = $framework['database'] ?? null;
        $frameworkPrefix = $framework['prefix'] ?? null;
        if (!is_string($frameworkHost) || $frameworkHost === ''
            || !(is_int($frameworkPort) || (is_string($frameworkPort) && ctype_digit($frameworkPort)))
            || !(is_int($frameworkDatabase) || (is_string($frameworkDatabase) && ctype_digit($frameworkDatabase)))
            || !is_string($frameworkPrefix)) {
            s2_queue_refuse('framework_connection_identity_invalid');
        }
        $nativeHost = preg_replace('/\A(?:tcp|tls):\/\//', '', $connection['host']);
        $resolvedHost = preg_replace('/\A(?:tcp|tls):\/\//', '', $frameworkHost);
        if (!is_string($nativeHost) || !is_string($resolvedHost)
            || $nativeHost !== $resolvedHost || $connection['port'] !== (int) $frameworkPort
            || $connection['database'] !== (int) $frameworkDatabase || $connection['prefix'] !== $frameworkPrefix) {
            s2_queue_refuse('framework_connection_identity_mismatch');
        }
        $connection['framework_tuple_match'] = true;
        if (isset($resolved[$queueConnection]) && $resolved[$queueConnection]['connection'] !== $connection) {
            s2_queue_refuse('worker_connection_settings_conflict');
        }
        $resolved[$queueConnection] ??= ['redis_alias' => $redisAlias, 'connection' => $connection, 'queues' => []];
        $resolved[$queueConnection]['queues'] = array_values(array_unique(array_merge(
            $resolved[$queueConnection]['queues'],
            array_keys($queueNames)
        )));
    }
    return $resolved;
}

/**
 * $clientFactory is only used by offline fault fixtures. Production passes null.
 * A client is allowed to receive LLEN and ZCARD commands only.
 */
function s2_native_redis_counts(array $resolved, ?callable $clientFactory = null): array
{
    $totals = ['jobs' => 0, 'reserved' => 0, 'ready' => 0, 'delayed' => 0];
    foreach ($resolved as $connectionName => $spec) {
        $connection = $spec['connection'];
        if (($connection['framework_tuple_match'] ?? false) !== true) {
            s2_queue_refuse('framework_connection_identity_missing');
        }
        $client = $clientFactory ? $clientFactory($connectionName, $connection) : new Redis();
        if (!$client instanceof Redis && $clientFactory === null) {
            s2_queue_refuse('native_redis_client_unavailable');
        }
        $connectArgs = [
            $connection['host'],
            $connection['port'],
            $connection['timeout'],
            null,
            $connection['retry_interval'],
            $connection['read_timeout'],
        ];
        if ($connection['context'] !== null) {
            $context = $connection['context'];
            if (!is_array($context)) {
                s2_queue_refuse('invalid_redis_tls_context');
            }
            $connectArgs[] = isset($context['stream']) ? $context : ['stream' => ($context['ssl'] ?? $context)];
        }
        $ok = $client->connect(...$connectArgs);
        if ($ok !== true) {
            s2_queue_refuse('redis_connect_failed');
        }
        if (!empty($connection['password'])) {
            $auth = $connection['username'] !== null
                ? [$connection['username'], $connection['password'] ?? '']
                : $connection['password'];
            if ($client->auth($auth) !== true) {
                s2_queue_refuse('redis_auth_failed');
            }
        }
        if ($client->select($connection['database']) !== true) {
            s2_queue_refuse('redis_database_select_failed');
        }
        if (!defined('Redis::OPT_PREFIX') || $client->setOption(Redis::OPT_PREFIX, $connection['prefix']) !== true) {
            s2_queue_refuse('redis_prefix_setup_failed');
        }

        foreach ($spec['queues'] as $queue) {
            // Illuminate\Queue\RedisQueue::getQueue() returns this raw key;
            // Laravel PhpRedisConnector applies the cached OPT_PREFIX in the client.
            $base = 'queues:' . $queue;
            $ready = $client->lLen($base);
            $reserved = $client->zCard($base . ':reserved');
            $delayed = $client->zCard($base . ':delayed');
            foreach ([$ready, $reserved, $delayed] as $count) {
                if (!is_int($count) || $count < 0) {
                    s2_queue_refuse('invalid_redis_count');
                }
            }
            $totals['ready'] += $ready;
            $totals['reserved'] += $reserved;
            $totals['delayed'] += $delayed;
        }
        $client->close();
    }
    $totals['jobs'] = $totals['ready'] + $totals['reserved'] + $totals['delayed'];
    return $totals;
}

/** Production entrypoint: stdin contains worker specs only; all config stays in memory. */
function s2_native_redis_counts_entry(string $root): array
{
    if (!extension_loaded('redis') || !class_exists(Redis::class, false)) {
        s2_queue_refuse('native_redis_extension_missing');
    }
    $resolvedRoot = realpath($root);
    if ($resolvedRoot === false || !is_file($resolvedRoot . '/bootstrap/cache/config.php')) {
        s2_queue_refuse('cached_config_not_found');
    }
    if (!s2_laravel_key_derivation_match($resolvedRoot)) {
        s2_queue_refuse('laravel_key_derivation_source_unverified');
    }
    $cached = require $resolvedRoot . '/bootstrap/cache/config.php';
    $workerSpecs = json_decode(stream_get_contents(STDIN), true, 64, JSON_THROW_ON_ERROR);
    if (!is_array($cached) || !is_array($workerSpecs)) {
        s2_queue_refuse('invalid_adapter_input');
    }
    return [
        'laravel_key_derivation_match' => true,
        'payloads_read' => false,
        'data_write_commands' => 0,
        'framework_connection_identity_match' => true,
        ...s2_native_redis_counts(s2_native_queue_specs($cached, $workerSpecs['worker_specs'] ?? [], $workerSpecs['framework_connections'] ?? [])),
    ];
}

if (PHP_SAPI === 'cli' && isset($argv[1]) && $argv[1] === '--counts') {
    try {
        $result = s2_native_redis_counts_entry($argv[2] ?? '');
        echo json_encode($result, JSON_THROW_ON_ERROR);
    } catch (Throwable $e) {
        // Deliberately suppress exception text, config values, and credentials.
        fwrite(STDERR, json_encode(['status' => 'refused', 'reason' => s2_safe_refusal_reason($e)]) . "\n");
        exit(2);
    }
}
