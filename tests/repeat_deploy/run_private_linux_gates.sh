#!/bin/sh
set -eu
umask 077

FIXTURE_PARENT=/root/amorenat-fixtures
FIXTURE_ROOT=${REPEAT_DEPLOY_TEST_ROOT:-/root/amorenat-fixtures/repeat-deploy-be24}
PHP_BIN=${REPEAT_DEPLOY_TEST_PHP:-/usr/bin/php8.5}

if [ "$FIXTURE_ROOT" != /root/amorenat-fixtures/repeat-deploy-be24 ]; then
    echo 'REPEAT_DEPLOY_TEST_ROOT must be the dedicated repeat-deploy-be24 fixture' >&2
    exit 2
fi
if [ -L "$FIXTURE_PARENT" ] || [ ! -d "$FIXTURE_PARENT" ] || [ "$(stat -c '%u' "$FIXTURE_PARENT")" != 0 ]; then
    echo 'fixture parent must be an existing root-owned directory' >&2
    exit 2
fi
if [ -L "$FIXTURE_ROOT" ]; then
    echo 'private fixture root must not be a symlink' >&2
    exit 2
fi
mkdir -p "$FIXTURE_ROOT"
chown root:root "$FIXTURE_ROOT"
chmod 0700 "$FIXTURE_ROOT"
if [ "$(stat -c '%u:%g:%a' "$FIXTURE_ROOT")" != '0:0:700' ]; then
    echo 'private fixture root owner or mode mismatch' >&2
    exit 2
fi

command -v python3 >/dev/null
command -v git >/dev/null
test -x "$PHP_BIN"
PHP_VERSION=$("$PHP_BIN" -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
if [ "$PHP_VERSION" != 8.5 ]; then
    echo 'private fixture tests require PHP 8.5' >&2
    exit 2
fi

export REPEAT_DEPLOY_TEST_ROOT="$FIXTURE_ROOT"
export REPEAT_DEPLOY_TEST_PHP="$PHP_BIN"
python3 -m unittest discover -s tests/repeat_deploy -p 'test_*.py' -v
