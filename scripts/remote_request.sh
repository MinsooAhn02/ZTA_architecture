#!/bin/sh
# Remote half of one request. Input is base64 line protocol; secrets never enter argv.
set -u
umask 077
tmp=$(mktemp)
cfg=$(mktemp)
bodyfile=$(mktemp)
trap 'rm -f "$tmp" "$cfg" "$bodyfile"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
IFS= read -r method || exit 2
IFS= read -r url || exit 2
IFS= read -r rid || exit 2
IFS= read -r timeout || exit 2
IFS= read -r count || exit 2
case "$method" in GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) ;; *) exit 2;; esac
case "$count" in ''|*[!0-9]*) exit 2;; esac
case "$timeout" in ''|*[!0-9.]*) exit 2;; esac
quote() {
    escaped=$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')
    printf '"%s"' "$escaped"
}
{
    echo silent
    echo show-error
    echo 'max-filesize = 1048576'
    printf 'max-time = %s\n' "$timeout"
    printf 'request = '; quote "$method"; echo
    if [ "$method" = HEAD ]; then echo head; fi
    printf 'output = '; quote "$tmp"; echo
    echo 'write-out = "%{http_code}"'
    printf 'header = '; quote "X-Request-ID: $rid"; echo
    i=0
    while [ "$i" -lt "$count" ]; do
        IFS= read -r encoded || exit 2
        header=$(printf '%s' "$encoded" | base64 -d) || exit 2
        printf 'header = '; quote "$header"; echo
        i=$((i + 1))
    done
    IFS= read -r encoded_body || exit 2
    if [ -n "$encoded_body" ]; then
        printf '%s' "$encoded_body" | base64 -d > "$bodyfile" || exit 2
        printf 'data-binary = '; quote "@$bodyfile"; echo
    fi
    printf 'url = '; quote "$url"; echo
} > "$cfg"
code=$(curl --config "$cfg" 2>/dev/null)
curl_exit=$?
if [ "$curl_exit" -ne 0 ]; then code=000; fi
# Cap captured bodies; errors and diagnostics are never mixed with response bytes.
body64=$(head -c 65536 "$tmp" | base64 | tr -d '\n')
printf '__ZTA_RESULT__\t%s\t%s\t%s\n' "$code" "$curl_exit" "$body64"
