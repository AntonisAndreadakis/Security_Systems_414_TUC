#!/bin/sh
set -eu

program=./assign_1
test_dir=$(mktemp -d)
trap 'rm -rf -- "$test_dir"' EXIT HUP INT TERM

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

expect_failure() {
    if "$@" >/dev/null 2>&1; then
        fail "command unexpectedly succeeded: $*"
    fi
}

python3 -c 'import sys; open(sys.argv[1], "wb").write(bytes(range(256)) + b"\\x00binary\\ntext\\xff" * 19)' "$test_dir/binary"
: > "$test_dir/empty"

for bits in 128 256; do
    "$program" -i "$test_dir/binary" -o "$test_dir/encrypted-$bits" -p 'test password' -b "$bits" -e
    "$program" -i "$test_dir/encrypted-$bits" -o "$test_dir/decrypted-$bits" -p 'test password' -b "$bits" -d
    cmp "$test_dir/binary" "$test_dir/decrypted-$bits" ||
        fail "$bits-bit binary encryption roundtrip"

    "$program" -i "$test_dir/empty" -o "$test_dir/empty-encrypted-$bits" -p empty-test -b "$bits" -e
    "$program" -i "$test_dir/empty-encrypted-$bits" -o "$test_dir/empty-decrypted-$bits" -p empty-test -b "$bits" -d
    cmp "$test_dir/empty" "$test_dir/empty-decrypted-$bits" ||
        fail "$bits-bit empty encryption roundtrip"

    "$program" -i "$test_dir/binary" -o "$test_dir/signed-$bits" -p cmac-test -b "$bits" -s
    "$program" -i "$test_dir/signed-$bits" -o "$test_dir/verified-$bits" -p cmac-test -b "$bits" -v >/dev/null
    cmp "$test_dir/binary" "$test_dir/verified-$bits" ||
        fail "$bits-bit CMAC roundtrip"

    "$program" -i "$test_dir/empty" -o "$test_dir/empty-signed-$bits" -p cmac-test -b "$bits" -s
    "$program" -i "$test_dir/empty-signed-$bits" -o "$test_dir/empty-verified-$bits" -p cmac-test -b "$bits" -v >/dev/null
    cmp "$test_dir/empty" "$test_dir/empty-verified-$bits" ||
        fail "$bits-bit empty CMAC roundtrip"
done

cp "$test_dir/signed-128" "$test_dir/tag-tampered"
python3 -c 'import sys; p=sys.argv[1]; d=bytearray(open(p,"rb").read()); d[-1] ^= 1; open(p,"wb").write(d)' "$test_dir/tag-tampered"
expect_failure "$program" -i "$test_dir/tag-tampered" -o "$test_dir/tag-tampered.out" -p cmac-test -b 128 -v
[ ! -e "$test_dir/tag-tampered.out" ] || fail "tag tamper created output"
expect_failure "$program" -i "$test_dir/signed-128" -o "$test_dir/wrong-password.out" -p wrong-password -b 128 -v
[ ! -e "$test_dir/wrong-password.out" ] || fail "wrong-password verification created output"

cp "$test_dir/signed-128" "$test_dir/cipher-tampered"
python3 -c 'import sys; p=sys.argv[1]; d=bytearray(open(p,"rb").read()); d[0] ^= 1; open(p,"wb").write(d)' "$test_dir/cipher-tampered"
expect_failure "$program" -i "$test_dir/cipher-tampered" -o "$test_dir/cipher-tampered.out" -p cmac-test -b 128 -v
[ ! -e "$test_dir/cipher-tampered.out" ] || fail "ciphertext tamper created output"

printf '\001\002\003' > "$test_dir/truncated"
expect_failure "$program" -i "$test_dir/truncated" -o "$test_dir/truncated.out" -p invalid -b 128 -d
expect_failure "$program" -i "$test_dir/truncated" -o "$test_dir/truncated-v.out" -p invalid -b 128 -v
expect_failure "$program" -i "$test_dir/empty" -o "$test_dir/invalid.out" -p invalid -b 192 -e
expect_failure "$program" -i "$test_dir/empty" -o "$test_dir/invalid.out" -p invalid -b 128 -e -d
expect_failure "$program" -i "$test_dir/empty" -o "$test_dir/invalid.out" -p '' -b 128 -e
expect_failure "$program" -i "$test_dir/empty" -o "$test_dir/invalid.out" -p invalid -b 128
"$program" -h >/dev/null

"$program" -i hpy414_decryptme_128.txt -o "$test_dir/fixture-decrypted" -p hpy414 -b 128 -d
printf 'Hello HPY414\n\nThis file was encrypted with a 128-bit key\n\nBB!\n' > "$test_dir/fixture-expected"
cmp "$test_dir/fixture-expected" "$test_dir/fixture-decrypted" ||
    fail "provided 128-bit decryption fixture"

"$program" -i hpy414_verifyme_128.txt -o "$test_dir/fixture-verified-128" -p hpy414 -b 128 -v >/dev/null ||
    fail "provided 128-bit CMAC fixture"
"$program" -i hpy414_verifyme_256.txt -o "$test_dir/fixture-verified-256" -p hpy414 -b 256 -v >/dev/null ||
    fail "provided 256-bit CMAC fixture"

printf 'All encryption, CMAC, tamper, invalid-input, empty-file, binary-file, and supplied fixture tests passed.\n'
