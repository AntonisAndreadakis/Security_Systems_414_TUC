#!/usr/bin/env python3
import pathlib, struct, subprocess, sys, tempfile
ROOT = pathlib.Path(__file__).resolve().parent
EXE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "./assign_3").resolve()
WORD = struct.calcsize("P")

def run(*args, cwd=None, success=True):
    p = subprocess.run([str(EXE), *map(str, args)], cwd=cwd,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert (p.returncode == 0) == success, (args, p.returncode, p.stdout, p.stderr)

def key(path):
    raw = path.read_bytes()
    assert len(raw) == 2 * WORD
    return struct.unpack("@NN", raw)

def encrypt(data, path):
    n, exponent = key(path)
    return b"".join(struct.pack("@N", pow(byte, exponent, n)) for byte in data)

def decrypt(data, path):
    n, exponent = key(path)
    assert len(data) % WORD == 0
    return bytes(pow(v[0], exponent, n) for v in struct.iter_unpack("@N", data))

with tempfile.TemporaryDirectory() as name:
    tmp = pathlib.Path(name)
    run("-g", cwd=tmp)
    pub, priv = tmp / "public.key", tmp / "private.key"
    assert key(pub)[0] == key(priv)[0] > 255
    for payload in (b"", bytes(range(256)), b"RSA\x00binary\xff\n"):
        plain, cipher, restored = tmp / "p", tmp / "c", tmp / "r"
        plain.write_bytes(payload)
        for enc_key, dec_key in ((pub, priv), (priv, pub)):
            run("-i", plain, "-o", cipher, "-k", enc_key, "-e")
            assert cipher.read_bytes() == encrypt(payload, enc_key)
            assert len(cipher.read_bytes()) == len(payload) * WORD
            run("-i", cipher, "-o", restored, "-k", dec_key, "-d")
            assert restored.read_bytes() == payload

    challenges = (
        ("hpy414_encryptme_pub.txt", "hpy414_public.key", "e"),
        ("hpy414_encryptme_priv.txt", "hpy414_private.key", "e"),
        ("hpy414_decryptme_pub.txt", "hpy414_public.key", "d"),
        ("hpy414_decryptme_priv.txt", "hpy414_private.key", "d"))
    for source_name, key_name, mode in challenges:
        source, supplied_key = ROOT / source_name, ROOT / key_name
        output = tmp / (source_name + ".out")
        run("-i", source, "-o", output, "-k", supplied_key, "-" + mode)
        expected = encrypt(source.read_bytes(), supplied_key) if mode == "e" else decrypt(source.read_bytes(), supplied_key)
        assert output.read_bytes() == expected

    bad_key = tmp / "bad.key"; bad_key.write_bytes(b"short")
    run("-i", tmp / "p", "-o", tmp / "x", "-k", bad_key, "-e", success=False)
    odd = tmp / "odd"; odd.write_bytes(b"x")
    run("-i", odd, "-o", tmp / "x", "-k", pub, "-d", success=False)
    outside = tmp / "outside"; outside.write_bytes(struct.pack("@N", key(pub)[0]))
    run("-i", outside, "-o", tmp / "x", "-k", pub, "-d", success=False)
    run("-e", "-d", "-i", tmp / "p", "-o", tmp / "x", "-k", pub, success=False)
print("all RSA tests passed")
