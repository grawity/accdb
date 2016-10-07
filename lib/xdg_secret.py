import subprocess

def xdg_secret_store(label, secret, attrs):
    with subprocess.Popen(["secret-tool", "store", "--label", label, *attrs],
                           stdin=subprocess.PIPE) as proc:
        proc.stdin.write(secret.encode("utf-8"))

def xdg_secret_clear(attrs):
    return subprocess.run(["secret-tool", "clear", *attrs])

def xdg_secret_whatever(*args):
    return subprocess.run(["secret-tool", *args])
