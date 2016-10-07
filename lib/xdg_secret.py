import subprocess

def xdg_secret_store(label, secret, attrs):
    with subprocess.Popen(["secret-tool", "store", "--label", label, *attrs],
                           stdin=subprocess.PIPE) as proc:
        proc.stdin.write(secret.encode("utf-8"))

def xdg_secret_lookup_secret(attrs):
    with subprocess.Popen(["secret-tool", "lookup", *attrs],
                           stdout=subprocess.PIPE) as proc:
        return proc.stdout.read().rstrip("\n")

def xdg_secret_search_stdout(attrs):
    return subprocess.run(["secret-tool", "search", *attrs])

def xdg_secret_clear(attrs):
    return subprocess.run(["secret-tool", "clear", *attrs])
