import subprocess

def xdg_secret_store(label, secret, attrs):
    with subprocess.Popen(["secret-tool", "store", "--label", label] + attrs,
                           stdin=subprocess.PIPE) as proc:
        proc.communicate(secret.encode("utf-8"))
        return proc.wait() == 0

def xdg_secret_lookup_secret(attrs):
    with subprocess.Popen(["secret-tool", "lookup"] + attrs,
                           stdout=subprocess.PIPE) as proc:
        return proc.stdout.read().rstrip(b"\n")

def xdg_secret_search_stdout(attrs):
    return subprocess.call(["secret-tool", "search"] + attrs) == 0

def xdg_secret_clear(attrs):
    return subprocess.call(["secret-tool", "clear"] + attrs) == 0
