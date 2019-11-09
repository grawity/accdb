import os
import subprocess

def _is_in_path(exe):
    for dir in os.environ["PATH"].split(":"):
        if os.path.exists("%s/%s" % (dir or ".", exe)):
            return True
    return False

def qr_encode(data):
    if _is_in_path("qrencode"):
        with subprocess.Popen(["qrencode", "-tUTF8", data],
                              stdout=subprocess.PIPE) as proc:
            for line in proc.stdout:
                yield line.decode("utf-8").strip()
    else:
        raise Exception("no QR code generator available")
