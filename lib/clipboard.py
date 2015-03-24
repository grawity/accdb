import sys
import subprocess

# 'Clipboard' {{{

class Clipboard():
    @classmethod
    def get(self):
        if sys.platform == "win32":
            import win32clipboard as clip
            clip.OpenClipboard()
            # TODO: what type does this return?
            data = clip.GetClipboardData(clip.CF_UNICODETEXT)
            print("clipboard.get =", repr(data))
            clip.CloseClipboard()
            return data
        else:
            raise RuntimeError("Unsupported platform")

    @classmethod
    def put(self, data):
        if sys.platform == "win32":
            import win32clipboard as clip
            clip.OpenClipboard()
            clip.EmptyClipboard()
            clip.SetClipboardText(data, clip.CF_UNICODETEXT)
            clip.CloseClipboard()
        elif sys.platform.startswith("linux"):
            proc = subprocess.Popen(("xsel", "-i", "-b", "-l", "/dev/null"),
                        stdin=subprocess.PIPE)
            proc.stdin.write(data.encode("utf-8"))
            proc.stdin.close()
            proc.wait()
        else:
            raise RuntimeError("Unsupported platform")

# }}}
