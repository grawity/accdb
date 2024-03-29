import base64
from collections import OrderedDict
from nullroute.core import Core
import urllib.parse

from .hotpie import TOTP
from .string import encode_psk

class OATHParameters():
    def __init__(self, raw_psk, digits=6, window=30,
                 login=None, issuer=None, image=None):
        self.raw_psk = raw_psk
        self.digits = digits
        self.window = window
        self.login = login
        self.issuer = issuer
        self.image = image

    @property
    def text_psk(self):
        return encode_psk(self.raw_psk)

    def make_uri(self):
        # https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
        if self.issuer and (self.issuer != self.login):
            issuer = self.issuer
            label = "%s:%s" % (issuer, self.login)
        else:
            issuer = None
            label = self.login

        data = OrderedDict()
        data["secret"] = self.text_psk
        if issuer:
            data["issuer"] = issuer
        if self.digits != 6:
            data["digits"] = self.digits
        if self.image:
            data["image"] = self.image

        uri = "otpauth://totp/%s?%s" % (urllib.parse.quote(label),
                                        urllib.parse.urlencode(data))
        return uri

    def generate(self):
        return TOTP(self.raw_psk, digits=self.digits, window=self.window)
