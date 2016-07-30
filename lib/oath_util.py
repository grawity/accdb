import base64
from collections import OrderedDict
from nullroute.core import *
import urllib.parse

from . import hotpie as oath
from .string import encode_psk

class OATHParameters(object):
    """
    A collection of OATH parameters for a single site.
    """
    def __init__(self, raw_psk, digits=6, otype="totp", window=30,
                 login=None, issuer=None, image=None):
        if otype not in {"totp"}:
            Core.err("OATH %r is not supported yet" % otype)
        self.raw_psk = raw_psk
        self.digits = digits
        self.otype = otype
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

        uri = "otpauth://totp/%s?%s" % (urllib.parse.quote_plus(label),
                                        urllib.parse.urlencode(data))

        return uri

    def generate(self):
        Core.debug("generating OTP from: %r" % \
                   base64.b32encode(self.raw_psk).decode("us-ascii"))

        if self.otype == "totp":
            return oath.TOTP(self.raw_psk, digits=self.digits, window=self.window)
        else:
            Core.err("OATH %r is not supported yet" % self.otype)
