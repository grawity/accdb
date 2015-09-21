import base64
from nullroute.core import Core

from . import hotpie as oath

from .string import encode_psk
from .util import _debug

class OATHParameters(object):
    """
    A collection of OATH parameters for a single site.
    """
    def __init__(self, raw_psk, digits=6, otype="totp", window=30,
                 login=None, issuer=None):
        if otype not in {"totp"}:
            Core.err("OATH %r is not supported yet" % otype)
        self.raw_psk = raw_psk
        self.digits = digits
        self.otype = otype
        self.window = window
        self.login = login
        self.issuer = issuer

    @property
    def text_psk(self):
        return encode_psk(self.raw_psk)

    def make_uri(self):
        # https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
        # TODO: url-encode label & issuer
        if self.issuer and (self.issuer != self.login):
            issuer = self.issuer
            label = "%s:%s" % (issuer, self.login)
        else:
            issuer = None
            label = self.login

        uri = "otpauth://totp/%s?secret=%s" % (label, self.text_psk)
        if issuer:
            uri += "&issuer=%s" % issuer
        if self.digits != 6:
            uri += "&digits=%d" % self.digits

        return uri

    def generate(self):
        _debug("generating OTP from: %r",
               base64.b32encode(self.raw_psk).decode("us-ascii"))

        if self.otype == "totp":
            return oath.TOTP(self.raw_psk, digits=self.digits, window=self.window)
        else:
            Core.err("OATH %r is not supported yet" % self.otype)
