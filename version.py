"""Single source of truth for the application version."""

__version__ = "1.0.0"
APP_NAME = "Veilwire"
APP_TAGLINE = "Private, peer-to-peer encrypted messaging"
LICENSE = "MIT"
REPOSITORY = "https://github.com/veilwire/p2p"

# Monero address for optional project support, shown in the About dialog.
# Never used anywhere else in the app - no payment/wallet functionality
# exists, this is purely a donation address a user may choose to copy.
XMR_DONATION_ADDRESS = (
    "8AtJNcybvakDRYV6YzANQj1wFu7xh4CDD2bJsYYjYJBWYJULMKWkAs6RTaGMW629"
    "s9K2fShKWF2Pu76Zpp2gSZ9UDs4JdKs"
)

# The project's own Veilwire identity, so a user can add it as a contact
# from the About dialog. Deliberately the public key + fingerprint only -
# never the onion address, matching the app's own rule everywhere else
# that the onion is an internal transport detail, not a normal
# user-facing identity field. Signature-verified against a real contact
# bundle before being hardcoded here (see bundle.parse_bundle).
CONTACT_PUBLIC_KEY = "WLaHZ2NocZk4EHzossIKAZVStWRFmZknsul-CMQv2zI"
CONTACT_FINGERPRINT = "494E 523E B7FA E229 EDBD"


def version_string() -> str:
    return f"v{__version__}"


def full_version() -> str:
    return f"{APP_NAME} {version_string()} - open source ({LICENSE})"
