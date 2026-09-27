"""Custom Presidio pattern recognizers for secrets and proprietary/financial data.

Presidio's built-ins (EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN,
US_BANK_NUMBER, IBAN_CODE, CRYPTO, US_PASSPORT, ...) already cover most
common PII with checksum/format validation, which keeps their false-positive
rate low. The recognizers below extend that coverage to API keys/secrets and
internal-financial markers, which Presidio does not ship out of the box.

Each pattern is deliberately specific (real key prefixes, fixed lengths)
rather than a loose catch-all, since loose patterns are what drive false
positives up.
"""

from presidio_analyzer import Pattern, PatternRecognizer

# --- Cloud / API secrets -----------------------------------------------

AWS_ACCESS_KEY = PatternRecognizer(
    supported_entity="AWS_ACCESS_KEY",
    name="AwsAccessKeyRecognizer",
    patterns=[Pattern("AWS Access Key ID", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", 0.9)],
)

AWS_SECRET_KEY = PatternRecognizer(
    supported_entity="AWS_SECRET_KEY",
    name="AwsSecretKeyRecognizer",
    patterns=[
        Pattern(
            "AWS Secret Access Key (contextual)",
            r"(?i)aws_?(secret)?_?(access)?_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?",
            0.85,
        )
    ],
    context=["aws", "secret", "credentials"],
)

GITHUB_TOKEN = PatternRecognizer(
    supported_entity="GITHUB_TOKEN",
    name="GitHubTokenRecognizer",
    patterns=[Pattern("GitHub Token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", 0.9)],
)

SLACK_TOKEN = PatternRecognizer(
    supported_entity="SLACK_TOKEN",
    name="SlackTokenRecognizer",
    patterns=[Pattern("Slack Token", r"\bxox[baprs]-[0-9A-Za-z-]{10,72}\b", 0.9)],
)

STRIPE_KEY = PatternRecognizer(
    supported_entity="STRIPE_KEY",
    name="StripeKeyRecognizer",
    patterns=[
        Pattern("Stripe Live Key", r"\bsk_live_[0-9a-zA-Z]{24,99}\b", 0.9),
        Pattern("Stripe Restricted Key", r"\brk_live_[0-9a-zA-Z]{24,99}\b", 0.9),
    ],
)

PRIVATE_KEY_BLOCK = PatternRecognizer(
    supported_entity="PRIVATE_KEY",
    name="PrivateKeyRecognizer",
    patterns=[
        Pattern(
            "PEM Private Key Header",
            r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----",
            0.95,
        )
    ],
)

JWT_TOKEN = PatternRecognizer(
    supported_entity="JWT",
    name="JwtRecognizer",
    patterns=[
        Pattern(
            "JSON Web Token",
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b",
            0.85,
        )
    ],
)

GENERIC_API_KEY = PatternRecognizer(
    supported_entity="GENERIC_API_KEY",
    name="GenericApiKeyRecognizer",
    patterns=[
        Pattern(
            "key/token/secret assignment",
            r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret|"
            r"auth[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{16,}['\"]?",
            0.6,
        )
    ],
    context=["key", "token", "secret", "credentials", "auth"],
)

# --- Internal / financial data markers ----------------------------------
# Kept as lower-confidence *supporting* signals (never the sole trigger by
# default) since keyword-based detection alone is prone to false positives.

CONFIDENTIALITY_MARKER = PatternRecognizer(
    supported_entity="CONFIDENTIALITY_MARKER",
    name="ConfidentialityMarkerRecognizer",
    patterns=[
        Pattern(
            "Internal/confidential marker",
            r"(?i)\b(internal use only|proprietary and confidential|do not distribute|"
            r"company confidential|not for external distribution)\b",
            0.5,
        )
    ],
)

ROUTING_NUMBER = PatternRecognizer(
    supported_entity="US_ROUTING_NUMBER",
    name="RoutingNumberRecognizer",
    patterns=[Pattern("ABA routing number (contextual)", r"\b\d{9}\b", 0.3)],
    context=["routing", "aba", "wire", "bank transfer"],
)

ALL_CUSTOM_RECOGNIZERS = [
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    GITHUB_TOKEN,
    SLACK_TOKEN,
    STRIPE_KEY,
    PRIVATE_KEY_BLOCK,
    JWT_TOKEN,
    GENERIC_API_KEY,
    CONFIDENTIALITY_MARKER,
    ROUTING_NUMBER,
]

# Entity types that are high-precision (format/checksum-validated or a very
# specific literal pattern) and are allowed to trigger a flag on their own.
HIGH_PRECISION_ENTITIES = {
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "STRIPE_KEY",
    "PRIVATE_KEY",
    "JWT",
    "GENERIC_API_KEY",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
    "US_SSN",
    "US_BANK_NUMBER",
    "IBAN_CODE",
    "CRYPTO",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
}

# Entity types that are noisy on their own (generic NER, loose context
# matches) and are only used to *corroborate* a high-precision hit, not to
# trigger a flag by themselves. This is what keeps the false-positive rate
# in the target 1-10% band instead of flagging every name or phone-looking
# number in the payload.
SUPPORTING_ENTITIES = {
    "PERSON",
    "LOCATION",
    "PHONE_NUMBER",
    "CONFIDENTIALITY_MARKER",
    "US_ROUTING_NUMBER",
    "NRP",
}
# NOTE: DATE_TIME is deliberately excluded. It's an extremely common,
# low-signal entity (any "this week"/"tomorrow" mention) and letting it
# count toward corroboration causes ordinary sentences to false-positive
# (e.g. "this week's weather forecast for Boston" -> DATE_TIME + LOCATION).
