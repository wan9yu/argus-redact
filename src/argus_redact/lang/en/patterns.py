"""English regex patterns for Layer 1 PII detection."""

from argus_redact.lang.zh.patterns import _validate_luhn


def _validate_ssn(value: str) -> bool:
    """Basic SSN validation: area != 000, group != 00, serial != 0000."""
    parts = value.split("-")
    if len(parts) != 3:
        return False
    area, group, serial = parts
    if area == "000" or group == "00" or serial == "0000":
        return False
    return True


def _validate_credit_card_luhn(value: str) -> bool:
    """Luhn checksum for credit card with optional separators."""
    digits_only = value.replace("-", "").replace(" ", "")
    if not digits_only.isdigit():
        return False
    return _validate_luhn(digits_only)


_MONTHS = (
    r"(?:January|February|March|April|May|June"
    r"|July|August|September|October|November|December"
    r"|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
)

PATTERNS = [
    {
        "type": "ssn",
        "label": "[SSN REDACTED]",
        "pattern": r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        "validate": _validate_ssn,
        "check_context": True,
        "description": "US Social Security Number",
    },
    {
        "type": "phone",
        "label": "[PHONE REDACTED]",
        "pattern": (r"(?:\+1[-.\s]?)?" r"\(?\d{3}\)?[-.\s]?" r"\d{3}[-.\s]?" r"\d{4}" r"(?!\d)"),
        "description": "North American phone number",
    },
    {
        "type": "credit_card",
        "label": "[CARD REDACTED]",
        "pattern": (r"(?<!\d)" r"[3-6]\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}" r"(?!\d)"),
        "validate": _validate_credit_card_luhn,
        "check_context": True,
        "description": "Credit card number (Luhn checksum)",
    },
    {
        "type": "address",
        "label": "[ADDRESS REDACTED]",
        "pattern": (
            r"\d{1,5}\s+"
            r"(?:[A-Z][a-z]+\s+){1,3}"
            r"(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|"
            r"Dr(?:ive)?|Ln|Lane|Way|Ct|Court|Pl(?:ace)?|Cir(?:cle)?)"
            r"(?:\s*,\s*(?:Apt|Suite|Unit|#)\s*\w+)?"
        ),
        "description": "US street address (number + street name + type)",
    },
    {
        "type": "date_of_birth",
        "label": "[DOB REDACTED]",
        "pattern": (
            r"(?:date\s+of\s+birth|DOB|birthdate|birthday|born(?:\s+on)?)"
            r"\s*[:.]?\s*"
            r"(?P<date_of_birth>"
            # M/D/YYYY or MM/DD/YYYY
            r"(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}"
            r"|"
            # YYYY-MM-DD
            r"(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
            r"|"
            # Month D, YYYY or Month D YYYY
            rf"{_MONTHS}\s+\d{{1,2}},?\s+(?:19|20)\d{{2}}"
            r"|"
            # D(st/nd/rd/th) Month YYYY
            r"\d{1,2}(?:st|nd|rd|th)?\s+"
            rf"{_MONTHS}\s+(?:19|20)\d{{2}}"
            r")"
        ),
        "group": "date_of_birth",
        "description": "English date of birth (keyword-triggered, multiple formats)",
    },
    {
        "type": "us_passport",
        "label": "[PASSPORT REDACTED]",
        "pattern": (
            r"(?i:passport\s*(?:number|no\.?|#)?)\s*[:.]?\s*"
            r"(?P<us_passport>[A-Za-z]\d{8})"
            r"(?!\d)"
        ),
        "group": "us_passport",
        "description": "US passport number (keyword-triggered, letter + 8 digits)",
    },
    # ── Level 3 sensitive attributes (explicit keyword detection) ──
    {
        "type": "medical",
        "label": "[MEDICAL REDACTED]",
        "pattern": (
            r"(?i:(?:diagnosed with|suffering from|treated for|prescribed|"
            r"patient has|history of))\s+"
            r"(?P<medical>(?i:\w[\w\s]{2,30}))"
        ),
        "group": "medical",
        "description": "Medical diagnosis (keyword-triggered, preserves trigger phrase)",
    },
    {
        "type": "medical",
        "label": "[MEDICAL REDACTED]",
        "pattern": (
            r"(?i:HIV\s*(?:positive|negative)"
            r"|(?:\w+\s+)?(?:surgery|transplant|chemotherapy|radiation therapy)"
            r"|(?:diabetes|cancer|tumor|leukemia|hypertension|"
            r"depression|schizophrenia|epilepsy|tuberculosis|hepatitis|"
            r"alzheimer|parkinson|asthma|arthritis))"
        ),
        "description": "Medical standalone (HIV/disease/surgery)",
    },
    {
        "type": "financial",
        "label": "[FINANCIAL REDACTED]",
        "pattern": (
            r"(?i:(?:salary|income|wage|earnings|pay))\s*(?:of\s*)?"
            r"(?P<financial>\$[\d,.]+)"
        ),
        "group": "financial",
        "description": "Financial amount (keyword-triggered, preserves keyword)",
    },
    {
        "type": "financial",
        "label": "[FINANCIAL REDACTED]",
        "pattern": (
            r"(?i:(?:owes?|debt|owed|loan|mortgage)\s+\$[\d,.]+"
            r"(?:\s+(?:in\s+)?(?:debt|loan|mortgage))?"
            r"|credit\s+score\s+\d{3}"
            r"|(?:net\s+worth|annual\s+income|monthly\s+salary)\s*(?:of\s*)?\$[\d,.]+"
            r"|(?:bankrupt|bankruptcy|foreclosure|repossession))"
        ),
        "description": "Financial standalone (debt/credit score/bankruptcy)",
    },
    {
        "type": "criminal_record",
        "label": "[CRIMINAL REDACTED]",
        "pattern": (
            r"(?i:(?:convicted|convicted of|found guilty|pleaded guilty)\s+\w[\w\s]{2,20}"
            r"|sentenced\s+to\s+\d+\s+\w+"
            r"|(?:felony|misdemeanor)\s+(?:record|charge|conviction)"
            r"|(?:criminal record|arrest record|police record)"
            r"|(?:on\s+parole|on\s+probation|incarcerated|imprisoned))"
        ),
        "description": "Criminal record (conviction/sentence/felony/arrest)",
    },
    {
        "type": "biometric",
        "label": "[BIOMETRIC REDACTED]",
        "pattern": (
            r"(?i:(?:fingerprint|fingerprints)\s+(?:collected|scanned|recorded|stored|data)"
            r"|facial\s+recognition"
            r"|(?:iris|retina)\s+scan"
            r"|(?:voice(?:print)?|palm\s+print)\s+(?:recorded|collected|data)"
            r"|(?:DNA|genetic)\s+(?:test|sample|data|profile|analysis)"
            r"|biometric\s+(?:data|information|identifier))"
        ),
        "description": "Biometric data (fingerprint/facial/iris/DNA/voiceprint)",
    },
    {
        "type": "religion",
        "label": "[RELIGION REDACTED]",
        "pattern": (
            r"(?i:(?:Christian|Catholic|Protestant|Muslim|Jewish|Hindu|Buddhist|"
            r"Sikh|Mormon|Atheist|Agnostic|Orthodox)"
            r"|(?:Sunday|Friday|Saturday)\s+(?:worship|prayer|service|mass)"
            r"|(?:baptized|baptism|communion|confession|pilgrimage|Ramadan|"
            r"Sabbath|kosher|halal))"
        ),
        "description": "Religious belief (faith/worship/practices)",
    },
    {
        "type": "political",
        "label": "[POLITICAL REDACTED]",
        "pattern": (
            r"(?i:(?:registered|affiliated)\s+(?:Democrat|Republican|"
            r"Labour|Conservative|Liberal|Independent)"
            r"|voted\s+(?:for\s+)?(?:Democrat|Republican|Labour|Conservative|"
            r"Liberal|Independent|\w+)"
            r"|(?:protest|demonstration|rally|march)\s*(?:against|for)?"
            r"|(?:political\s+(?:affiliation|party|opinion|belief|activist)))"
        ),
        "description": "Political opinion (party/voting/protest/affiliation)",
    },
    {
        "type": "sexual_orientation",
        "label": "[ORIENTATION REDACTED]",
        "pattern": (
            r"(?i:(?:homosexual|heterosexual|bisexual|asexual|pansexual)"
            r"|\b(?:gay|lesbian|queer|LGBTQ?)\b"
            r"|(?:came\s+out|coming\s+out))"
        ),
        "description": "Sexual orientation (explicit terms)",
    },
]
