"""Brazilian regex patterns for Layer 1 PII detection."""


def _validate_cpf(value: str) -> bool:
    """Validate CPF (Cadastro de Pessoas Físicas) check digits."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) != 11 or len(set(digits)) == 1:
        return False

    # First check digit
    total = sum(d * w for d, w in zip(digits[:9], range(10, 1, -1)))
    remainder = total % 11
    if digits[9] != (0 if remainder < 2 else 11 - remainder):
        return False

    # Second check digit
    total = sum(d * w for d, w in zip(digits[:10], range(11, 1, -1)))
    remainder = total % 11
    if digits[10] != (0 if remainder < 2 else 11 - remainder):
        return False

    return True


def _validate_cnpj(value: str) -> bool:
    """Validate CNPJ (Cadastro Nacional da Pessoa Jurídica) check digits."""
    digits = [int(c) for c in value if c.isdigit()]
    if len(digits) != 14 or len(set(digits)) == 1:
        return False

    # First check digit
    weights = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(digits[:12], weights))
    remainder = total % 11
    if digits[12] != (0 if remainder < 2 else 11 - remainder):
        return False

    # Second check digit
    weights = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    total = sum(d * w for d, w in zip(digits[:13], weights))
    remainder = total % 11
    if digits[13] != (0 if remainder < 2 else 11 - remainder):
        return False

    return True


PATTERNS = [
    {
        "type": "cpf",
        "label": "[CPF]",
        "pattern": r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)",
        "validate": _validate_cpf,
        "description": "Brazilian CPF (Cadastro de Pessoas Físicas)",
    },
    {
        "type": "cnpj",
        "label": "[CNPJ]",
        "pattern": r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)",
        "validate": _validate_cnpj,
        "description": "Brazilian CNPJ (Cadastro Nacional da Pessoa Jurídica)",
    },
    {
        "type": "phone",
        "label": "[Telefone]",
        "pattern": r"(?:\+55\s?)?\(?\d{2}\)?\s?\d{4,5}-?\d{4}(?!\d)",
        "description": "Brazilian phone number",
    },
]
