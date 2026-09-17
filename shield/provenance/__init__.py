from shield.provenance.models import Provenance

__all__ = ["Provenance", "ProvenanceValidationResult", "validate_provenance"]


def __getattr__(name: str):
    """
    Lazily re-export validator names.

    shield.gateway.models imports shield.provenance.models, which initializes this
    package. Eagerly importing shield.provenance.validator here (it imports
    shield.gateway.models for ReasonCode) would create a circular import, so the
    validator symbols are resolved on demand instead.
    """
    if name in ("ProvenanceValidationResult", "validate_provenance"):
        from shield.provenance import validator

        return getattr(validator, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
