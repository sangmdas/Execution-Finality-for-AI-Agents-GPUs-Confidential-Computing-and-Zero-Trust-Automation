class FinalityError(Exception):
    """Base class for reference implementation failures."""


class ValidationDenied(FinalityError):
    pass


class VerificationFailed(FinalityError):
    pass


class ReplayDetected(VerificationFailed):
    pass


class EffectDenied(FinalityError):
    pass


class EvidenceError(FinalityError):
    pass
