from veritas_ai.assurance import _advisory_decision


def test_unlabelled_confidence_cusum_threshold_requires_investigation() -> None:
    action, reasons = _advisory_decision(
        integrity_ok=True,
        missingness=0.0,
        fnr_increase=None,
        ece_increase=None,
        labels_available=False,
        context_approved=False,
        max_psi=0.0,
        confidence_cusum=5.0,
    )

    assert action == "investigate"
    assert reasons == ["confidence_cusum_threshold_exceeded"]


def test_labelled_cusum_does_not_replace_labelled_performance_evidence() -> None:
    action, reasons = _advisory_decision(
        integrity_ok=True,
        missingness=0.0,
        fnr_increase=0.0,
        ece_increase=0.0,
        labels_available=True,
        context_approved=False,
        max_psi=0.0,
        confidence_cusum=6.0,
    )

    assert action == "continue"
    assert reasons == []
