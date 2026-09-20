from backend.logic.nft_hook import _forward_nfqueue_args


def test_hook_targets_forward_nfqueue_not_input():
    args = _forward_nfqueue_args(0, "-A")
    assert "FORWARD" in args
    assert "NFQUEUE" in args
    assert "INPUT" not in args
    assert "--queue-num" in args
