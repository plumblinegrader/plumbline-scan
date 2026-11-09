"""Reference/network logic with a scripted fake Docker (no Docker needed)."""

from pathlib import Path

from plumbline_scan.checks import Options, Scan
from plumbline_scan.docker import RunResult
from plumbline_scan.harbor import load_task

TOY = Path(__file__).parent / "toy_tasks"


class FakeDocker:
    log_dir = None

    def __init__(self, sealed, network):
        self.sealed, self.network = list(sealed), list(network)

    def run(self, task, label, network, solve=True, patch=None, log_name=None):
        reward = (self.network if network else self.sealed).pop(0)
        return RunResult(label=label, network=network, reward=reward, full=reward >= 1)


def _ref(sealed, network, task="needs-network"):
    s = Scan(load_task(TOY / task), FakeDocker(sealed, network), Options(k=3), log=lambda m: None)
    ref = s.check_reference()
    return ref, s.check_network([]), s


def test_network_dependence_confirmed():
    ref, net, s = _ref(sealed=[0, 0], network=[1, 1, 1])
    assert ref.status == "PASS" and net.status == "NETWORK" and s.net_needed


def test_flaky_sealed_failure_is_not_network():
    ref, net, s = _ref(sealed=[0, 1], network=[1, 1, 1])
    assert ref.status == "WARN" and "flaky" in ref.summary
    assert net.status == "PASS" and not s.net_needed


def test_network_does_not_help_stops_retrying():
    ref, net, _ = _ref(sealed=[0, 0, 0], network=[0])
    assert ref.status == "FLAG" and net.status != "NETWORK"


def test_flaky_sealed():
    ref, net, _ = _ref(sealed=[1, 0, 1], network=[0], task="good")  # good declares no network: no retry
    assert ref.status == "WARN" and ref.details["passes"] == 2
