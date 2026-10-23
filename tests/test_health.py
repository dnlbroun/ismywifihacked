from pathlib import Path

from netcheck.health import run_checks


def test_alerts_once_per_problem_and_on_recovery(tmp_path: Path) -> None:
    sent: list[str] = []
    state = tmp_path / "state.json"
    broken = {"web": lambda: "web app not answering", "disk": lambda: None}

    def notify(title: str, message: str) -> None:
        sent.append(f"{title}: {message}")

    run_checks(broken, state, notify)
    run_checks(broken, state, notify)  # still broken: no repeat alert
    assert sent == ["ismywifihacked.com problem: web app not answering"]

    run_checks({"web": lambda: None, "disk": lambda: None}, state, notify)
    assert sent[-1] == "ismywifihacked.com recovered: web is OK again"


def test_a_crashing_check_is_a_problem(tmp_path: Path) -> None:
    def boom() -> str | None:
        raise RuntimeError

    sent: list[str] = []
    problems = run_checks({"x": boom}, tmp_path / "s.json", lambda t, m: sent.append(m))
    assert problems == {"x": "check crashed (RuntimeError)"}
    assert len(sent) == 1
