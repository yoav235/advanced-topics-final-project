import pytest
from simulate import main as simulate_main
from simulate_attack_demo import main as simulate_attack_main

def test_legit_clients(capsys):
    simulate_main()
    captured = capsys.readouterr()
    output = captured.out
    assert "[Server S3] Final destination reached." in output
    assert "❌ Invalid NOPE signature!" not in output

def test_malicious_client(capsys):
    simulate_attack_main()
    captured = capsys.readouterr()
    output = captured.out
    assert "❌ Invalid NOPE signature! Message dropped." in output
    assert output.count("Final destination reached.") == 2


def test_client_send_message(capsys):
