from click.testing import CliRunner
from backend.app.cli import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "Forge CLI Version" in result.output


def test_cli_list_rules():
    runner = CliRunner()
    result = runner.invoke(cli, ["rules"])
    assert result.exit_code == 0
    assert "PY-SQL-001" in result.output
    assert "PY-CMD-001" in result.output


def test_cli_scan_json_output():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "examples/vulnerable", "--format", "json"])
    assert result.exit_code == 0
    assert '"forge_version": "0.1.0"' in result.output
    assert '"PY-SQL-001"' in result.output


def test_cli_fail_on_high():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "examples/vulnerable", "--fail-on", "high"])
    assert result.exit_code == 1
    assert "Security check failed" in result.output
