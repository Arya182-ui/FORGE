import sys
import os
import click
from pathlib import Path

from backend.app.scanner.engine import ScannerEngine
from backend.app.scanner.reporters.json_reporter import JSONReporter
from backend.app.scanner.reporters.markdown_reporter import MarkdownReporter
from backend.app.scanner.rules import get_all_registered_rules
from backend.app.evaluation.metrics import EvaluatorEngine
from backend.app.evaluation.bandit_runner import BanditRunner
from backend.app import __version__


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0
}


@click.group()
def cli():
    """FORGE — AI-Powered Security Code Review & Analysis Platform"""
    pass


@cli.command()
def version():
    """Display Forge version info."""
    click.echo(f"Forge CLI Version {__version__}")


@cli.group(name="rules", invoke_without_command=True)
@click.pass_context
def rules_group(ctx):
    """List or inspect registered security rules."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(list_rules)


@rules_group.command(name="list")
def list_rules():
    """List all registered Forge security rules."""
    rules = get_all_registered_rules()
    click.echo("\nRegistered Forge Security Rules:")
    click.echo("-" * 60)
    for r in rules:
        click.echo(f"[{r.rule_id}] {r.name} | Language: {r.language.upper()} | Severity: {r.severity} | OWASP: {r.owasp_category}")
    click.echo("-" * 60)



@cli.command()
@click.argument("target_path", type=click.Path(exists=True))
@click.option("--language", "-l", help="Filter scan by language (python, javascript)")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json", "markdown"]), default="table", help="Output format")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low", "info"], case_sensitive=False), help="Fail CLI with non-zero exit code if findings meet or exceed severity threshold")
@click.option("--no-ai", is_flag=True, help="Disable AI explanation enrichment (run rule-based scan only)")
@click.option("--output", "-o", type=click.Path(), help="Save report to file path")
def scan(target_path: str, language: str, output_format: str, fail_on: str, no_ai: bool, output: str):
    """Scan a local directory or file for security vulnerabilities."""
    click.echo(f"Starting Forge Security Scan on target: {target_path} ...\n")
    
    engine = ScannerEngine()
    try:
        report = engine.run_scan(target_path, language_filter=language, save_to_db=True)
    except Exception as e:
        click.echo(f"Error executing scan: {str(e)}", err=True)
        sys.exit(2)

    summary = report.summary
    findings = report.findings

    # Render report according to requested format
    rendered_output = ""
    if output_format == "json":
        rendered_output = JSONReporter.generate_report(summary, findings, report.parser_errors)
    elif output_format == "markdown":
        rendered_output = MarkdownReporter.generate_report(summary, findings, report.parser_errors)
    else:  # table / default console format
        rendered_output = f"Scan Summary for target '{target_path}':\n"
        rendered_output += f"  Files Scanned: {summary.scanned_files_count}\n"
        rendered_output += f"  Lines Scanned: {summary.scanned_lines_count}\n"
        rendered_output += f"  Total Findings: {summary.total_findings_count}\n"
        rendered_output += f"  [CRITICAL: {summary.critical_count} | HIGH: {summary.high_count} | MEDIUM: {summary.medium_count} | LOW: {summary.low_count}]\n"
        rendered_output += f"  Duration: {summary.duration_ms:.2f} ms\n"
        rendered_output += "-" * 70 + "\n"

        if not findings:
            rendered_output += "SUCCESS: No security vulnerabilities found!\n"
        else:
            for idx, f in enumerate(findings, 1):
                rendered_output += f"\n[{idx}] [{f.severity}] {f.title} ({f.rule_id})\n"
                rendered_output += f"    Location : {f.file_path} : L{f.line_number}\n"
                rendered_output += f"    OWASP    : {f.owasp_category}\n"
                rendered_output += f"    Snippet  : {f.code_snippet}\n"
                rendered_output += f"    Fix      : {f.recommendation}\n"

    if output:
        out_path = Path(output)
        out_path.write_text(rendered_output, encoding="utf-8")
        click.echo(f"Scan report written to file: {output}")
    else:
        click.echo(rendered_output)

    # Check --fail-on threshold
    if fail_on:
        threshold_sev = fail_on.upper()
        threshold_val = SEVERITY_ORDER.get(threshold_sev, 0)

        should_fail = False
        for f in findings:
            f_sev_val = SEVERITY_ORDER.get(f.severity.upper(), 0)
            if f_sev_val >= threshold_val:
                should_fail = True
                break

        if should_fail:
            click.echo(f"\n[FAIL] Security check failed: Findings found meeting or exceeding threshold '{threshold_sev}'", err=True)
            sys.exit(1)

    sys.exit(0)


@cli.command()
@click.argument("evaluation_path", type=click.Path(exists=True), default="./evaluation")
def evaluate(evaluation_path: str):
    """Run empirical benchmark evaluation against ground truth dataset and Bandit baseline."""
    click.echo(f"Running Forge Benchmark Evaluation on dataset: {evaluation_path} ...\n")

    try:
        forge_metrics = EvaluatorEngine.evaluate_directory(evaluation_path)
    except Exception as e:
        click.echo(f"Evaluation error: {str(e)}", err=True)
        sys.exit(1)

    bandit_metrics = BanditRunner.evaluate_bandit(evaluation_path)

    click.echo("=" * 65)
    click.echo("                 FORGE BENCHMARK EVALUATION RESULTS")
    click.echo("=" * 65)

    headers = f"{'Metric':<20} | {'Forge AST':<15} | {'Bandit Baseline':<15}"
    click.echo(headers)
    click.echo("-" * 65)

    p_forge = f"{forge_metrics['precision']:.1f}%"
    p_bandit = f"{bandit_metrics['precision']:.1f}%" if bandit_metrics else "N/A"
    click.echo(f"{'Precision':<20} | {p_forge:<15} | {p_bandit:<15}")

    r_forge = f"{forge_metrics['recall']:.1f}%"
    r_bandit = f"{bandit_metrics['recall']:.1f}%" if bandit_metrics else "N/A"
    click.echo(f"{'Recall':<20} | {r_forge:<15} | {r_bandit:<15}")

    f1_forge = f"{forge_metrics['f1_score']:.1f}%"
    f1_bandit = f"{bandit_metrics['f1_score']:.1f}%" if bandit_metrics else "N/A"
    click.echo(f"{'F1 Score':<20} | {f1_forge:<15} | {f1_bandit:<15}")

    click.echo("-" * 65)
    click.echo(f"{'True Positives (TP)':<20} | {forge_metrics['tp']:<15} | {bandit_metrics['tp'] if bandit_metrics else 'N/A':<15}")
    click.echo(f"{'False Positives (FP)':<20} | {forge_metrics['fp']:<15} | {bandit_metrics['fp'] if bandit_metrics else 'N/A':<15}")
    click.echo(f"{'False Negatives (FN)':<20} | {forge_metrics['fn']:<15} | {bandit_metrics['fn'] if bandit_metrics else 'N/A':<15}")
    click.echo(f"{'Execution Time (ms)':<20} | {forge_metrics['duration_ms']:<15} | {bandit_metrics['duration_ms'] if bandit_metrics else 'N/A':<15}")
    click.echo("=" * 65 + "\n")


if __name__ == "__main__":
    cli()


