"""
CLI entry point for AI Red Team Simulation.

Provides the `airtsim` command-line interface for running
security test suites against LLM applications.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

from airtsim.runner import run_suite
from airtsim.report import generate_reports


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="airtsim",
        description="AI Red Team Simulation - LLM Application Security Testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run a test suite
  airtsim run --suite suites/demo.yaml

  # Run with mitigations enabled
  airtsim run --suite suites/demo.yaml --enable-mitigations

  # Specify output directory
  airtsim run --suite suites/demo.yaml --report-dir ./my_reports

  # Use verbose output
  airtsim run --suite suites/demo.yaml -v
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run a test suite")
    run_parser.add_argument(
        "--suite", "-s",
        required=True,
        type=str,
        help="Path to YAML test suite file",
    )
    run_parser.add_argument(
        "--report-dir", "-r",
        type=str,
        default="reports",
        help="Directory for report output (default: reports)",
    )
    run_parser.add_argument(
        "--enable-mitigations", "-m",
        action="store_true",
        help="Enable security mitigations during testing",
    )
    run_parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )
    run_parser.add_argument(
        "--json-only",
        action="store_true",
        help="Only generate JSON report (skip Markdown)",
    )
    
    # Info command
    subparsers.add_parser("info", help="Show tool information")
    
    # List command
    list_parser = subparsers.add_parser("list", help="List available test suites")
    list_parser.add_argument(
        "--dir", "-d",
        type=str,
        default="suites",
        help="Directory to search for suites (default: suites)",
    )
    
    return parser


def print_banner():
    """Print the tool banner."""
    if HAS_RICH:
        banner = """
[bold red]    _    ___ ____  _____ ____ ___ __  __ [/bold red]
[bold red]   / \\  |_ _|  _ \\|_   _/ ___|_ _|  \\/  |[/bold red]
[bold red]  / _ \\  | || |_) | | | \\___ \\| || |\\/| |[/bold red]
[bold red] / ___ \\ | ||  _ <  | |  ___) | || |  | |[/bold red]
[bold red]/_/   \\_\\___|_| \\_\\ |_| |____/___|_|  |_|[/bold red]

[bold cyan]AI Red Team Simulation - LLM AppSec Testing[/bold cyan]
        """
        console = Console()
        console.print(banner)
    else:
        print("""
    _    ___ ____  _____ ____ ___ __  __ 
   / \\  |_ _|  _ \\|_   _/ ___|_ _|  \\/  |
  / _ \\  | || |_) | | | \\___ \\| || |\\/| |
 / ___ \\ | ||  _ <  | |  ___) | || |  | |
/_/   \\_\\___|_| \\_\\ |_| |____/___|_|  |_|

AI Red Team Simulation - LLM AppSec Testing
        """)


def cmd_run(args: argparse.Namespace) -> int:
    """Execute the run command."""
    suite_path = Path(args.suite)
    
    if not suite_path.exists():
        print(f"Error: Suite file not found: {suite_path}")
        return 1
    
    # Print configuration
    if HAS_RICH:
        console = Console()
        config_text = f"""
[bold]Suite:[/bold] {suite_path}
[bold]Mitigations:[/bold] {'✅ Enabled' if args.enable_mitigations else '❌ Disabled'}
[bold]Report Directory:[/bold] {args.report_dir}
        """
        console.print(Panel(config_text.strip(), title="Configuration", border_style="cyan"))
        console.print()
    else:
        print(f"\nConfiguration:")
        print(f"  Suite: {suite_path}")
        print(f"  Mitigations: {'Enabled' if args.enable_mitigations else 'Disabled'}")
        print(f"  Report Directory: {args.report_dir}")
        print()
    
    # Run the suite
    try:
        if HAS_RICH:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console,
            ) as progress:
                task = progress.add_task("[cyan]Running test suite...", total=None)
                result = run_suite(
                    suite_path=str(suite_path),
                    enable_mitigations=args.enable_mitigations,
                )
                progress.update(task, description="[green]Test suite complete!")
        else:
            print("Running test suite...")
            result = run_suite(
                suite_path=str(suite_path),
                enable_mitigations=args.enable_mitigations,
            )
            print("Test suite complete!")
    except Exception as e:
        print(f"Error running suite: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Display results summary
    display_summary(result, verbose=args.verbose)
    
    # Generate reports
    report_name = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    try:
        if HAS_RICH:
            console.print("\n[bold]Generating reports...[/bold]")
        else:
            print("\nGenerating reports...")
        
        json_path, md_path = generate_reports(
            result=result,
            output_dir=args.report_dir,
            report_name=report_name,
        )
        
        if HAS_RICH:
            console.print(f"  [green]✓[/green] JSON report: {json_path}")
            if not args.json_only:
                console.print(f"  [green]✓[/green] Markdown report: {md_path}")
        else:
            print(f"  ✓ JSON report: {json_path}")
            if not args.json_only:
                print(f"  ✓ Markdown report: {md_path}")
    except Exception as e:
        print(f"Error generating reports: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    
    # Return exit code based on results
    if result.metrics.overall_asr > 0.5:
        return 2  # High risk
    elif result.errors:
        return 1  # Errors occurred
    else:
        return 0


def display_summary(result, verbose: bool = False):
    """Display results summary."""
    if HAS_RICH:
        console = Console()
        
        # Summary table
        table = Table(title="Test Results Summary", border_style="cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")
        
        table.add_row("Suite Name", result.suite_name)
        table.add_row("Target", result.target_name)
        table.add_row("Total Test Cases", str(result.metrics.total_cases))
        table.add_row("Successful Attacks", f"[red]{result.metrics.successful_attacks}[/red]")
        table.add_row("Failed Attacks", f"[green]{result.metrics.failed_attacks}[/green]")
        table.add_row("Leaks Detected", str(result.metrics.leaks_detected))
        table.add_row("Injections Detected", str(result.metrics.injections_detected))
        
        # Color ASR based on risk
        asr = result.metrics.overall_asr
        if asr > 0.5:
            asr_str = f"[bold red]{asr:.1%}[/bold red]"
        elif asr > 0.2:
            asr_str = f"[yellow]{asr:.1%}[/yellow]"
        else:
            asr_str = f"[green]{asr:.1%}[/green]"
        table.add_row("Overall ASR", asr_str)
        
        table.add_row("Duration", f"{result.duration_seconds:.2f}s")
        
        console.print(table)
        
        # ASR by kind
        if result.metrics.asr_by_kind and verbose:
            kind_table = Table(title="ASR by Attack Type", border_style="blue")
            kind_table.add_column("Attack Type")
            kind_table.add_column("ASR", justify="right")
            
            for kind, asr in result.metrics.asr_by_kind.items():
                kind_name = kind.replace("_", " ").title()
                if asr > 0.5:
                    asr_str = f"[red]{asr:.1%}[/red]"
                elif asr > 0.2:
                    asr_str = f"[yellow]{asr:.1%}[/yellow]"
                else:
                    asr_str = f"[green]{asr:.1%}[/green]"
                kind_table.add_row(kind_name, asr_str)
            
            console.print(kind_table)
        
        # Errors
        if result.errors:
            console.print(f"\n[bold red]Errors ({len(result.errors)}):[/bold red]")
            for error in result.errors:
                console.print(f"  [red]✗[/red] {error}")
    else:
        # Plain text output
        print("\n" + "=" * 50)
        print("TEST RESULTS SUMMARY")
        print("=" * 50)
        print(f"Suite Name:          {result.suite_name}")
        print(f"Target:              {result.target_name}")
        print(f"Total Test Cases:    {result.metrics.total_cases}")
        print(f"Successful Attacks:  {result.metrics.successful_attacks}")
        print(f"Failed Attacks:      {result.metrics.failed_attacks}")
        print(f"Leaks Detected:      {result.metrics.leaks_detected}")
        print(f"Injections Detected: {result.metrics.injections_detected}")
        print(f"Overall ASR:         {result.metrics.overall_asr:.1%}")
        print(f"Duration:            {result.duration_seconds:.2f}s")
        print("=" * 50)
        
        if result.errors:
            print(f"\nErrors ({len(result.errors)}):")
            for error in result.errors:
                print(f"  ✗ {error}")


def cmd_info(args: argparse.Namespace) -> int:
    """Show tool information."""
    if HAS_RICH:
        console = Console()
        info = """
[bold cyan]AI Red Team Simulation (airtsim)[/bold cyan]

A security testing framework for LLM applications that simulates
adversarial attacks including:

• [bold]Prompt Injection[/bold] - Direct manipulation of LLM prompts
• [bold]Indirect Injection[/bold] - Injection via RAG documents/context
• [bold]Data Leakage[/bold] - Extraction of sensitive information

[bold]Features:[/bold]
• Mock LLM backend (no API keys required)
• Vulnerable RAG customer support bot
• Toggleable security mitigations
• Comprehensive Markdown and JSON reports

[bold]Usage:[/bold]
  airtsim run --suite <path> [--enable-mitigations]

[bold]Learn more:[/bold]
  https://github.com/your-org/ai-redteaming-simulation
        """
        console.print(Panel(info.strip(), border_style="cyan"))
    else:
        print("""
AI Red Team Simulation (airtsim)

A security testing framework for LLM applications that simulates
adversarial attacks including:

• Prompt Injection - Direct manipulation of LLM prompts
• Indirect Injection - Injection via RAG documents/context
• Data Leakage - Extraction of sensitive information

Features:
• Mock LLM backend (no API keys required)
• Vulnerable RAG customer support bot
• Toggleable security mitigations
• Comprehensive Markdown and JSON reports

Usage:
  airtsim run --suite <path> [--enable-mitigations]
        """)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List available test suites."""
    suites_dir = Path(args.dir)
    
    if not suites_dir.exists():
        print(f"Directory not found: {suites_dir}")
        return 1
    
    yaml_files = list(suites_dir.glob("*.yaml")) + list(suites_dir.glob("*.yml"))
    
    if not yaml_files:
        print(f"No YAML suite files found in: {suites_dir}")
        return 0
    
    if HAS_RICH:
        console = Console()
        table = Table(title=f"Available Test Suites in '{suites_dir}'", border_style="cyan")
        table.add_column("Suite File")
        table.add_column("Size")
        
        for f in sorted(yaml_files):
            size = f.stat().st_size
            table.add_row(f.name, f"{size} bytes")
        
        console.print(table)
    else:
        print(f"\nAvailable Test Suites in '{suites_dir}':")
        for f in sorted(yaml_files):
            print(f"  • {f.name}")
    
    return 0


def main():
    """Main entry point."""
    print_banner()
    
    parser = create_parser()
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 0
    
    if args.command == "run":
        return cmd_run(args)
    elif args.command == "info":
        return cmd_info(args)
    elif args.command == "list":
        return cmd_list(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
