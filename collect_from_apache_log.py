#!/usr/bin/env python3

"""
CLI tool to parse Apache log files and export them as Parquet files.
"""

import sys
from pathlib import Path

import click
import polars as pl
from simple_web_stat.parser import parse_log_files, parse_log_file


@click.group()
def cli():
    """CLI tool for parsing Apache log files and exporting to Parquet format."""
    pass


@cli.command()
@click.argument(
    "log_file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=Path("./output"),
    help="Output directory for Parquet files. Default: ./output",
)
@click.option(
    "--prefix",
    "-p",
    type=str,
    default="apache_logs",
    help="Prefix for output Parquet filename. Default: apache_logs",
)
def single(log_file: Path, output_dir: Path, prefix: str):
    """
    Parse a single Apache log file and export to Parquet partitioned by date and hour.

    Example:
        python collect_from_apache_log.py single logs/access.log -o data/ -p mysite
    """
    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)

        click.echo(f"Parsing log file: {log_file}")
        df = parse_log_file(log_file)

        click.echo(f"Parsed {len(df)} entries")

        # Add date and hour columns for partitioning
        df = df.with_columns(
            [
                df["timestamp"].dt.date().alias("date"),
                df["timestamp"].dt.hour().alias("hour"),
            ]
        )

        output_path = output_dir / f"{prefix}.parquet"

        # Check if data already exists and append to it
        if output_path.exists():
            click.echo(f"Reading existing partitioned data from: {output_path}")
            existing_df = pl.read_parquet(output_path)
            click.echo(f"Existing data has {len(existing_df)} entries")

            # Concatenate new data with existing data
            df = pl.concat([existing_df, df])
            click.echo(f"Total entries after merge: {len(df)}")

        click.echo(f"Writing partitioned data to: {output_path}")
        
        # Show date and hour distribution
        date_hour_counts = df.group_by(["date", "hour"]).agg(pl.count("timestamp").alias("count"))
        for row in date_hour_counts.iter_rows(named=True):
            click.echo(f"  {row['date']} hour {row['hour']:02d}: {row['count']} entries")
        
        df.write_parquet(
            output_path,
            partition_by=["date", "hour"],
        )
        click.echo(
            click.style(
                f"✓ Successfully wrote {len(df)} total entries to {output_path}",
                fg="green",
            )
        )

    except FileNotFoundError as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red"), err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red"), err=True)
        sys.exit(1)


@cli.command()
@click.argument(
    "log_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
)
@click.option(
    "--pattern",
    type=str,
    default="*.log",
    help="Glob pattern for matching log files. Default: *.log",
)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=Path("./output"),
    help="Output directory for Parquet files. Default: ./output",
)
@click.option(
    "--prefix",
    "-p",
    type=str,
    default="apache_logs_combined",
    help="Prefix for output Parquet filename. Default: apache_logs_combined",
)
def batch(log_dir: Path, pattern: str, output_dir: Path, prefix: str):
    """
    Parse multiple Apache log files from a directory and export to Parquet partitioned by date and hour.
    Appends to existing data if the output directory already exists.

    Example:
        python collect_from_apache_log.py batch logs/ -o data/ -p mysite --pattern "*.log"
    """
    try:
        # Create output directory if it doesn't exist
        output_dir.mkdir(parents=True, exist_ok=True)

        click.echo(f"Parsing log files from: {log_dir}")
        click.echo(f"Pattern: {pattern}")

        df = parse_log_files(log_dir, pattern=pattern)

        click.echo(f"Parsed {len(df)} entries total")

        # Add date and hour columns for partitioning
        df = df.with_columns(
            [
                df["timestamp"].dt.date().alias("date"),
                df["timestamp"].dt.hour().alias("hour"),
            ]
        )

        output_path = output_dir / f"{prefix}.parquet"

        # Check if data already exists and append to it
        if output_path.exists():
            click.echo(f"Reading existing partitioned data from: {output_path}")
            existing_df = pl.read_parquet(output_path)
            click.echo(f"Existing data has {len(existing_df)} entries")

            # Concatenate new data with existing data
            df = pl.concat([existing_df, df])
            click.echo(f"Total entries after merge: {len(df)}")

        click.echo(f"Writing partitioned data to: {output_path}")
        
        # Show date and hour distribution
        date_hour_counts = df.group_by(["date", "hour"]).agg(pl.count("timestamp").alias("count"))
        for row in date_hour_counts.iter_rows(named=True):
            click.echo(f"  {row['date']} hour {row['hour']:02d}: {row['count']} entries")
        
        df.write_parquet(
            output_path,
            partition_by=["date", "hour"],
        )
        click.echo(
            click.style(
                f"✓ Successfully wrote {len(df)} total entries to {output_path}",
                fg="green",
            )
        )

    except NotADirectoryError as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red"), err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(click.style(f"✗ Error: {e}", fg="red"), err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
