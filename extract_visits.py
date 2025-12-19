#!/usr/bin/env python3
"""
Extract unique visits per day matching specific patterns from Apache logs.
Filters by host pattern and URI patterns (OR match), then outputs CSV.
"""

import click
import polars as pl
from pathlib import Path
from typing import Optional


@click.command()
@click.argument('data_dir', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option(
    '--uri-patterns',
    '-u',
    multiple=True,
    required=True,
    help='URI patterns to match (OR logic - any match counts). Can specify multiple times.'
)
@click.option(
    '--referrer-pattern',
    '-r',
    default=None,
    help='Optional referrer pattern to filter by (regex pattern)'
)
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    default='visits.csv',
    help='Output CSV file path (default: visits.csv)'
)
@click.option(
    '--show-uris',
    is_flag=True,
    help='Show and save unique URIs that matched the patterns'
)
@click.option(
    '--verbose',
    '-v',
    is_flag=True,
    help='Show detailed statistics'
)
def extract_visits(
    data_dir: str,
    uri_patterns: tuple,
    referrer_pattern: Optional[str],
    output: str,
    show_uris: bool,
    verbose: bool
):
    """
    Extract unique visits per day from Apache logs.
    
    Counts unique visitor IPs per day that match the specified URI patterns.
    Multiple URI patterns are combined with OR logic.
    
    Example:
        ./extract_visits.py ../web_stat_data/data/ -u '/api/' -u '/admin/' -o visits.csv
    """
    data_dir_path = Path(data_dir)
    
    # Find parquet files with Hive partitioning (date=YYYY-MM-DD/hour=HH/*.parquet)
    parquet_files = list(data_dir_path.glob('**/date=*/*/*.parquet'))
    
    if not parquet_files:
        click.echo(f"❌ No parquet files found in {data_dir_path}", err=True)
        raise click.Abort()
    
    click.echo(f"📂 Found {len(parquet_files)} parquet files")
    
    # Read all parquet files with partitioning
    try:
        df = pl.scan_parquet(str(data_dir_path / '**/date=*/*/*.parquet'))
    except Exception as e:
        click.echo(f"❌ Error reading parquet files: {e}", err=True)
        raise click.Abort()
    
    # Extract date from timestamp
    df = df.with_columns([
        pl.col('timestamp').dt.date().alias('date')
    ])
    
    if verbose:
        click.echo(f"📊 Total records: {df.select(pl.len()).collect().item():,}")
    
    # Apply URI pattern filters (OR logic)
    uri_filter = None
    for pattern in uri_patterns:
        pattern_filter = pl.col('uri').str.contains(pattern, literal=False)
        if uri_filter is None:
            uri_filter = pattern_filter
        else:
            uri_filter = uri_filter | pattern_filter
    
    if uri_filter is not None:
        df = df.filter(uri_filter)
    
    if verbose:
        click.echo(f"📍 After URI filter: {df.select(pl.len()).collect().item():,}")
    
    # Apply referrer filter if specified
    if referrer_pattern:
        df = df.filter(pl.col('referrer').str.contains(referrer_pattern, literal=False))
        if verbose:
            click.echo(f"📍 After referrer filter: {df.select(pl.len()).collect().item():,}")
    
    # Collect unique URIs that matched (before grouping)
    if show_uris:
        # Get filtered URIs with their request counts
        uris_with_counts = df.group_by('uri').agg(pl.len().alias('count')).sort('count', descending=True)
        
        # Add a column showing which patterns matched each URI
        matched_patterns = []
        uri_list = uris_with_counts.select('uri').collect().to_series().to_list()
        
        for uri in uri_list:
            patterns_matched = [p for p in uri_patterns if p in uri]
            matched_patterns.append(','.join(patterns_matched) if patterns_matched else '-')
        
        uris_with_counts = uris_with_counts.with_columns([
            pl.Series('matched_patterns', matched_patterns)
        ]).select(['uri', 'matched_patterns', 'count'])
        
        # Save URIs to a separate file
        uris_output = output.replace('.csv', '_uris.csv')
        uris_with_counts.collect().write_csv(uris_output)
        
        if verbose:
            total_unique_uris = len(uris_with_counts.collect())
            click.echo(f"\n🔗 Found {total_unique_uris} unique URIs matching patterns")
            click.echo("Top 20 URIs by request count:")
            top_uris = uris_with_counts.collect().head(20)
            for row in top_uris.rows(named=True):
                click.echo(f"  {row['count']:6d}x  [{row['matched_patterns']}]  {row['uri']}")
        else:
            click.echo(f"✓ Saved {len(uris_with_counts.collect())} unique URIs to {uris_output}")
    
    # Group by date and count unique IPs
    result = df.group_by('date').agg([
        pl.col('remote_host').n_unique().alias('unique_visits'),
        pl.len().alias('total_requests')
    ]).sort('date')
    
    # Collect and convert to pandas for CSV export
    result_df = result.collect()
    
    # Write to CSV
    result_df.write_csv(output)
    
    click.echo(f"✓ Extracted {len(result_df)} days of data")
    click.echo(f"✓ Successfully wrote to {output}")
    
    if verbose:
        click.echo("📈 Sample data:")
        click.echo(result_df.head(10).__str__())
        click.echo("📊 Statistics:")
        stats = result_df.select([
            pl.col('unique_visits').min().alias('min_visits'),
            pl.col('unique_visits').max().alias('max_visits'),
            pl.col('unique_visits').mean().alias('avg_visits'),
            pl.col('total_requests').sum().alias('total_requests'),
        ])
        click.echo(stats.__str__())


if __name__ == '__main__':
    extract_visits()
