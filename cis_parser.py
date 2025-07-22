#!/usr/bin/env python3
"""
CIS Metrics Extractor
"""

import re
import sys
import json
from typing import Dict, List, Optional
from collections import defaultdict, Counter
from argparse import (
    ArgumentParser,
    RawTextHelpFormatter
)

labels = defaultdict(lambda: {'total': 0, 'pass': 0, 'fail': 0, 'skipped': 0, 'manual': 0, 'not implemented': 0, 'error': 0})

class AuditItem:
    """Represents a single audit item."""
    def __init__(self, id: str, description: str, level: Optional[int], 
                 result: Optional[str], duration: Optional[str], 
                 duration_ms: Optional[float]):
        self.id = id
        self.description = description
        self.level = level
        self.result = result
        self.duration = duration
        self.duration_ms = duration_ms


class AuditMetricsExtractor:
    """Extracts and analyzes metrics from security audit reports."""
    
    def __init__(self):
        self.items: List[AuditItem] = []
        self.metrics: Dict = {}
    
    def parse_text(self, text: str) -> List[AuditItem]:
        """Parse the audit text and extract structured data."""
        lines = text.strip().split('\n')
        
        # Find the header line to determine column positions
        header_line = None
        data_start = 0
        
        for i, line in enumerate(lines):
            if 'ID' in line and 'Description' in line and 'Level' in line:
                header_line = line
                # Skip the separator line
                data_start = i + 2
                break
        
        if not header_line:
            raise ValueError("Could not find header line in the text")
        
        # Parse each data line
        items = []
        for line in lines[data_start:]:
            if line.strip() and not line.startswith('-'):
                item = self._parse_line(line)
                if item:
                    items.append(item)
        
        self.items = items
        return items
    
    def _parse_line(self, line: str) -> Optional[AuditItem]:
        """Parse a single line of audit data."""
        # Split by multiple spaces to handle the column structure
        parts = re.split(r'\s{2,}', line.strip())
        
        if len(parts) < 2:
            return None
        
        # Extract ID
        id_str = parts[0].strip()
        
        # Extract description
        description = parts[1].strip()
        
        # Extract level, result, and duration
        level = None
        result = None
        duration = None
        duration_ms = None
        
        if len(parts) >= 3:
            level_str = parts[2].strip()
            if level_str.isdigit():
                level = int(level_str)
        
        if len(parts) >= 4:
            result = parts[3].strip()
        
        if len(parts) >= 5:
            duration = parts[4].strip()
            duration_ms = self._parse_duration(duration)
        
        return AuditItem(
            id=id_str,
            description=description,
            level=level,
            result=result,
            duration=duration,
            duration_ms=duration_ms
        )
    
    def _parse_duration(self, duration_str: str) -> Optional[float]:
        """Parse duration string to milliseconds."""
        if not duration_str:
            return None
        
        # Handle different duration formats
        duration_str = duration_str.lower()
        
        if 'ms' in duration_str:
            try:
                return float(duration_str.replace('ms', ''))
            except ValueError:
                return None
        elif 's' in duration_str:
            try:
                return float(duration_str.replace('s', '')) * 1000
            except ValueError:
                return None
        
        return None
    
    def calculate_metrics(self) -> Dict:
        """Calculate comprehensive metrics from the audit data."""
        if not self.items:
            return {}
        
        # Filter items that have actual test results (not just headers)
        test_items = [item for item in self.items if item.result and item.level is not None]
        
        metrics = {
            'total_tests': len(test_items),
            'results_summary': self._calculate_results_summary(test_items),
            'level_breakdown': self._calculate_level_breakdown(test_items),
            'category_analysis': self._calculate_category_analysis(test_items),
            'failures': self._calculate_failures(test_items)
        }
        
        self.metrics = metrics
        return metrics
    
    def _calculate_results_summary(self, items: List[AuditItem]) -> Dict:
        """Calculate summary of test results."""
        result_counts = Counter(item.result for item in items)
        total = len(items)
        
        summary = {
            'counts': dict(result_counts),
            'percentages': {
                result: (count / total * 100) if total > 0 else 0 
                for result, count in result_counts.items()
            }
        }
        
        return summary
    
    def _calculate_level_breakdown(self, items: List[AuditItem]) -> Dict:
        """Calculate breakdown by security level."""
        level_data = labels
        
        for item in items:
            if item.level is not None:
                level_data[item.level]['total'] += 1
                if item.result:
                    level_data[item.level][item.result.lower()] += 1
        
        return dict(level_data)
    
    def _calculate_category_analysis(self, items: List[AuditItem]) -> Dict:
        """Analyze results by category based on ID patterns."""
        categories = labels
        
        for item in items:
            # Extract main category from ID (e.g., "1.1" from "1.1.1")
            if '.' in item.id:
                category = '.'.join(item.id.split('.')[:2])
            else:
                category = item.id
            
            categories[category]['total'] += 1
            if item.result:
                categories[category][item.result.lower()] += 1
        
        return dict(categories)
    
    def _calculate_failures(self, items: List[AuditItem]) -> Dict:
        """Analyze failed tests in detail."""
        failed_items = [item for item in items if item.result and item.result.lower() == 'fail']
        
        analysis = {
            'total_failures': len(failed_items),
            'failed_by_level': Counter(item.level for item in failed_items),
            'failed_items': [
                {
                    'id': item.id,
                    'description': item.description,
                    'level': item.level,
                    'duration_ms': item.duration_ms
                }
                for item in failed_items
            ]
        }
        
        return analysis
    
    def generate_report(self, format_type: str = 'text') -> str:
        """Generate a formatted report of the metrics."""
        if not self.metrics:
            self.calculate_metrics()
        
        if format_type == 'json':
            return json.dumps(self.metrics, indent=2)
        elif format_type == 'text':
            return self._generate_text_report()
        else:
            raise ValueError("Unsupported format type. Use 'text' or 'json'")
    
    def _generate_text_report(self) -> str:
        """Generate a human-readable text report."""
        if not self.metrics:
            return "No metrics calculated"
        
        report = []
        report.append("=== AUDIT METRICS ===\n")
        
        # Overall Summary
        report.append(f"Total Tests: {self.metrics['total_tests']}")
        report.append("")
        
        # Results Summary
        report.append("RESULTS SUMMARY:")
        results = self.metrics['results_summary']
        for result, count in results['counts'].items():
            percentage = results['percentages'][result]
            report.append(f"  {result}: {count} ({percentage:.1f}%)")
        report.append("")
        
        # Level Breakdown
        report.append("BREAKDOWN BY SECURITY LEVEL:")
        for level, data in sorted(self.metrics['level_breakdown'].items()):
            report.append(f"  Level {level}: {data['total']} tests")
            report.append(f"    Pass: {data['pass']}, Fail: {data['fail']} Skipped: {data['skipped']}, Manual: {data['manual']}, Not Implemented: {data['not implemented']}, Error: {data['error']}")
        report.append("")
        
        # Failure Analysis
        failures = self.metrics['failures']
        if failures['total_failures'] > 0:
            report.append("FAILURE ANALYSIS:")
            report.append(f"  Total Failures: {failures['total_failures']}")
            report.append("  Failed by Level:")
            for level, count in sorted(failures['failed_by_level'].items()):
                report.append(f"    Level {level}: {count}")
            report.append("")
        
        return "\n".join(report)
    
    def export_failed_tests(self) -> List[Dict]:
        """Export details of failed tests for further analysis."""
        if not self.metrics:
            self.calculate_metrics()
        
        return self.metrics['failures']['failed_items']


if __name__ == "__main__":
    """Example usage of the AuditMetricsExtractor"""

    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)
    parser.add_argument('-i','--input', action='store', dest='input')
    parser.add_argument('-q','--query', action='store', dest='query', 
                       help='Filter controls by ID pattern (e.g., "1.1" to include only controls starting with 1.1)')

    args = parser.parse_args(sys.argv[1:])
    with open(args.input) as f: data = f.read()
    
    # Initialize extractor
    extractor = AuditMetricsExtractor()
    
    # Parse the text
    items = extractor.parse_text(data)
    
    # Filter items if query is provided
    if args.query:
        filtered_items = [item for item in items if item.id.startswith(args.query)]
        extractor.items = filtered_items
        print(f"Filtered {len(filtered_items)} items matching '{args.query}' (from {len(items)} total)")
    else:
        print(f"Parsed {len(items)} items")
    print()
    
    # Generate and display report
    report = extractor.generate_report('text')
    print(report)
    
    # Export failed tests
    failed_tests = extractor.export_failed_tests()
    print(f"\nFailed tests details ({len(failed_tests)} items)")
    for test in failed_tests:
        print(f"  {test['id']}: {test['description']}")
    
    # JSON
    #json_report = extractor.generate_report('json')
    #print(json_report)