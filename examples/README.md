# Report Generation Examples

This directory contains examples for generating professional security assessment reports with CyberSentinel.

## Prerequisites

1. Python 3.8 or higher
2. Required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Examples

### 1. Generate Sample Reports

Run the following command to generate sample reports in HTML, PDF, and JSON formats:

```bash
python generate_sample_report.py
```

This will create three report files in the `~/.local/share/cybersentinel/reports/` directory:
- `cybersentinel_report_<timestamp>.html` - Interactive HTML report
- `cybersentinel_report_<timestamp>.pdf` - Printable PDF report
- `cybersentinel_report_<timestamp>.json` - Machine-readable JSON report

## Report Features

### HTML Reports
- Responsive design that works on all devices
- Interactive elements (expandable sections, tabs, etc.)
- Syntax highlighting for code blocks
- Print-friendly styles

### PDF Reports
- Professional layout with cover page
- Table of contents with page numbers
- Proper page breaks and headers/footers
- Embedded fonts and styles

### JSON Reports
- Machine-readable format for integration with other tools
- Contains all scan data in a structured format
- Can be used for custom reporting or data analysis

## Customizing Reports

To customize the reports, you can modify the following files:

1. `app/resources/templates/report.html` - Main HTML template
2. `app/resources/templates/report.css` - Custom styles
3. `app/core/report_generator.py` - Report generation logic

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.
