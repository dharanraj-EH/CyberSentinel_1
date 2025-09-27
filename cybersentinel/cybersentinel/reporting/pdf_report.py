"""
PDF report generator for CyberSentinel.

This module provides functionality to generate PDF reports from scan results.
"""

import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union, List, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
    PageBreak, ListFlowable, ListItem, PageTemplate, Frame, NextPageTemplate
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

logger = logging.getLogger(__name__)

# Register fonts (will be loaded in the class)
FONT_DIR = Path(__file__).parent / 'fonts'

class PDFReportGenerator:
    """
    A class to generate PDF reports from scan results.
    
    This class provides methods to generate professional PDF reports with
    tables, charts, and formatted text.
    """
    
    # Default styles
    DEFAULT_STYLES = {
        'title': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 16,
            'leading': 22,
            'spaceAfter': 12,
            'alignment': TA_CENTER
        },
        'heading1': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 14,
            'leading': 18,
            'spaceBefore': 12,
            'spaceAfter': 6,
            'textColor': colors.HexColor('#2c3e50')
        },
        'heading2': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 12,
            'leading': 16,
            'spaceBefore': 10,
            'spaceAfter': 4,
            'textColor': colors.HexColor('#34495e')
        },
        'heading3': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 11,
            'leading': 14,
            'spaceBefore': 8,
            'spaceAfter': 4,
            'textColor': colors.HexColor('#7f8c8d'
        },
        'normal': {
            'fontName': 'Helvetica',
            'fontSize': 10,
            'leading': 12,
            'spaceAfter': 6
        },
        'small': {
            'fontName': 'Helvetica',
            'fontSize': 8,
            'leading': 10,
            'spaceAfter': 4
        },
        'bold': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'spaceAfter': 6
        },
        'italic': {
            'fontName': 'Helvetica-Oblique',
            'fontSize': 10,
            'leading': 12,
            'spaceAfter': 6
        },
        'footer': {
            'fontName': 'Helvetica',
            'fontSize': 8,
            'leading': 10,
            'textColor': colors.grey
        },
        'finding_title': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'spaceAfter': 2,
            'textColor': colors.HexColor('#2c3e50')
        },
        'finding_severity_critical': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'textColor': colors.HexColor('#e74c3c')
        },
        'finding_severity_high': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'textColor': colors.HexColor('#e67e22')
        },
        'finding_severity_medium': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'textColor': colors.HexColor('#f39c12')
        },
        'finding_severity_low': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'textColor': colors.HexColor('#3498db')
        },
        'finding_severity_info': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'textColor': colors.HexColor('#2ecc71')
        },
        'finding_severity_unknown': {
            'fontName': 'Helvetica-Bold',
            'fontSize': 10,
            'leading': 12,
            'textColor': colors.HexColor('#7f8c8d')
        }
    }
    
    def __init__(self, title: str = "CyberSentinel Scan Report",
                 author: str = "CyberSentinel",
                 subject: str = "Vulnerability Scan Report",
                 page_size: str = 'A4',
                 margin: float = 20.0):
        """
        Initialize the PDF report generator.
        
        Args:
            title: Title of the report.
            author: Author of the report.
            subject: Subject of the report.
            page_size: Page size ('A4' or 'LETTER').
            margin: Page margin in mm.
        ""
        self.title = title
        self.author = author
        self.subject = subject
        self.page_size = A4 if page_size.upper() == 'A4' else letter
        self.margin = margin * mm
        self.styles = {}
        self.elements = []
        
        # Set up fonts
        self._register_fonts()
        
        # Set up styles
        self._setup_styles()
    
    def _register_fonts(self) -> None:
        """Register custom fonts if available."""
        try:
            # Register Helvetica (standard PDF font, no need for file)
            pdfmetrics.registerFont(TTFont('Helvetica', 'Helvetica'))
            pdfmetrics.registerFont(TTFont('Helvetica-Bold', 'Helvetica-Bold'))
            pdfmetrics.registerFont(TTFont('Helvetica-Oblique', 'Helvetica-Oblique'))
            
            # Try to register additional fonts if available
            if FONT_DIR.exists():
                for font_file in FONT_DIR.glob('*.ttf'):
                    try:
                        font_name = font_file.stem
                        pdfmetrics.registerFont(TTFont(font_name, str(font_file)))
                    except Exception as e:
                        logger.warning(f"Failed to register font {font_file.name}: {e}")
        except Exception as e:
            logger.warning(f"Failed to register fonts: {e}")
    
    def _setup_styles(self) -> None:
        """Set up the styles for the PDF document."""
        # Create a stylesheet
        self.styles = {}
        
        # Add default styles
        for style_name, style_attrs in self.DEFAULT_STYLES.items():
            self.styles[style_name] = ParagraphStyle(style_name, **style_attrs)
        
        # Add additional styles
        self.styles['bullet'] = ParagraphStyle(
            'bullet',
            parent=self.styles['normal'],
            leftIndent=10,
            firstLineIndent=-5,
            spaceAfter=4
        )
        
        # Table styles
        self.table_styles = {
            'default': [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ],
            'finding': [
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ]
        }
    
    def generate(self, scan_data: Dict[str, Any], 
                output_path: Union[str, Path]) -> str:
        """
        Generate a PDF report from scan data.
        
        Args:
            scan_data: A dictionary containing the scan results.
            output_path: Path to save the PDF report.
                       
        Returns:
            The path to the generated PDF file.
            
        Raises:
            ValueError: If scan_data is empty or invalid.
            IOError: If there's an error writing the PDF.
        """
        if not scan_data:
            raise ValueError("Scan data cannot be empty")
        
        output_path = Path(output_path)
        
        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Create a temporary file for the PDF
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as tmp_file:
                temp_path = tmp_file.name
            
            # Create the PDF document
            doc = SimpleDocTemplate(
                str(temp_path),
                pagesize=self.page_size,
                title=self.title,
                author=self.author,
                subject=self.subject,
                leftMargin=self.margin,
                rightMargin=self.margin,
                topMargin=self.margin,
                bottomMargin=self.margin
            )
            
            # Reset elements
            self.elements = []
            
            # Add cover page
            self._add_cover_page(scan_data)
            
            # Add table of contents
            self._add_table_of_contents(scan_data)
            
            # Add executive summary
            self._add_executive_summary(scan_data)
            
            # Add detailed findings
            self._add_detailed_findings(scan_data)
            
            # Add scan details
            self._add_scan_details(scan_data)
            
            # Add appendix
            self._add_appendix(scan_data)
            
            # Build the PDF
            doc.build(self.elements)
            
            # Move the temporary file to the final location
            if output_path.exists():
                output_path.unlink()
            
            Path(temp_path).rename(output_path)
            
            logger.info(f"PDF report generated at: {output_path}")
            return str(output_path)
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}", exc_info=True)
            
            # Clean up temporary file if it exists
            if 'temp_path' in locals() and Path(temp_path).exists():
                try:
                    Path(temp_path).unlink()
                except:
                    pass
            
            if isinstance(e, (ValueError, IOError)):
                raise
            raise IOError(f"Failed to generate PDF report: {e}")
    
    def _add_cover_page(self, scan_data: Dict[str, Any]) -> None:
        """Add a cover page to the report."""
        # Add title
        title = Paragraph(self.title, self.styles['title'])
        self.elements.append(Spacer(1, 50))
        self.elements.append(title)
        self.elements.append(Spacer(1, 20))
        
        # Add subtitle
        subtitle = Paragraph("Vulnerability Assessment Report", self.styles['heading1'])
        self.elements.append(subtitle)
        self.elements.append(Spacer(1, 40))
        
        # Add scan metadata
        scan_info = [
            ["Date:", self._format_timestamp(scan_data.get('timestamp'))],
            ["Target:", scan_data.get('target', 'N/A')],
            ["Scan Type:", scan_data.get('scan_type', 'N/A')],
            ["Generated By:", self.author],
        ]
        
        # Add scan info table
        scan_table = Table(scan_info, colWidths=[100, None])
        scan_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (0, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        
        self.elements.append(scan_table)
        self.elements.append(Spacer(1, 40))
        
        # Add summary statistics if available
        if 'summary' in scan_data:
            summary = scan_data['summary']
            severity_counts = summary.get('severity_counts', {})
            
            stats = [
                ["Critical Findings:", str(severity_counts.get('critical', 0))],
                ["High Findings:", str(severity_counts.get('high', 0))],
                ["Medium Findings:", str(severity_counts.get('medium', 0))],
                ["Low Findings:", str(severity_counts.get('low', 0))],
                ["Informational:", str(severity_counts.get('info', 0))],
            ]
            
            stats_table = Table(stats, colWidths=[150, 50])
            stats_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING', (0, 0), (0, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 5),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('TEXTCOLOR', (0, 0), (0, 0), colors.HexColor('#e74c3c')),  # Critical
                ('TEXTCOLOR', (0, 1), (0, 1), colors.HexColor('#e67e22')),  # High
                ('TEXTCOLOR', (0, 2), (0, 2), colors.HexColor('#f39c12')),  # Medium
                ('TEXTCOLOR', (0, 3), (0, 3), colors.HexColor('#3498db')),  # Low
                ('TEXTCOLOR', (0, 4), (0, 4), colors.HexColor('#2ecc71')),  # Info
            ]))
            
            self.elements.append(stats_table)
        
        # Add page break
        self.elements.append(PageBreak())
    
    def _add_table_of_contents(self, scan_data: Dict[str, Any]) -> None:
        """Add a table of contents to the report."""
        # Add TOC title
        toc_title = Paragraph("Table of Contents", self.styles['heading1'])
        self.elements.append(toc_title)
        self.elements.append(Spacer(1, 20))
        
        # TOC entries
        toc_entries = [
            ("1. Executive Summary", 1, self.styles['normal']),
            ("2. Detailed Findings", 1, self.styles['normal']),
            ("3. Scan Details", 1, self.styles['normal']),
            ("4. Appendix", 1, self.styles['normal']),
        ]
        
        # Add TOC entries
        for text, level, style in toc_entries:
            # Add left padding based on level
            left_padding = (level - 1) * 10
            style = ParagraphStyle(
                'TOC_Level_' + str(level),
                parent=style,
                leftIndent=left_padding,
                firstLineIndent=-left_padding,
                spaceAfter=4
            )
            
            # Create a paragraph with a dot leader and page number
            p = Paragraph(f"{text} <tocadd page='{text}'/>", style)
            self.elements.append(p)
        
        # Add page break
        self.elements.append(PageBreak())
    
    def _add_executive_summary(self, scan_data: Dict[str, Any]) -> None:
        """Add an executive summary to the report."""
        # Add section title
        title = Paragraph("1. Executive Summary", self.styles['heading1'])
        self.elements.append(title)
        self.elements.append(Spacer(1, 12))
        
        # Add introduction
        intro_text = """
        This report presents the findings of a security assessment conducted on the 
        target system(s). The assessment was performed using CyberSentinel, a 
        comprehensive vulnerability scanning tool.
        """
        
        intro = Paragraph(intro_text, self.styles['normal'])
        self.elements.append(intro)
        self.elements.append(Spacer(1, 12))
        
        # Add summary statistics
        if 'summary' in scan_data:
            summary = scan_data['summary']
            severity_counts = summary.get('severity_counts', {})
            
            # Create a table for the summary statistics
            stats_data = [
                ["Severity", "Count", "Description"],
                [
                    self._get_severity_text("Critical"), 
                    str(severity_counts.get('critical', 0)),
                    "Critical vulnerabilities that pose an immediate risk and should be addressed immediately."
                ],
                [
                    self._get_severity_text("High"), 
                    str(severity_counts.get('high', 0)),
                    "High-risk vulnerabilities that should be addressed as soon as possible."
                ],
                [
                    self._get_severity_text("Medium"), 
                    str(severity_counts.get('medium', 0)),
                    "Medium-risk vulnerabilities that should be addressed in a timely manner."
                ],
                [
                    self._get_severity_text("Low"), 
                    str(severity_counts.get('low', 0)),
                    "Low-risk vulnerabilities that should be reviewed and addressed when possible."
                ],
                [
                    self._get_severity_text("Info"), 
                    str(severity_counts.get('info', 0)),
                    "Informational findings that do not represent a direct vulnerability."
                ],
            ]
            
            # Create the table
            stats_table = Table(stats_data, colWidths=[100, 50, 300])
            
            # Apply styles
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ]
            
            # Add severity-specific text colors
            for i in range(1, 6):
                table_style.append(('TEXTCOLOR', (0, i), (0, i), self._get_severity_color(stats_data[i][0])))
            
            stats_table.setStyle(TableStyle(table_style))
            
            self.elements.append(stats_table)
            self.elements.append(Spacer(1, 12))
        
        # Add conclusion
        conclusion_text = """
        The following sections of this report provide detailed information about each 
        finding, including descriptions, risk ratings, and recommended remediation steps.
        """
        
        conclusion = Paragraph(conclusion_text, self.styles['normal'])
        self.elements.append(conclusion)
        
        # Add page break
        self.elements.append(PageBreak())
    
    def _add_detailed_findings(self, scan_data: Dict[str, Any]) -> None:
        """Add detailed findings to the report."""
        # Add section title
        title = Paragraph("2. Detailed Findings", self.styles['heading1'])
        self.elements.append(title)
        self.elements.append(Spacer(1, 12))
        
        # Check if there are any findings
        findings = scan_data.get('findings', [])
        if not findings:
            no_findings = Paragraph("No security findings were identified during this scan.", 
                                  self.styles['normal'])
            self.elements.append(no_findings)
            self.elements.append(PageBreak())
            return
        
        # Group findings by severity (critical, high, medium, low, info)
        severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
        grouped_findings = {sev: [] for sev in severity_order}
        
        for finding in findings:
            severity = str(finding.get('severity', 'unknown')).lower()
            if severity not in grouped_findings:
                severity = 'unknown'
            grouped_findings[severity].append(finding)
        
        # Add findings by severity
        for severity in severity_order:
            sev_findings = grouped_findings.get(severity, [])
            if not sev_findings:
                continue
            
            # Add severity section
            sev_title = f"{severity.capitalize()} Severity Findings"
            sev_heading = Paragraph(sev_title, self.styles['heading2'])
            self.elements.append(sev_heading)
            self.elements.append(Spacer(1, 8))
            
            # Add each finding
            for i, finding in enumerate(sev_findings, 1):
                self._add_finding(finding, i)
                self.elements.append(Spacer(1, 12))
            
            # Add page break between severity groups
            self.elements.append(PageBreak())
    
    def _add_finding(self, finding: Dict[str, Any], finding_number: int) -> None:
        """Add a single finding to the report."""
        # Get finding details
        finding_id = finding.get('id', f"FND-{finding_number:03d}")
        title = finding.get('title', 'Untitled Finding')
        severity = str(finding.get('severity', 'unknown')).capitalize()
        description = finding.get('description', 'No description provided.')
        impact = finding.get('impact', 'Not specified.')
        recommendation = finding.get('recommendation', 'No recommendation provided.')
        
        # Add finding header
        header_style = self.styles.get(f'finding_severity_{severity.lower()}', 
                                     self.styles['finding_severity_unknown'])
        
        header_text = f"{finding_id}: {title}"
        header = Paragraph(header_text, header_style)
        self.elements.append(header)
        
        # Add severity badge
        severity_style = ParagraphStyle(
            'severity_badge_' + severity.lower(),
            parent=self.styles['small'],
            textColor=colors.white,
            backColor=self._get_severity_color(severity),
            alignment=TA_CENTER,
            borderWidth=1,
            borderColor=self._get_severity_color(severity, darken=0.2),
            borderRadius=3,
            padding=(6, 2, 6, 2)
        )
        
        severity_badge = Table([
            [f"Severity: {severity}"]
        ], colWidths=[100])
        
        severity_badge.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), self._get_severity_color(severity)),
            ('TEXTCOLOR', (0, 0), (0, 0), colors.white),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, 0), 8),
            ('ALIGN', (0, 0), (0, 0), 'CENTER'),
            ('BORDERCOLOR', (0, 0), (0, 0), self._get_severity_color(severity, darken=0.2)),
            ('BOTTOMPADDING', (0, 0), (0, 0), 2),
            ('TOPPADDING', (0, 0), (0, 0), 2),
            ('LEFTPADDING', (0, 0), (0, 0), 4),
            ('RIGHTPADDING', (0, 0), (0, 0), 4),
            ('VALIGN', (0, 0), (0, 0), 'MIDDLE'),
        ]))
        
        # Create a table to hold the severity badge
        badge_table = Table([
            [severity_badge, '']
        ], colWidths=[100, None])
        
        badge_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        self.elements.append(badge_table)
        
        # Add description
        desc_heading = Paragraph("<b>Description:</b>", self.styles['bold'])
        desc_content = Paragraph(description, self.styles['normal'])
        
        self.elements.append(desc_heading)
        self.elements.append(Spacer(1, 4))
        self.elements.append(desc_content)
        self.elements.append(Spacer(1, 8))
        
        # Add impact
        impact_heading = Paragraph("<b>Impact:</b>", self.styles['bold'])
        impact_content = Paragraph(impact, self.styles['normal'])
        
        self.elements.append(impact_heading)
        self.elements.append(Spacer(1, 4))
        self.elements.append(impact_content)
        self.elements.append(Spacer(1, 8))
        
        # Add recommendation
        rec_heading = Paragraph("<b>Recommendation:</b>", self.styles['bold'])
        rec_content = Paragraph(recommendation, self.styles['normal'])
        
        self.elements.append(rec_heading)
        self.elements.append(Spacer(1, 4))
        self.elements.append(rec_content)
        
        # Add evidence if available
        if 'evidence' in finding:
            evidence_heading = Paragraph("<b>Evidence:</b>", self.styles['bold'])
            evidence_content = Paragraph(finding['evidence'], self.styles['normal'])
            
            self.elements.append(Spacer(1, 8))
            self.elements.append(evidence_heading)
            self.elements.append(Spacer(1, 4))
            self.elements.append(evidence_content)
        
        # Add references if available
        if 'references' in finding and finding['references']:
            refs_heading = Paragraph("<b>References:</b>", self.styles['bold'])
            self.elements.append(Spacer(1, 8))
            self.elements.append(refs_heading)
            self.elements.append(Spacer(1, 4))
            
            refs = finding['references']
            if isinstance(refs, str):
                refs = [refs]
            
            ref_items = []
            for ref in refs:
                ref_items.append(Paragraph(f"• {ref}", self.styles['normal']))
            
            self.elements.extend(ref_items)
    
    def _add_scan_details(self, scan_data: Dict[str, Any]) -> None:
        """Add scan details to the report."""
        # Add section title
        title = Paragraph("3. Scan Details", self.styles['heading1'])
        self.elements.append(title)
        self.elements.append(Spacer(1, 12))
        
        # Create a table for scan metadata
        scan_metadata = [
            ["Scan ID:", scan_data.get('scan_id', 'N/A')],
            ["Target:", scan_data.get('target', 'N/A')],
            ["Scan Type:", scan_data.get('scan_type', 'N/A')],
            ["Start Time:", self._format_timestamp(scan_data.get('start_time'))],
            ["End Time:", self._format_timestamp(scan_data.get('end_time'))],
            ["Duration:", self._format_duration(scan_data.get('duration_seconds'))],
            ["Scanner Version:", scan_data.get('scanner_version', 'N/A')],
        ]
        
        # Add scan parameters if available
        if 'parameters' in scan_data and scan_data['parameters']:
            for key, value in scan_data['parameters'].items():
                scan_metadata.append([f"{key}:", str(value)])
        
        # Create the table
        scan_table = Table(scan_metadata, colWidths=[150, None])
        
        # Apply styles
        scan_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (0, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        
        self.elements.append(scan_table)
        
        # Add page break
        self.elements.append(PageBreak())
    
    def _add_appendix(self, scan_data: Dict[str, Any]) -> None:
        """Add an appendix to the report."""
        # Add section title
        title = Paragraph("4. Appendix", self.styles['heading1'])
        self.elements.append(title)
        self.elements.append(Spacer(1, 12))
        
        # Add glossary
        glossary_title = Paragraph("Glossary", self.styles['heading2'])
        self.elements.append(glossary_title)
        self.elements.append(Spacer(1, 8))
        
        glossary_items = [
            ["Critical", "Vulnerabilities that pose an immediate risk and should be addressed immediately."],
            ["High", "High-risk vulnerabilities that should be addressed as soon as possible."],
            ["Medium", "Medium-risk vulnerabilities that should be addressed in a timely manner."],
            ["Low", "Low-risk vulnerabilities that should be reviewed and addressed when possible."],
            ["Info", "Informational findings that do not represent a direct vulnerability."],
        ]
        
        # Create the glossary table
        glossary_table = Table(glossary_items, colWidths=[100, None])
        
        # Apply styles
        glossary_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (0, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ]))
        
        self.elements.append(glossary_table)
        self.elements.append(Spacer(1, 20))
        
        # Add disclaimer
        disclaimer_title = Paragraph("Disclaimer", self.styles['heading2'])
        self.elements.append(disclaimer_title)
        self.elements.append(Spacer(1, 8))
        
        disclaimer_text = """
        This report is provided for informational purposes only. The information contained in this 
        report is based on the results of automated scanning tools and may contain inaccuracies. 
        The findings should be reviewed and validated by a qualified security professional before 
        taking any remedial action. The authors of this report are not responsible for any damages 
        or liabilities arising from the use of this information.
        """
        
        disclaimer = Paragraph(disclaimer_text, self.styles['normal'])
        self.elements.append(disclaimer)
        
        # Add page break
        self.elements.append(PageBreak())
    
    def _format_timestamp(self, timestamp: Any) -> str:
        """Format a timestamp for display."""
        if not timestamp:
            return 'N/A'
        
        try:
            # Try parsing ISO format
            if isinstance(timestamp, str):
                if 'T' in timestamp and 'Z' in timestamp.upper():
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = datetime.fromisoformat(timestamp)
            elif hasattr(timestamp, 'isoformat'):
                dt = timestamp
            else:
                return str(timestamp)
            
            return dt.strftime('%Y-%m-%d %H:%M:%S %Z')
        except (ValueError, TypeError):
            return str(timestamp)
    
    def _format_duration(self, seconds: Optional[float]) -> str:
        """Format a duration in seconds as a human-readable string."""
        if seconds is None:
            return 'N/A'
        
        try:
            seconds = float(seconds)
            hours, remainder = divmod(seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            
            parts = []
            if hours > 0:
                parts.append(f"{int(hours)}h")
            if minutes > 0 or hours > 0:
                parts.append(f"{int(minutes)}m")
            parts.append(f"{seconds:.1f}s")
            
            return ' '.join(parts)
        except (ValueError, TypeError):
            return str(seconds)
    
    def _get_severity_text(self, severity: str) -> str:
        """Get formatted text for a severity level."""
        severity = str(severity).lower()
        color = self._get_severity_color(severity)
        
        # Create a colored bullet point
        return f"<font color='{color}'>•</font> {severity.capitalize()}"
    
    @staticmethod
    def _get_severity_color(severity: str, darken: float = 1.0) -> colors.Color:
        """Get the color for a severity level."""
        severity = str(severity).lower()
        
        severity_colors = {
            'critical': colors.HexColor('#e74c3c'),  # Red
            'high': colors.HexColor('#e67e22'),      # Orange
            'medium': colors.HexColor('#f39c12'),    # Yellow-Orange
            'low': colors.HexColor('#3498db'),       # Blue
            'info': colors.HexColor('#2ecc71'),      # Green
            'unknown': colors.HexColor('#7f8c8d')    # Grey
        }
        
        color = severity_colors.get(severity, colors.HexColor('#7f8c8d'))
        
        # Darken the color if requested
        if darken != 1.0:
            r = min(1.0, max(0.0, color.red * darken))
            g = min(1.0, max(0.0, color.green * darken))
            b = min(1.0, max(0.0, color.blue * darken))
            return colors.Color(r, g, b)
        
        return color
    
    @classmethod
    def from_scan_result(cls, scan_result: Any, **kwargs) -> 'PDFReportGenerator':
        """
        Create a PDF report generator from a scan result object.
        
        This is a convenience method that extracts the relevant data from
        a scan result object and creates a new PDFReportGenerator instance.
        
        Args:
            scan_result: A scan result object (e.g., from NmapScanner, SSLChecker, etc.).
            **kwargs: Additional arguments to pass to the PDFReportGenerator constructor.
            
        Returns:
            A new PDFReportGenerator instance.
        """
        # Extract data from scan result based on its type
        if hasattr(scan_result, 'to_dict'):
            scan_data = scan_result.to_dict()
        elif hasattr(scan_result, '__dict__'):
            scan_data = vars(scan_result)
        elif isinstance(scan_result, dict):
            scan_data = scan_result
        else:
            raise ValueError(f"Unsupported scan result type: {type(scan_result).__name__}")
        
        # Create a new instance with the extracted data
        generator = cls(**kwargs)
        generator.scan_data = scan_data
        return generator
