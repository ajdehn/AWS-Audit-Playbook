from datetime import datetime, timezone
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, LETTER
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, ListFlowable, ListItem, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

BASE_STYLES = getSampleStyleSheet()

# Define style constants
LABEL_STYLE = ParagraphStyle(name="Label", fontSize=9, fontName="Helvetica-Bold")
VALUE_STYLE = ParagraphStyle(name="Value", fontSize=9, fontName="Helvetica")
LARGE_VALUE_STYLE = ParagraphStyle(name ='LargeValue', parent=VALUE_STYLE, fontSize=11, leading=15,spaceAfter=2)
LIST_STYLE = ParagraphStyle(name="List", parent=VALUE_STYLE, spaceAfter=6)
CENTER_STYLE = ParagraphStyle(name="Center", parent=VALUE_STYLE, alignment=1)
HEADER_BG = colors.lightgrey
PASS_COLOR = "green"
FAIL_COLOR = "red"
# Highlight first row of table.
TABLE_STYLE_HIGHLIGHT_ROW = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ])

# Highlight first row of table.
TABLE_STYLE_HIGHLIGHT_COLUMN = TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.black),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 6),
    ])

def format_count_with_pct(count, total):
    if total == 0:
        return f"{count} (0%)"
    pct = (count / total) * 100
    return f"{count} ({pct:.1f}%)"

"""
    Build first page of the audit report.
"""
def render_audit_cover_page(audit, tool_name, styles, tests):
    elements = []
    # Header and audit metadata
    elements.append(Paragraph(f"{tool_name} Audit Report", styles["Title"]))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph("Audit Summary", styles["Heading1"]))
    elements.append(Spacer(1, 12))

    # TODO: Consider adding transparency for excluded tests from JSON file.
    date_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    total = len(tests)
    failed = sum(1 for t in tests if not t.is_passing)
    passed = total - failed

    audit_metadata = [
        [Paragraph("Prepared By", LABEL_STYLE), Paragraph("AJ Dehn", VALUE_STYLE)], 
        [Paragraph("Date", LABEL_STYLE), Paragraph(str(date_str), VALUE_STYLE)],
        [Paragraph("AWS Account ID", LABEL_STYLE), Paragraph(str(audit.aws_account_id), VALUE_STYLE)],
        [Paragraph("Number of tests", LABEL_STYLE), Paragraph(str(total), VALUE_STYLE)], 
        [Paragraph("Passed", LABEL_STYLE), Paragraph(format_count_with_pct(passed, total), VALUE_STYLE)],
        [Paragraph("Failed", LABEL_STYLE), Paragraph(format_count_with_pct(failed, total), VALUE_STYLE)],
    ]

    audit_metadata_table = Table(audit_metadata, colWidths=[150, 100], hAlign="LEFT")
    audit_metadata_table.setStyle(TABLE_STYLE_HIGHLIGHT_COLUMN)
    elements.append(audit_metadata_table)
    elements.append(Spacer(1, 24))


    # --- Disclaimers Section ---
    elements.append(Paragraph("Notes / Disclaimers", styles["Heading1"]))
    elements.append(Spacer(1, 8))

    disclaimers_list = ListFlowable(
        [
            ListItem(Paragraph("This report was generated using the AWS Audit Playbook (https://github.com/ajdehn/AWS-Audit-Playbook).", LARGE_VALUE_STYLE)),
            ListItem(Paragraph("Evidence used to conduct the audit was gathered directly from boto3 (AWS software development kit 'SDK' for Python).", LARGE_VALUE_STYLE)),
            ListItem(Paragraph("Please review src/aws_tests.py for additional information on how evidence was gathered and testing was performed.", LARGE_VALUE_STYLE)),
            ListItem(Paragraph(f"Evidence used to produce this audit was gathered on {date_str}. Configurations may have changed since this report was generated.", LARGE_VALUE_STYLE))
        ],
        bulletType='bullet', bulletFontSize=11
)    

    elements.append(disclaimers_list)
    elements.append(Spacer(1, 8))
    elements.append(PageBreak())

    return elements

"""
    Render 2-column test summary table.
"""
def render_test_summary(test, page_width):
    test_procedures = [
        Paragraph(f"{i+1}. {item}", LIST_STYLE)
        for i, item in enumerate(test.test_procedures)
    ]
    test_attributes = [
        Paragraph(f"• {item}", LIST_STYLE)
        for item in test.test_attributes
    ]

    # Conclusion
    conclusion = Paragraph(
        f"<font color='{PASS_COLOR if test.is_passing else FAIL_COLOR}'><b>{'Pass' if test.is_passing else 'Fail'}</b></font>",
        VALUE_STYLE
    )
    
    # Build summary table
    table_data = [
        [Paragraph("Test ID", LABEL_STYLE), Paragraph(test.test_id, VALUE_STYLE)], 
        [Paragraph("Test Description", LABEL_STYLE), Paragraph(test.test_description, VALUE_STYLE)],
        [Paragraph("Risk Rating", LABEL_STYLE), Paragraph(test.risk_rating_str, VALUE_STYLE)],
        [Paragraph("Test Procedures", LABEL_STYLE), test_procedures], 
        [Paragraph("Conclusion", LABEL_STYLE), conclusion],
    ]

    if test_attributes:
        # Add test attributes only when populated.
        table_data.insert(4, [Paragraph("Test Attributes", LABEL_STYLE), test_attributes])

    # Add row to summary table if test failed and comments is populated.
    if not test.is_passing and test.comments:
        table_data.append([Paragraph("Comments", LABEL_STYLE), Paragraph(test.comments, VALUE_STYLE)])

    table_width = page_width - 2 * 72
    table = Table(table_data, colWidths=[table_width * 0.25, table_width * 0.75])
    table.setStyle(TABLE_STYLE_HIGHLIGHT_COLUMN)

    return table

"""
    Render sample table (if present).
"""
def render_sample_table(test, page_width):
    if not test.table_headers:
        return None

    # Sort failing samples to top of the table.
    test.samples = sorted(test.samples, key=lambda s: (s.is_passing))

    table_data = []
    # Header row
    table_data.append([
        Paragraph(h, LABEL_STYLE) for h in test.table_headers
    ])
    for i, sample in enumerate(test.samples, 1):
        row = []
        if test.include_sample_number:
            row.append(Paragraph(str(i), CENTER_STYLE))
        row.extend([
            Paragraph(str(v), VALUE_STYLE)
            for v in sample.sample_id.values()
        ])

        # Document Result
        if not sample.is_excluded:
            result_text = "Pass" if sample.is_passing else "Fail"
            result_color = PASS_COLOR if sample.is_passing else FAIL_COLOR
            row.append(Paragraph(f"<font color='{result_color}'>{result_text}</font>", CENTER_STYLE))
        else:
            sample.is_passing = False
            row.append(Paragraph("Excluded", CENTER_STYLE))

        if not sample.is_passing:
            # Add comments if sample failed.
            row.append(Paragraph(str(sample.comments), VALUE_STYLE))

        table_data.append(row)

    table_width = page_width - 2 * 72
    col_width = table_width / len(table_data[0]) # divide evenly across columns
    col_widths = [col_width] * len(table_data[0])
    table = Table(table_data, colWidths=col_widths)
    table.setStyle(TABLE_STYLE_HIGHLIGHT_ROW)

    return table

"""Build summary elements with pass/fail counts."""
def render_summary_page(tests, styles):
    elements = []

    elements.append(Paragraph("Test Summary", styles["Heading1"]))
    elements.append(Spacer(1, 12))

    test_summary_data = []
    # Header row
    test_summary_data.append([
        Paragraph("Test Description", LABEL_STYLE), Paragraph("Results", LABEL_STYLE), 
        Paragraph("Risk Level", LABEL_STYLE),  Paragraph("Comments", LABEL_STYLE)
    ])
    # Detailed Findings
    for test in tests:
        row = []
        row.append(Paragraph(str(test.test_description), VALUE_STYLE))
        test_result = "Pass" if test.is_passing else "Fail"
        result_color = PASS_COLOR if test.is_passing else FAIL_COLOR
        row.append(Paragraph(f"<font color='{result_color}'>{test_result}</font>", VALUE_STYLE))
        row.append(Paragraph(str(test.risk_rating_str), VALUE_STYLE))
        row.append(Paragraph(test.comments, VALUE_STYLE))
        
        test_summary_data.append(row)

    test_summary_table = Table(test_summary_data, colWidths=[200, 75, 75, 125])
    test_summary_table.setStyle(TABLE_STYLE_HIGHLIGHT_ROW)
    elements.append(test_summary_table)
    return elements


"""
Build audit report summarizing findings.

Structure:
    1. Cover Page
    2. Test Summary Results
    3. Detailed Test Findings
        - Optional: Sample Table
"""
def generate_pdf_report(audit, tests, tool_name, file_name="tmp/audit_report.pdf"):

    # Sort by failing tests, and then by risk rating.
    tests = sorted(tests, key=lambda c: (c.is_passing, -c.risk_rating))

    doc = SimpleDocTemplate(file_name, pagesize=letter,
    title=f"{tool_name} Audit Report", author="AJ Dehn", subject=f"Summarizes audit findings from {tool_name}")
    styles = getSampleStyleSheet()
    page_width, _ = LETTER
    elements = []

    elements.extend(render_audit_cover_page(audit, tool_name, styles, tests))

    # Summary Page
    elements.extend(render_summary_page(tests, styles))
    elements.append(PageBreak())

    # Detailed Findings
    for test in tests:
        summary_table = render_test_summary(test, page_width)
        elements.append(KeepTogether(summary_table))
        elements.append(Spacer(1, 16))
        sample_table = render_sample_table(test, page_width)
        if sample_table:
            elements.append(KeepTogether(sample_table))
            # Create new page if test includes sample table.
            elements.append(PageBreak())
        else:
            elements.append(Spacer(1, 30))

    doc.build(elements)
    print(f"Report generated: {file_name}")


def parse_dt(dt_str):
    if not dt_str:
        return None
    return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))