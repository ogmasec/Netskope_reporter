import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors

class PDFGenerator:
    def __init__(self, file_name):
        self.file_name = file_name
        self.document = SimpleDocTemplate(self.file_name, pagesize=letter)
        
    def generate_pdf(self, data):
        table_data = [
            ["Timestamp", "Incident ID", "DLP Rule Name", "DLP Rule Score", "DLP Rule Severity", "Activity"]
        ]  # Header row
        
        for item in data:
            dlp_rules = item.get("dlp_rules", [])
            dlp_rule = dlp_rules[0] if dlp_rules else {}
            row = [
                item.get("Date (converted)", ""),
                item.get("dlp_incident_id", ""),
                dlp_rule.get("dlp_rule_name", ""),
                str(dlp_rule.get("dlp_rule_score", "")),
                dlp_rule.get("dlp_rule_severity", ""),
                item.get("activity", "")
            ]
            table_data.append(row)
        
        table = Table(table_data, colWidths=[100, 100, 150, 80, 100, 100])
        table.setStyle(TableStyle([
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.orange),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
        ]))
        
        elements = [table]
        self.document.build(elements)

        df = pd.DataFrame(table_data)
        print(df)

