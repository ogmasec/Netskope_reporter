from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib import colors

class PDFGenerator:
    def __init__(self, filename):
        self.filename = filename
        self.document = SimpleDocTemplate(filename, pagesize=letter)

    def generate_pdf(self, data):
        table_data = [
            #["Timestamp", "Date (converted)", "_id", "Alert Name", "Alert Type", "DLP Rule", "Policy"]
            ["Date", "Alert Name", "Alert Type"]
        ]  # Header row

        for item in data:
            row = [
                #item.get("timestamp", ""),
                item.get("Date (converted)", ""),
                #item.get("_id", ""),
                item.get("alert_name", ""),
                item.get("alert_type", "")
                #item.get("dlp_rule", ""),
                #item.get("policy", ""),
            ]
            table_data.append(row)

        table = Table(table_data, colWidths=[None] * 3)
        table.setStyle(TableStyle([
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('INNERGRID', (0, 0), (-1, -1), 0.25, colors.black),
            ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
        ]))

        # Automatically adjust row heights based on content
        row_heights = []
        for row_idx in range(len(table_data)):
            row_height = max([table_data[row_idx][col_idx] for col_idx in range(3)], key=lambda cell: len(str(cell)))
            row_heights.append(row_height)

        table.setStyle(TableStyle([
            ('ROWHEIGHT', (0, 0), (-1, -1), row_heights),
        ]))

        elements = [table]
        self.document.build(elements)
