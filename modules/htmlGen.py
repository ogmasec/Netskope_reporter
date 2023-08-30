class HTMLGenerator:
    def __init__(self, file_name, columns):
        self.file_name = file_name
        self.columns = columns
        self.data = []

    def add_data(self, **kwargs):
        self.data.append(kwargs)

    def generate_html(self):
        with open(self.file_name, "w") as f:
            f.write("<html><head><style>")
            f.write("table {border-collapse: collapse; width: 100%;}")
            f.write("th, td {border: 1px solid black; padding: 8px; text-align: center;}")
            f.write("th {background-color: orange;}")
            f.write("</style></head><body>")
            f.write("<h2>Data Report</h2>")
            f.write("<table>")
            f.write("<tr>")
            
            for column in self.columns:
                f.write(f"<th>{column}</th>")
            
            f.write("</tr>")
            
            for item in self.data:

                f.write("<tr>")
                for key, value in item.items():
                    f.write(f"<td>{value}</td>")
                f.write("</tr>")
            
            f.write("</table>")
            f.write("</body></html>")