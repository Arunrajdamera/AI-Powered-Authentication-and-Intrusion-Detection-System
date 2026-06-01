import csv
from io import StringIO
from typing import Iterable


class ReportService:
    @staticmethod
    def rows_to_csv(headers: list[str], rows: Iterable[Iterable[object]]) -> str:
        buffer = StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(headers)
        for row in rows:
            writer.writerow(["" if value is None else value for value in row])
        return buffer.getvalue()
