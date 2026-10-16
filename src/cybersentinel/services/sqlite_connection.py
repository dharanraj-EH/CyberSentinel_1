"""SQLite transaction context that also releases Windows file handles."""
import sqlite3


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *exception):
        try:
            return super().__exit__(*exception)
        finally:
            self.close()
