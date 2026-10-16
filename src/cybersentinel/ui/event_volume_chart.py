"""Native Qt histogram of stored event counts, including empty hours."""
from PyQt5.QtCore import Qt, QRectF
from PyQt5.QtGui import QPainter, QColor, QFont
from PyQt5.QtWidgets import QWidget


class EventVolumeChart(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.points = []
        self.setMinimumHeight(180)

    def set_points(self, points):
        self.points = points
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor('#142237'))
        painter.setPen(QColor('#c5d8eb'))
        painter.drawText(16, 24, 'EVENT VOLUME / Latest 24 hours of stored event time (UTC)')
        if not self.points:
            painter.drawText(self.rect(), Qt.AlignCenter, 'No events imported — no activity data to chart')
            return
        left, top, height = 40, 48, max(30, self.height() - 82)
        width = max(100, self.width() - 65)
        maximum = max(1, max(value for _, value in self.points))
        step = width / len(self.points)
        painter.setPen(QColor('#58718d'))
        painter.drawLine(left, top + height, left + width, top + height)
        for index, (hour, count) in enumerate(self.points):
            bar_height = height * count / maximum
            painter.fillRect(QRectF(left + index * step + 2, top + height - bar_height, max(2, step - 4), bar_height), QColor('#59cbb9'))
        painter.setPen(QColor('#c5d8eb'))
        painter.drawText(5, top + 8, str(maximum))
        painter.drawText(left, self.height() - 10, self.points[0][0].replace('T', ' ') + ':00')
        painter.drawText(max(left, self.width() - 170), self.height() - 10, self.points[-1][0].replace('T', ' ') + ':00')
