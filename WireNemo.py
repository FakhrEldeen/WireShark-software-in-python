# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'WireNemo.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(800, 600)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.filter_le = QtWidgets.QLineEdit(self.centralwidget)
        self.filter_le.setObjectName("filter_le")
        self.horizontalLayout.addWidget(self.filter_le)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.capture_stop_btn = QtWidgets.QPushButton(self.centralwidget)
        self.capture_stop_btn.setObjectName("capture_stop_btn")
        self.horizontalLayout_2.addWidget(self.capture_stop_btn)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.all_txt_browser = QtWidgets.QTextBrowser(self.centralwidget)
        self.all_txt_browser.setObjectName("all_txt_browser")
        self.horizontalLayout_3.addWidget(self.all_txt_browser)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.header_txt_browser = QtWidgets.QTextBrowser(self.centralwidget)
        self.header_txt_browser.setObjectName("header_txt_browser")
        self.horizontalLayout_4.addWidget(self.header_txt_browser)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.hex_txt_browser = QtWidgets.QTextBrowser(self.centralwidget)
        self.hex_txt_browser.setObjectName("hex_txt_browser")
        self.horizontalLayout_5.addWidget(self.hex_txt_browser)
        self.verticalLayout.addLayout(self.horizontalLayout_5)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 800, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "WireNemo"))
        self.label.setText(_translate("MainWindow", "Enter Filter : "))
        self.capture_stop_btn.setText(_translate("MainWindow", "Capture"))
        self.capture_stop_btn.clicked.connect(self.btn_click)
       
    def btn_click(self):
        _translate = QtCore.QCoreApplication.translate
        self.capture_stop_btn.setText(_translate("MainWindow", "Stop"))
        self.all_txt_browser.setText(self.filter_le.text())



if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
