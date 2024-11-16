#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QStackedWidget>
#include <QPushButton>
#include <QMap>
#include <QLineEdit>
#include <QLabel>
#include <QColor>

#include <memory>
#include "cryptoutils.h"
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void printLog(const QString& msg, const QColor& color = Qt::black);
private:
    void setupConnections(QStackedWidget *stackedWidget, const QMap<QPushButton *, int> &buttons);
    QString toHex(const unsigned char* data, int len);
private slots:
    void updateLineEeditLeng(const QString &text);
    
    void on_btn_MakeCert_clicked();

    void on_btn_RSARemovePadding_clicked();

    void on_btn_RSAPubDec_clicked();

    void on_btn_ComputeHash_clicked();

    void on_btn_RsaVetify_clicked();

    void on_btn_ParseP10_clicked();

    void on_btn_VerifyP10_clicked();

    void on_btn_HexToBase64_clicked();

    void on_btn_Base64ToHex_clicked();

    void on_btn_sm2Verify_clicked();

    void on_checkBox_no_zvalue_stateChanged(int arg1);

    void on_btn_clear_log_clicked();

    void on_btn_StringToHex_clicked();

private:
    Ui::MainWindow *ui;
    CryptoUtils* m_cryptoUtilsInstance;
    QMap<QLineEdit*, QLabel*> m_lengthLineEditMap;
};

#endif // MAINWINDOW_H
