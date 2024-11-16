#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "configmanager.h"

#include <QByteArray>
#include <QDebug>

#include <iostream>
#include <cstring>
#include <memory>
#include <cstdio>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle("CryptoTool");
    QMap<QPushButton*, int>buttons;
    buttons[ui->btn_hash] = 0;
    buttons[ui->btn_SwitchP10Page] = 1;
    buttons[ui->btn_RSAVerify] = 2;
    buttons[ui->btn_SM2Verify] = 3;
    buttons[ui->btn_dataConversion] = 4;
    setupConnections(ui->stackedWidget,buttons);


    m_lengthLineEditMap.insert(ui->xLineEdit, ui->label_x_leng);
    m_lengthLineEditMap.insert(ui->yLineEdit, ui->label_y_leng);
    m_lengthLineEditMap.insert(ui->rLineEdit, ui->label_r_leng);
    m_lengthLineEditMap.insert(ui->sLineEdit, ui->label_s_leng);
    m_lengthLineEditMap.insert(ui->userIDLineEdit, ui->label_id_leng);

    for(auto it = m_lengthLineEditMap.begin(); it != m_lengthLineEditMap.end(); it++) {
        connect(it.key(), &QLineEdit::textChanged, this, &MainWindow::updateLineEeditLeng);
    }

    // 初始化RSA 哈希算法
    QMap<QString, int> mapHashType;
    mapHashType["SHA1"] = HASH_SHA1;
    mapHashType["SHA256"] = HASH_SHA256;
    mapHashType["SHA384"] = HASH_SHA384;
    mapHashType["SHA512"] = HASH_SHA512;
    mapHashType["MD5"] = HASH_MD5;
    mapHashType["SM3"] = HASH_SM3;
    ui->comboBox_rsa_sign_hash_type->clear();
    for(auto it = mapHashType.begin(); it != mapHashType.end(); it++) {
        ui->comboBox_rsa_sign_hash_type->addItem(it.key(), it.value());
    }

    // 使用ConfigManager读取配置文件
    ConfigManager configManager("config.ini");
    QString sm2PrivateKeyPath = configManager.getValue("Certificates/SM2PrivateKey");
    QString sm2CertPath = configManager.getValue("Certificates/SM2Cert");
    QString rsaPrivateKeyPath = configManager.getValue("Certificates/RSAPrivateKey");
    QString rsaCertPath = configManager.getValue("Certificates/RSACert");

    qDebug()<<"sm2PrivateKeyPath = " << sm2PrivateKeyPath << endl;
    qDebug()<<"sm2CertPath = " << sm2CertPath << endl;
    qDebug()<<"rsaPrivateKeyPath = " << rsaPrivateKeyPath << endl;
    qDebug()<<"rsaCertPath = " << rsaCertPath << endl;

    m_cryptoUtilsInstance = new CryptoUtils([this](const QString &msg, const QColor& color) { printLog(msg, color); });
    m_cryptoUtilsInstance->setCertPaths(sm2CertPath, sm2PrivateKeyPath, rsaCertPath, rsaPrivateKeyPath);
    
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::setupConnections(QStackedWidget *stackedWidget, const QMap<QPushButton *, int> &buttons)
{
    for(auto& button : buttons.keys()) {
        int index = buttons.value(button);
        connect(button, &QPushButton::clicked, [stackedWidget, index]() {
            stackedWidget->setCurrentIndex(index);
        });
    }
}

QString MainWindow::toHex(const unsigned char* data, int len)
{
    QByteArray hexData((const char* )data, len);
    return hexData.toHex().toUpper();
}

void MainWindow::updateLineEeditLeng(const QString &text) {
    // 获取发出信号的QLineEdit
    QLineEdit *senderLineEdit = qobject_cast<QLineEdit*>(sender());

    // 如果找到了对应的QLabel，则更新它的文本
    if (m_lengthLineEditMap.contains(senderLineEdit)) {
        QLabel *label = m_lengthLineEditMap.value(senderLineEdit);
        label->setText(QString::number(text.toStdWString().size()));
    }
}

void MainWindow::on_btn_MakeCert_clicked()
{
    printLog("\n================= 制证 =================");
    QString certReq = ui->textEdit_ReqData->toPlainText();
    if(certReq.isEmpty()) {
        printLog("CSR为空，请输入。", Qt::red);
        return;
    }
    bool isVerifyCsr = ui->radioButton_verify_csr->isChecked();
    char* cer = nullptr;
    m_cryptoUtilsInstance->MakeCert(certReq.toStdString().c_str(), &cer, isVerifyCsr);
    printLog(cer);
}

QString stringToBase64(const QString& input)
{
    QByteArray byteArray = input.toLocal8Bit();
    QByteArray base64ByteArray = byteArray.toBase64();
    return QString::fromUtf8(base64ByteArray);
}

QString stringToHex(const QString& input, char separator)
{
    QByteArray byteArray = input.toLocal8Bit();
    return byteArray.toHex().toUpper();
}

void MainWindow::on_btn_RSARemovePadding_clicked()
{
    QByteArray data = QByteArray::fromHex(ui->textEdit_RsaDecData->toPlainText().toLocal8Bit());
    if(data.isEmpty()) {
        return;
    }
    size_t outLen = 0;
    unsigned char* outData = m_cryptoUtilsInstance->remove_pkcs1_padding((const unsigned char*)data.data(), data.size(), &outLen);
    if(nullptr == outData) {
        return;
    }
    ui->textEdit_RsaDecData_2->setText(toHex(outData, outLen));
}

void MainWindow::on_btn_RSAPubDec_clicked()
{
    QByteArray rsaOriginalData = QByteArray::fromHex(ui->textEdit_RsaOriginalData->toPlainText().toLocal8Bit());
    QByteArray rsaCiphertextData = QByteArray::fromHex(ui->textEdit_RsaCiphertextData->toPlainText().toLocal8Bit());
    QByteArray N = QByteArray::fromHex(ui->textEdit_RSA_N->toPlainText().toLocal8Bit());
    QByteArray E = QByteArray::fromHex(ui->lineEdit_RSA_E->text().toLocal8Bit());

    EVP_PKEY *rsaPubKey = m_cryptoUtilsInstance->LoadRSAPublicKey((const unsigned char*)N.data(), N.size(), (const unsigned char*)E.data(), E.size());
    if(nullptr == rsaPubKey) {
        printLog("RSA 公钥加载失败", Qt::red);
        return;
    }
    size_t decDataLen = EVP_PKEY_get_bits(rsaPubKey) / 8 + 1;
    std::unique_ptr<unsigned char> decData(new unsigned char[decDataLen]);
    int rv = m_cryptoUtilsInstance->VerifyRecover(rsaPubKey, (const unsigned char*)rsaCiphertextData.data(), rsaCiphertextData.length(), decData.get(), &decDataLen);
    if(0 == rv) {
        ui->textEdit_RsaDecData->setText(toHex(decData.get(), decDataLen));
    }
}

void MainWindow::on_btn_ComputeHash_clicked()
{
    ui->lineEdit_HashData->clear();
    QString hashMsg = ui->comboBox_HashAlg->currentText();
    QByteArray data;
    if(ui->comboBox_HashDataFromat->currentText() == "HEX") {
         data = QByteArray::fromHex(ui->textEdit_input2HashData->toPlainText().toLocal8Bit());
    } else {
        data = ui->textEdit_input2HashData->toPlainText().toLocal8Bit();
    }
    unsigned char outHash[128] = {0};
    unsigned int outLen = sizeof(outHash)/sizeof(outHash[0]);
    int ret = m_cryptoUtilsInstance->Digest(hashMsg.toStdString().c_str(), (const unsigned char*)data.data(), data.size(), outHash, &outLen);
    if(0 == ret) {
        ui->lineEdit_HashData->setText(toHex(outHash, (int)outLen));
    } else {
        printLog("hash 计算失败", Qt::red);
    }
}

void MainWindow::on_btn_RsaVetify_clicked()
{
    QByteArray rsaOriginalData = QByteArray::fromHex(ui->textEdit_RsaOriginalData->toPlainText().toLocal8Bit());
    QByteArray rsaCiphertextData = QByteArray::fromHex(ui->textEdit_RsaCiphertextData->toPlainText().toLocal8Bit());
    QByteArray pubKeyData = QByteArray::fromHex(ui->textEdit_RSA_N->toPlainText().toLocal8Bit());


    const EVP_MD *hash_alg = nullptr;
    int hashAlg = ui->comboBox_rsa_sign_hash_type->currentData().toInt();
    switch (hashAlg) {
    case HASH_SHA1:
        hash_alg = EVP_sha1();
        break;
    case HASH_SHA256:
        hash_alg = EVP_sha256();
        break;
    case HASH_SHA384:
        hash_alg = EVP_sha384();
        break;
    case HASH_SHA512:
        hash_alg = EVP_sha512();
        break;
    case HASH_MD5:
        hash_alg = EVP_md5();
        break;
    case HASH_SM3:
        hash_alg = EVP_sm3();
        break;
    default:
        printLog("未知的哈希算法", Qt::red);
        return;
    }

    unsigned char pubEData[] = {0x01, 0x00, 0x01};
    EVP_PKEY *rsaPubKey = m_cryptoUtilsInstance->LoadRSAPublicKey((const unsigned char*)pubKeyData.data(), pubKeyData.size(), pubEData, 3);
    if(nullptr == rsaPubKey) {
        printLog("加载RSA公钥失败", Qt::red);
        return;
    }
    int rv = m_cryptoUtilsInstance->DigestVerify(rsaPubKey, hash_alg, (const unsigned char*)rsaCiphertextData.data(),
    rsaCiphertextData.length(), (const unsigned char*)rsaOriginalData.data(),
     rsaOriginalData.length(), nullptr, 0);
    if(1 == rv) {
        ui->label_10->setText("验签成功");
    } else {
        ui->label_10->setText("验签失败");
    }
}

void MainWindow::on_btn_ParseP10_clicked()
{
    printLog("\n================= 解析CSR =================");
    QString CSR = ui->textEdit_ReqData->toPlainText();
    if(CSR.isEmpty()) {
        printLog("CSR为空，请输入。", Qt::red);
        return;
    }
    m_cryptoUtilsInstance->ParseP10((const unsigned char*)CSR.toStdString().c_str(), CSR.size());
}

void MainWindow::on_btn_VerifyP10_clicked()
{
    printLog("\n================= 验证CSR =================");
    QString CSR = ui->textEdit_ReqData->toPlainText();
    if(CSR.isEmpty()) {
        printLog("CSR为空，请输入。", Qt::red);
        return;
    }
    int rv = m_cryptoUtilsInstance->CertReqVerify(CSR.toStdString().c_str(), CSR.size());
    if(1 == rv) {
        printLog("CSR验签成功", Qt::green);
    } else {
        printLog("CSR验签失败", Qt::red);
    }
}

bool isValidHex(const QString &data)
{
    if (data.length() % 2 != 0) {
        return false;
    }
    QRegularExpression regex("^[A-Fa-f0-9]*$");
    return regex.match(data).hasMatch();
}

bool isValidBase64(const QString &data)
{
    if (data.length() % 4 != 0) {
        return false;
    }
    QRegularExpression regex("^[A-Za-z0-9+/]*={0,2}$");
    return regex.match(data).hasMatch();
}

void MainWindow::on_btn_HexToBase64_clicked()
{
    QByteArray inputData = ui->dataConversionInput->toPlainText().toLocal8Bit();
    if(!isValidHex(inputData)) {
        ui->dataConversionOutput->setText("输入的数据无效");
        return;
    }
    inputData = QByteArray::fromHex(inputData);
    QByteArray outputData = inputData.toBase64();
    ui->dataConversionOutput->setText(outputData);
}

void MainWindow::on_btn_Base64ToHex_clicked()
{
    QByteArray inputData = ui->dataConversionInput->toPlainText().toLocal8Bit();
    if(!isValidBase64(inputData)) {
        ui->dataConversionOutput->setText("输入的数据无效");
        return;
    }
    inputData = QByteArray::fromBase64(inputData);
    QByteArray outputData = inputData.toHex();
    ui->dataConversionOutput->setText(outputData);
}

void MainWindow::on_btn_sm2Verify_clicked()
{
    QByteArray originalData = ui->textEdit_3->toPlainText().toLocal8Bit();
    QByteArray userId = QByteArray::fromHex(ui->userIDLineEdit->text().toLocal8Bit());
    QByteArray x = QByteArray::fromHex(ui->xLineEdit->text().toLocal8Bit());
    QByteArray y = QByteArray::fromHex(ui->yLineEdit->text().toLocal8Bit());
    QByteArray r = QByteArray::fromHex(ui->rLineEdit->text().toLocal8Bit());
    QByteArray s = QByteArray::fromHex(ui->sLineEdit->text().toLocal8Bit());

    printLog("\n================= SM2验签 =================");

    EVP_PKEY* pkey = m_cryptoUtilsInstance->LoadSM2PublicKey((const unsigned char*)x.data(), x.size(),
                        (const unsigned char*)y.data(), y.size());
    if(nullptr == pkey) {
        printLog("加载SM2公钥失败", Qt::red);
        return;
    }

    int derSize = 0;
    std::unique_ptr<unsigned char[]> der(nullptr);
    int ret = m_cryptoUtilsInstance->sm2_sig_toder((const unsigned char*)r.data(), r.size(),
                                                 (const unsigned char*)s.data(), s.size(), der.get(), &derSize);
    if(0 != ret || derSize < 0) {
        printLog("sm2_sig_toder err", Qt::red);
        return;
    }
    der.reset(new unsigned char[derSize + 1]);
    memset(der.get(), 0, derSize + 1);
    ret = m_cryptoUtilsInstance->sm2_sig_toder((const unsigned char*)r.data(), r.size(),
                                                 (const unsigned char*)s.data(), s.size(), der.get(), &derSize);
    if(0 != ret || derSize < 0) {
        printLog("sm2_sig_toder err", Qt::red);
        return;
    }

    // 判断原文是否为16进制字符串
    if(ui->checkBox_hex_data->isChecked()) {
        originalData = QByteArray::fromHex(originalData);
    }
    printLog("签名值(DER):");
    printLog(toHex(der.get(), derSize));

    bool rv = false;
    if(true == ui->checkBox_hash_data->isChecked()) {
        printLog("HASH值(HEX):");
        printLog(originalData.toHex());

        rv = m_cryptoUtilsInstance->sm2_verify(pkey, der.get(), (size_t)derSize, (const unsigned char*)originalData.data(), originalData.size());
    } else {
        printLog("原文(HEX):");
        printLog(originalData.toHex());

        if(ui->checkBox_no_zvalue->isChecked()) {
            rv = m_cryptoUtilsInstance->DigestVerify(pkey, EVP_sm3(), der.get(), derSize,
             (const unsigned char*)originalData.data(), originalData.size()
             , nullptr, 0);
        } else {
            printLog("USER ID(HEX):");
            printLog(userId.toHex());

            rv = m_cryptoUtilsInstance->DigestVerify(pkey, EVP_sm3(), der.get(), derSize,
             (const unsigned char*)originalData.data(), originalData.size()
             , userId.data(), userId.size());
        }
    }
    if(true == rv) {
        printLog("SM2 验签成功", Qt::green);
    } else {
        printLog("SM2 验签失败", Qt::red);
    }
}

void MainWindow::printLog(const QString& msg, const QColor& color)
{
    ui->textEdit_log->setTextColor(color);
    ui->textEdit_log->append(msg);
    ui->textEdit_log->moveCursor(QTextCursor::End);
    ui->textEdit_log->setTextColor(Qt::black);
}

void MainWindow::on_checkBox_no_zvalue_stateChanged(int arg1)
{
    if(Qt::Checked == arg1) {
        ui->userIDLineEdit->setEnabled(false);
    } else if(Qt::Unchecked == arg1) {
        ui->userIDLineEdit->setEnabled(true);
    }
}

void MainWindow::on_btn_clear_log_clicked()
{
    ui->textEdit_log->clear();
}

void MainWindow::on_btn_StringToHex_clicked()
{
    QByteArray inputData = ui->dataConversionInput->toPlainText().toLocal8Bit();
    ui->dataConversionOutput->setText(inputData.toHex().toUpper());
}
