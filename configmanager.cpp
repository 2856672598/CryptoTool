#include "configmanager.h"
#include <QTextStream>

ConfigManager::ConfigManager(const QString& configFilePath)
    : settings(configFilePath, QSettings::IniFormat) {
    // 检查配置文件是否存在
    QFile configFile(configFilePath);
    if (!configFile.exists()) {
        // 如果不存在，创建一个默认的配置文件
        if (configFile.open(QIODevice::WriteOnly)) {
            QTextStream out(&configFile);
            out << "[Certificates]\n";
            out << "SM2PrivateKey = /path/to/sm2_private_key.pem\n";
            out << "SM2Cert = /path/to/sm2_cert.pem\n";
            out << "RSAPrivateKey = /path/to/rsa_private_key.pem\n";
            out << "RSACert = /path/to/rsa_cert.pem\n";
            configFile.close();
        }
    }
}

QString ConfigManager::getValue(const QString& key, const QString& defaultValue) const {
    return settings.value(key, defaultValue).toString();
}
