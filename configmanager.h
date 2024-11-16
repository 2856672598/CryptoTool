#ifndef CONFIGMANAGER_H
#define CONFIGMANAGER_H

#include <QString>
#include <QSettings>
#include <QFile>

class ConfigManager {
public:
    ConfigManager(const QString& configFilePath);
    
    // 通用获取方法
    QString getValue(const QString& key, const QString& defaultValue = QString()) const;

private:
    QSettings settings;
};

#endif // CONFIGMANAGER_H
