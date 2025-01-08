#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QSqlDatabase>
class Database{
    public:
           Database();
           void DatabaseConnexion();
           bool createSecretKeysTable();
           void InsertSecretKey(const QString& fileName, const QByteArray& fileData, const QString& iv, const QString& salt,
                                const QString& empreinteKey ,const QString& dateCreated, const QString& password);
           bool deleteSecretKey(const QString& id);
           QVector<QStringList> recover_secretKeys();
           void closeConnexion();
           bool symetricKeyExist();
           void resetSecretKeyExitValue();
           QVector<QStringList> filterByDate(QString& dateSelected);
           QString getIV(const QString &empreinte);
           QString getPassword(const QString &empreinteKey);
           QVector<QStringList> filterByPeriod (QString startDate, QString endDate);

           //PRIVATE KEY
           bool createPrivateKeysTable();
           QVector<QStringList> recover_privateKeys();
           void InsertPrivateKey(const QString &fileName, const QString &fileData, const QString &empreinteKey,
                                 const QString &dateCreated, const QString &password);
           bool privateKeyExist();
           void resetPrivateKeyExitValue();
           bool deletePrivateKey(const QString &id);
           QString getPasswordPrivateKey(const QString &empreinteKey);
           QVector<QStringList> filterByDatePrivateKey(QString &dateSelected);
           QVector<QStringList> filterByPeriodPrivateKey(QString startDate, QString endDate);

           //PUBLIC KEY
           bool createPublicKeysTable();
           void InsertPublicKey(const QString &fileName, const QString &fileData, const QString &empreinteKey, const QString &dateCreated);
           QVector<QStringList> recover_publicKeys();
           bool deletePublicKey(const QString &id);
           bool publicKeyExist();
           void resetPublicKeyExitValue();
           QVector<QStringList> filterByPeriodPublicKey(QString startDate, QString endDate);
           QVector<QStringList> filterByDatePublicKey(QString &dateSelected);

           // FIND SECRET KEY

           bool createfileCryptedReferencesTable();
           void insertFileCryptedReference(const QString &empreinteKey, const QString &empreinteFileCrypted, const QString &keyName);
           bool deleteFileCryptedReference(const QString &empreinteKey);
           QVector<QStringList> recover_referencesFileCrypted();
           QString findSecretKeyName(QString &empreinteFileCrypted);

           //FIND PUBLIC KEY

           bool createKeyCryptedReferencesTable();
           void insertKeyCryptedReference(const QString &empreinteKey, const QString &empreinteFileCrypted, const QString &keyName);
           bool deleteKeyCryptedReference(const QString &empreinteKey);
           QVector<QStringList> recover_referencesKeyCrypted();
           QString findPublicKeyName(QString &empreinteFileCrypted);

           // FIND PUBLIC KEY FOR PRIVATE KEY

           bool createPubReferencesTable();
           void insertPubReference(const QString& empreintePrivateKey , const QString& publickeyName);
           bool deletePubReference(const QString &empreintePrivateKey);
           QVector<QStringList> recover_referencesPubKey();
           QString findPubKeyName(QString &empreintePrivatekey);

           // FIND PRIVATE KEY FOR PUBLIC KEY

           bool createPemReferencesTable();
           void insertpemReference(const QString& empreintePublicKey , const QString& privatekeyName);
           bool deletePemReference(const QString &empreintePublicKey);
           QVector<QStringList> recover_referencesPemKey();
           QString findPemReferenceName(QString &empreintePublickey);

           // FIND PRIVATE KEY FOR SIGNATURE

           bool createsignaturesReferencesTable();
           void insertSignatureReference(const QString &empreinteSignature, const QString& empreintePrivateKey, const QString &privateKeyName);
           bool deleteSignatureReference(const QString &empreintePrivateKey);
           QVector<QStringList> recover_referencesSignatures();
           QString findSignatureName(QString &empreintePrivatekey);
private:
           QSqlDatabase db;
           QString statut;
           bool secretKeyExist = false;
           bool privatKeyExist = false;
           bool pubKeyExist = false;

};


#endif // DATABASEMANAGER_H
