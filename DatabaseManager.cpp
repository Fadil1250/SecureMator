#include "DatabaseManager.h"
#include <QDebug>
#include <QSqlDatabase>
#include <QCoreApplication>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QMessageBox>

Database::Database(){

}


void Database::DatabaseConnexion()
{
    //QString appDir = QCoreApplication::applicationDirPath();

        // Chemin relatif de la base de données par rapport au répertoire de l'application
        //QString dbPath = appDir + "/nom_de_votre_base_de_donnees.sqlite";

        // Initialisation de la base de données
        db = QSqlDatabase::addDatabase("QSQLITE");
        db.setDatabaseName(QCoreApplication::applicationDirPath() + "/database.db");

        // Connexion à la base de données
        if (!db.open()) {
            qDebug() << "Erreur lors de l'ouverture de la base de données:" << db.lastError().text();
        } else {
            qDebug() << "Connexion à la base de données réussie";
            statut = "open";
        }
}

bool Database::createSecretKeysTable() {
       // Création de la table "SecretKeys"
       QSqlQuery query;
       bool success = query.exec("CREATE TABLE IF NOT EXISTS secretKeys ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "fileName TEXT,"
                                 "fileData TEXT,"
                                 "iv TEXT,"
                                 "salt TEXT,"
                                 "empreinteKey TEXT,"
                                 "password TEXT,"
                                 "dateCreated DATE"
                                 ")");
       if (!success) {
           qDebug() << "Erreur lors de la création de la table secrets keys:" << query.lastError().text();
       }

       return success;
}

void Database::InsertSecretKey(const QString& fileName, const QByteArray& fileData, const QString& iv, const QString& salt,
                               const QString& empreinteKey ,const QString& dateCreated, const QString& password) {
    QSqlQuery query;


    query.prepare("SELECT COUNT(*) FROM secretKeys WHERE fileName = :fileName");
    query.bindValue(":fileName", fileName);

    if (!query.exec()) {
        qDebug() << "Erreur lors de la vérification de l'existence de la clé:" << query.lastError().text();
        return;
    }

    query.next(); // Passer au premier résultat
    int count = query.value(0).toInt();

    if (count > 0) {
      secretKeyExist = true;
        return;
    }


    // Préparer la requête d'insertion
    query.prepare("INSERT INTO secretKeys (fileName, fileData, iv, salt, empreinteKey, dateCreated, password)"
                  " VALUES (:fileName, :fileData, :iv, :salt, :empreinteKey, :dateCreated, :password)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":fileName", fileName);
    query.bindValue(":fileData", fileData);
    query.bindValue(":iv", iv);
    query.bindValue(":salt", salt);
    query.bindValue(":empreinteKey", empreinteKey);
    query.bindValue(":dateCreated", dateCreated);
    query.bindValue(":password", password);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
       /* qDebug() << "Insertion dans la base de données réussie";
        qDebug() << "file Name: " + fileName;
        qDebug() << "file Data: " + fileData;
        qDebug() << "Iv: " + iv;
        qDebug() << "Salt: " + salt;
        qDebug() << "empreinteKey: " + empreinteKey;
        qDebug() << "password: " + password;
        qDebug() << "Date created: " + dateCreated;*/
    }
}

bool Database::deleteSecretKey(const QString &id)
{
    QSqlQuery query;

    // Préparer la requête SQL pour supprimer la clé secrète en fonction de l'ID
    query.prepare("DELETE FROM secretKeys WHERE id = :id");

    // Lier l'ID à la requête
    query.bindValue(":id", id);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la clé secrète:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Clé secrète supprimée avec succès.";
        return true;
    }
}

bool Database::deletePrivateKey(const QString &id)
{
    QSqlQuery query;

    query.prepare("DELETE FROM privateKeys WHERE id = :id");

    // Lier l'ID à la requête
    query.bindValue(":id", id);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la clé privée:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Clé privée supprimée avec succès.";
        return true;
    }
}


QVector<QStringList> Database::recover_secretKeys()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM secretKeys")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

       return data;
}

void Database::closeConnexion()
{
    db.close();
}

bool Database::symetricKeyExist()
{
    return secretKeyExist;
}

void Database::resetSecretKeyExitValue()
{
    secretKeyExist = false;

}

bool Database::privateKeyExist()
{
    return privatKeyExist;
}

bool Database::publicKeyExist()
{
    return pubKeyExist;
}

void Database::resetPrivateKeyExitValue()
{
    privatKeyExist = false;

}
void Database::resetPublicKeyExitValue()
{
    pubKeyExist = false;

}

QVector<QStringList> Database::filterByDate(QString &dateSelected)
{
    QSqlQuery query;
    QVector<QStringList> data;

    query.prepare("SELECT * FROM secretKeys WHERE dateCreated = :date ");
    query.bindValue(":date", dateSelected);

    if(!query.exec()){
        qDebug() << "Erreur lord de l'exécution: " << query.lastError();
        return QVector<QStringList>();
    }

    else{

        while (query.next()) {
            QStringList row;
            for (int i = 0; i < query.record().count(); ++i) {
                row << query.value(i).toString();
            }
            data.append(row);
        }
    }

    return data;
}

QVector<QStringList> Database::filterByPeriod(QString startDate, QString endDate)
{
    QSqlQuery query;
    QVector<QStringList> data;
    query.prepare("SELECT * FROM secretKeys WHERE dateCreated BETWEEN :startDate AND :endDate");
    query.bindValue(":startDate", startDate);
    query.bindValue(":endDate", endDate);

    if(!query.exec()){
        qDebug() << "Erreur lors du filtrage: "<<query.lastError();
        return QVector<QStringList>();
    }
    else{
        while(query.next()){
            QStringList row;
            for(int i=0; i < query.record().count(); ++i){
                row << query.value(i).toString();

            }
            qDebug() <<"Value: " << row;

            data.append(row);
        }
    }

    return data;
}


QString Database::getIV(const QString& empreinteKey) {
    QSqlQuery query;
    query.prepare("SELECT iv FROM secretKeys WHERE empreinteKey = :empreinteKey");
    query.bindValue(":empreinteKey", empreinteKey);

    if (!query.exec()) {
        qDebug() << "Erreur lors de l'exécution: " << query.lastError();
        return QString(); // Retourner une chaîne vide en cas d'erreur
    }

    if (query.next()) {
        return query.value(0).toString();
    } else {
        qDebug() << "Aucun résultat pour ce fichier:" << empreinteKey;
        return QString(); // Retourner une chaîne vide si aucun résultat
    }
}

QString Database::getPassword(const QString &empreinteKey)
{
    QSqlQuery query;
    query.prepare("SELECT password FROM secretKeys WHERE empreinteKey = :empreinteKey");
    query.bindValue(":empreinteKey", empreinteKey);

    if(!query.exec()){
        qDebug() << "Erreur lors de l'exécution: " << query.lastError();
        return QString();
    }

    if (query.next()) {
        return query.value(0).toString();
    } else {
        qDebug() << "Aucun résultat pour ce fichier:" + empreinteKey ;
        return QString(); // Retourner une chaîne vide si aucun résultat
    }
}


//PRIVATE KEY

bool Database::createPrivateKeysTable()
{
    QSqlQuery query;
    bool success = query.exec("CREATE TABLE IF NOT EXISTS privateKeys ("
                              "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                              "fileName TEXT,"
                              "fileData TEXT,"
                              "empreinteKey TEXT,"
                              "password TEXT,"
                              "dateCreated DATE"
                              ")");
    if (!success) {
        qDebug() << "Erreur lors de la création de la table private keys:" << query.lastError().text();
    }

    return success;
}

QVector<QStringList> Database::recover_privateKeys()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM privateKeys")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

      // qDebug()<< "Charger depuis table privateKeys";
       return data;
}

void Database::InsertPrivateKey(const QString& fileName, const QString& fileData,
                               const QString& empreinteKey ,const QString& dateCreated, const QString& password) {
    QSqlQuery query;


    query.prepare("SELECT COUNT(*) FROM privateKeys WHERE fileName = :fileName");
    query.bindValue(":fileName", fileName);

    if (!query.exec()) {
        qDebug() << "Erreur lors de la vérification de l'existence de la clé:" << query.lastError().text();
        return;
    }

    query.next(); // Passer au premier résultat
    int count = query.value(0).toInt();

    if (count > 0) {
      privatKeyExist = true;
        return;
    }


    // Préparer la requête d'insertion
    query.prepare("INSERT INTO privateKeys (fileName, fileData, empreinteKey, dateCreated, password)"
                  " VALUES (:fileName, :fileData, :empreinteKey, :dateCreated, :password)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":fileName", fileName);
    query.bindValue(":fileData", fileData);
    query.bindValue(":empreinteKey", empreinteKey);
    query.bindValue(":dateCreated", dateCreated);
    query.bindValue(":password", password);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        /*qDebug() << "Insertion dans la base de données réussie";
        qDebug() << "file Name: " + fileName;
        qDebug() << "file Data: " + fileData;
        qDebug() << "empreinteKey: " + empreinteKey;
        qDebug() << "password: " + password;
        qDebug() << "Date created: " + dateCreated;*/
    }
}

QString Database::getPasswordPrivateKey(const QString &empreinteKey)
{
    QSqlQuery query;
    query.prepare("SELECT password FROM privateKeys WHERE empreinteKey = :empreinteKey");
    query.bindValue(":empreinteKey", empreinteKey);

    if(!query.exec()){
        qDebug() << "Erreur lors de l'exécution: " << query.lastError();
        return QString();
    }

    if (query.next()) {
        return query.value(0).toString();
    } else {
        qDebug() << "Aucun résultat pour ce fichier:" + empreinteKey ;
        return QString(); // Retourner une chaîne vide si aucun résultat
    }
}

QVector<QStringList> Database::filterByDatePrivateKey(QString &dateSelected)
{
    QSqlQuery query;
    QVector<QStringList> data;

    query.prepare("SELECT * FROM privateKeys WHERE dateCreated = :date ");
    query.bindValue(":date", dateSelected);

    if(!query.exec()){
        qDebug() << "Erreur lord de l'exécution: " << query.lastError();
        return QVector<QStringList>();
    }

    else{

        while (query.next()) {
            QStringList row;
            for (int i = 0; i < query.record().count(); ++i) {
                row << query.value(i).toString();
            }
            data.append(row);
        }
    }

    return data;
}

QVector<QStringList> Database::filterByPeriodPrivateKey(QString startDate, QString endDate)
{
    QSqlQuery query;
    QVector<QStringList> data;
    query.prepare("SELECT * FROM privateKeys WHERE dateCreated BETWEEN :startDate AND :endDate");
    query.bindValue(":startDate", startDate);
    query.bindValue(":endDate", endDate);



    if(!query.exec()){
        qDebug() << "Erreur lors du filtrage: "<<query.lastError();
        return QVector<QStringList>();
    }
    else{
        while(query.next()){
            QStringList row;
            for(int i=0; i < query.record().count(); ++i){
                row << query.value(i).toString();

            }
            qDebug() <<"Value: " << row;

            data.append(row);
        }
    }

    return data;
}


//PUBLIC KEY

bool Database::createPublicKeysTable() {
    QSqlQuery query;
    bool success = query.exec("CREATE TABLE IF NOT EXISTS publicKeys ("
                              "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                              "fileName TEXT,"
                              "fileData TEXT,"
                              "empreinteKey TEXT,"
                              "dateCreated DATE"
                              ")");
    if (!success) {
        qDebug() << "Erreur lors de la création de la table public keys:" << query.lastError().text();
    }

    return success;
}

void Database::InsertPublicKey(const QString& fileName, const QString& fileData,
                               const QString& empreinteKey ,const QString& dateCreated) {
    QSqlQuery query;

    query.prepare("SELECT COUNT(*) FROM publicKeys WHERE fileName = :fileName");
    query.bindValue(":fileName", fileName);

    if (!query.exec()) {
        qDebug() << "Erreur lors de la vérification de l'existence de la clé:" << query.lastError().text();
        return;
    }

    query.next(); // Passer au premier résultat
    int count = query.value(0).toInt();

    if (count > 0) {
      pubKeyExist = true;
        return;
    }


    // Préparer la requête d'insertion
    query.prepare("INSERT INTO publicKeys (fileName, fileData, empreinteKey, dateCreated)"
                  " VALUES (:fileName, :fileData, :empreinteKey, :dateCreated)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":fileName", fileName);
    query.bindValue(":fileData", fileData);
    query.bindValue(":empreinteKey", empreinteKey);
    query.bindValue(":dateCreated", dateCreated);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        qDebug() << "Insertion dans la base de données réussie";
        qDebug() << "file Name: " + fileName;
        qDebug() << "file Data: " + fileData;
        qDebug() << "empreinteKey: " + empreinteKey;
        qDebug() << "Date created: " + dateCreated;
    }
}

QVector<QStringList> Database::recover_publicKeys()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM publicKeys")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

      // qDebug()<< "Charger depuis table privateKeys";
       return data;
}

bool Database::deletePublicKey(const QString &id)
{
    QSqlQuery query;

    query.prepare("DELETE FROM publicKeys WHERE id = :id");

    // Lier l'ID à la requête
    query.bindValue(":id", id);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la clé privée:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Clé privée supprimée avec succès.";
        return true;
    }
}

QVector<QStringList> Database::filterByDatePublicKey(QString &dateSelected)
{
    QSqlQuery query;
    QVector<QStringList> data;

    query.prepare("SELECT * FROM publicKeys WHERE dateCreated = :date ");
    query.bindValue(":date", dateSelected);

    if(!query.exec()){
        qDebug() << "Erreur lord de l'exécution: " << query.lastError();
        return QVector<QStringList>();
    }

    else{

        while (query.next()) {
            QStringList row;
            for (int i = 0; i < query.record().count(); ++i) {
                row << query.value(i).toString();
            }
            data.append(row);
        }
    }

    return data;
}

QVector<QStringList> Database::filterByPeriodPublicKey(QString startDate, QString endDate)
{
    QSqlQuery query;
    QVector<QStringList> data;
    query.prepare("SELECT * FROM publicKeys WHERE dateCreated BETWEEN :startDate AND :endDate");
    query.bindValue(":startDate", startDate);
    query.bindValue(":endDate", endDate);



    if(!query.exec()){
        qDebug() << "Erreur lors du filtrage: "<<query.lastError();
        return QVector<QStringList>();
    }
    else{
        while(query.next()){
            QStringList row;
            for(int i=0; i < query.record().count(); ++i){
                row << query.value(i).toString();

            }
            qDebug() <<"Value: " << row;

            data.append(row);
        }
    }

    return data;
}

//FIND SECRET KEY

bool Database::createfileCryptedReferencesTable() {
        QSqlQuery query;
       bool success = query.exec("CREATE TABLE IF NOT EXISTS fileCryptedReferences ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "empreinteKey TEXT,"
                                 "empreinteFileCrypted TEXT,"
                                 "keyName TEXT"
                                 ")");
       if (!success) {
           qDebug() << "Erreur lors de la création de la table createfileCryptedReferencesTable:" << query.lastError().text();
       }

       return success;
}

void Database::insertFileCryptedReference(const QString& empreinteKey , const QString& empreinteFileCrypted ,const QString& keyName) {
    QSqlQuery query;

    // Préparer la requête d'insertion
    query.prepare("INSERT INTO fileCryptedReferences (empreinteKey, empreinteFileCrypted, keyName)"
                  " VALUES (:empreinteKey, :empreinteFileCrypted, :keyName)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":empreinteKey", empreinteKey);
    query.bindValue(":empreinteFileCrypted", empreinteFileCrypted);
    query.bindValue(":keyName", keyName);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        qDebug() << "empreinteKey: " + empreinteKey;
        qDebug() << "empreinteFileCrypted: " + empreinteFileCrypted;
        qDebug() << "keyName: " + keyName;

    }
}

bool Database::deleteFileCryptedReference(const QString &empreinteKey)
{
    QSqlQuery query;

    // Préparer la requête SQL pour supprimer la clé secrète en fonction de l'ID
    query.prepare("DELETE FROM fileCryptedReferences WHERE empreinteKey = :empreinteKey");

    // Lier l'ID à la requête
    query.bindValue(":empreinteKey", empreinteKey);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la clé secrète:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Référence file crypted  supprimée avec succès.";
        return true;
    }
}

QVector<QStringList> Database::recover_referencesFileCrypted()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM fileCryptedReferences")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

       return data;
}

QString Database::findSecretKeyName(QString &empreinteFileCrypted)
{
    QSqlQuery query;
    query.prepare("SELECT keyName FROM fileCryptedReferences WHERE  empreinteFileCrypted = :empreinteFileCrypted");
    query.bindValue(":empreinteFileCrypted", empreinteFileCrypted);

    if(!query.exec()){
        qDebug() << "Une erreur s'est produite lors de l'exécution";
        return QString();
    }

    if (query.next()) {
            return query.value(0).toString(); // Retourner le résultat
        } else {
            return QString(); // Retourne une chaîne vide si aucun résultat n'est trouvé
        }
}

//FIND PUBLIC KEY

bool Database::createKeyCryptedReferencesTable() {
        QSqlQuery query;
       bool success = query.exec("CREATE TABLE IF NOT EXISTS keyCryptedReferences ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "empreinteKey TEXT,"
                                 "empreinteKeyCrypted TEXT,"
                                 "keyName TEXT"
                                 ")");
       if (!success) {
           qDebug() << "Erreur lors de la création de la table createkeyCryptedReferencesTable:" << query.lastError().text();
       }

       return success;
}

void Database::insertKeyCryptedReference(const QString& empreinteKey , const QString& empreinteFileCrypted ,const QString& keyName) {
    QSqlQuery query;

    // Préparer la requête d'insertion
    query.prepare("INSERT INTO keyCryptedReferences (empreinteKey, empreinteKeyCrypted, keyName)"
                  " VALUES (:empreinteKey, :empreinteFileCrypted, :keyName)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":empreinteKey", empreinteKey);
    query.bindValue(":empreinteFileCrypted", empreinteFileCrypted);
    query.bindValue(":keyName", keyName);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        qDebug() << "empreinteKey: " + empreinteKey;
        qDebug() << "empreinteFileCrypted: " + empreinteFileCrypted;
        qDebug() << "keyName: " + keyName;

    }
}

bool Database::deleteKeyCryptedReference(const QString &empreinteKey)
{
    QSqlQuery query;

    // Préparer la requête SQL pour supprimer la clé secrète en fonction de l'ID
    query.prepare("DELETE FROM keyCryptedReferences WHERE empreinteKey = :empreinteKey");

    // Lier l'ID à la requête
    query.bindValue(":empreinteKey", empreinteKey);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la référence:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Référence key crypted  supprimée avec succès.";
        return true;
    }
}

QVector<QStringList> Database::recover_referencesKeyCrypted()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM keyCryptedReferences")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

       return data;
}

QString Database::findPublicKeyName(QString &empreinteFileCrypted)
{
    QSqlQuery query;
    query.prepare("SELECT keyName FROM keyCryptedReferences WHERE  empreinteKeyCrypted = :empreinteFileCrypted");
    query.bindValue(":empreinteFileCrypted", empreinteFileCrypted);

    if(!query.exec()){
        qDebug() << "Une erreur s'est produite lors de l'exécution";
        return QString();
    }

    if (query.next()) {
            return query.value(0).toString(); // Retourner le résultat
        } else {
            return QString(); // Retourne une chaîne vide si aucun résultat n'est trouvé
        }
}


// FIND PUBLIC KEY FOR PRIVATE KEY

bool Database::createPubReferencesTable() {
        QSqlQuery query;
       bool success = query.exec("CREATE TABLE IF NOT EXISTS privatekeyReferences ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "empreintePrivateKey TEXT,"
                                 "publickeyName TEXT"
                                 ")");
       if (!success) {
           qDebug() << "Erreur lors de la création de la table privatekeyReferences:" << query.lastError().text();
       }

       return success;
}

void Database::insertPubReference(const QString& empreintePrivateKey , const QString& publickeyName) {
    QSqlQuery query;

    // Préparer la requête d'insertion
    query.prepare("INSERT INTO privatekeyReferences (empreintePrivateKey, publickeyName)"
                  " VALUES (:empreintePrivateKey,  :publickeyName)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":empreintePrivateKey", empreintePrivateKey);
    query.bindValue(":publickeyName", publickeyName);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        qDebug() << "empreintePrivateKey: " + empreintePrivateKey;
        qDebug() << "publickeyName: " + publickeyName;

    }
}

bool Database::deletePubReference(const QString &empreintePrivateKey)
{
    QSqlQuery query;

    // Préparer la requête SQL pour supprimer la clé secrète en fonction de l'ID
    query.prepare("DELETE FROM privatekeyReferences WHERE empreintePrivateKey = :empreintePrivateKey");

    // Lier l'ID à la requête
    query.bindValue(":empreintePrivateKey", empreintePrivateKey);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la référence:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Référence private key  supprimée avec succès.";
        return true;
    }
}

QVector<QStringList> Database::recover_referencesPubKey()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM privatekeyReferences")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

       return data;
}

QString Database::findPubKeyName(QString &empreintePrivatekey)
{
    QSqlQuery query;
    query.prepare("SELECT publickeyName FROM privatekeyReferences WHERE  empreintePrivateKey = :empreintePrivateKey");
    query.bindValue(":empreintePrivateKey", empreintePrivatekey);

    if(!query.exec()){
        qDebug() << "Une erreur s'est produite lors de l'exécution";
        return QString();
    }

    if (query.next()) {
            return query.value(0).toString(); // Retourner le résultat
        } else {
            return QString(); // Retourne une chaîne vide si aucun résultat n'est trouvé
        }
}


// FIND PRIVATE KEY FOR PUBLIC KEY

bool Database::createPemReferencesTable() {
        QSqlQuery query;
       bool success = query.exec("CREATE TABLE IF NOT EXISTS pemReferences ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "empreintePublicKey TEXT,"
                                 "privateKeyName TEXT"
                                 ")");
       if (!success) {
           qDebug() << "Erreur lors de la création de la table privatekeyReferences:" << query.lastError().text();
       }

       return success;
}

void Database::insertpemReference(const QString& empreintePublicKey , const QString& privatekeyName) {
    QSqlQuery query;

    // Préparer la requête d'insertion
    query.prepare("INSERT INTO pemReferences (empreintePublicKey, privateKeyName)"
                  " VALUES (:empreintePublicKey,  :privateKeyName)");

    // Binder les valeurs aux paramètres de la requête
    query.bindValue(":empreintePublicKey", empreintePublicKey);
    query.bindValue(":privateKeyName", privatekeyName);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        qDebug() << "empreintePublicKey: " + empreintePublicKey;
        qDebug() << "privateKeyName: " + privatekeyName;

    }
}

bool Database::deletePemReference(const QString &empreintePublicKey)
{
    QSqlQuery query;

    // Préparer la requête SQL pour supprimer la clé secrète en fonction de l'ID
    query.prepare("DELETE FROM pemReferences WHERE empreintePublicKey = :empreintePublicKey");

    // Lier l'ID à la requête
    query.bindValue(":empreintePublicKey", empreintePublicKey);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la référence:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Référence public key  supprimée avec succès.";
        return true;
    }
}

QVector<QStringList> Database::recover_referencesPemKey()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM pemReferences")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

       return data;
}

QString Database::findPemReferenceName(QString &empreintePublickey)
{
    QSqlQuery query;
    query.prepare("SELECT privateKeyName FROM pemReferences WHERE  empreintePublicKey = :empreintePublicKey");
    query.bindValue(":empreintePublicKey", empreintePublickey);

    if(!query.exec()){
        qDebug() << "Une erreur s'est produite lors de l'exécution";
        return QString();
    }

    if (query.next()) {
            return query.value(0).toString(); // Retourner le résultat
        } else {
            return QString(); // Retourne une chaîne vide si aucun résultat n'est trouvé
        }
}


// FIND PRIVATE KEY FOR SIGNATURE

bool Database::createsignaturesReferencesTable() {
        QSqlQuery query;
       bool success = query.exec("CREATE TABLE IF NOT EXISTS signaturesReferences ("
                                 "id INTEGER PRIMARY KEY AUTOINCREMENT, "
                                 "empreinteSignature TEXT,"
                                 "empreintePrivateKey TEXT,"
                                 "signatureName TEXT"
                                 ")");
       if (!success) {
           qDebug() << "Erreur lors de la création de la table signaturesReferences:" << query.lastError().text();
       }

       return success;
}

void Database::insertSignatureReference(const QString& empreinteSignature , const QString& empreintePrivateKey,  const QString& privateKeyName) {
    QSqlQuery query;

    // Préparer la requête d'insertion
    query.prepare("INSERT INTO signaturesReferences (empreinteSignature, empreintePrivateKey, signatureName)"
                  " VALUES (:empreinteSignature, :empreintePrivateKey,   :signatureName)");

    // Binder les valeurs aux paramètres de la requête

    query.bindValue(":empreinteSignature", empreinteSignature);
    query.bindValue(":empreintePrivateKey", empreintePrivateKey);
    query.bindValue(":signatureName", privateKeyName);


    // Exécuter la requête d'insertion
    if (!query.exec()) {
        qDebug() << "Erreur lors de l'insertion dans la base de données:" << query.lastError().text();
    } else {
        qDebug() << "empreinteSignature: " + empreinteSignature;
        qDebug() << "privateKeyName: " + privateKeyName;

    }
}

bool Database::deleteSignatureReference(const QString &empreintePrivateKey)
{
    QSqlQuery query;

    // Préparer la requête SQL pour supprimer la clé secrète en fonction de l'ID
    query.prepare("DELETE FROM signaturesReferences WHERE empreintePrivateKey = :empreintePrivateKey");

    // Lier l'ID à la requête
    query.bindValue(":empreintePrivateKey", empreintePrivateKey);

    // Exécuter la requête
    if (!query.exec()) {
        qDebug() << "Erreur lors de la suppression de la référence:" << query.lastError().text();
        return false;
    } else {
        qDebug() << "Référence signature supprimée avec succès.";
        return true;
    }
}

QVector<QStringList> Database::recover_referencesSignatures()
{
    QVector<QStringList> data;

       QSqlQuery query;
       if (query.exec("SELECT * FROM signaturesReferences")) {
           while (query.next()) {
               QStringList row;
               for (int i = 0; i < query.record().count(); ++i) {
                   row << query.value(i).toString();
               }
               data.append(row);
           }
       }

       return data;
}

QString Database::findSignatureName(QString &empreintePrivatekey)
{
    QSqlQuery query;
    query.prepare("SELECT signatureName FROM signaturesReferences WHERE  empreinteSignature = :empreinteSignature");
    query.bindValue(":empreinteSignature", empreintePrivatekey);

    if(!query.exec()){
        qDebug() << "Une erreur s'est produite lors de l'exécution";
        return QString();
    }

    if (query.next()) {
            return query.value(0).toString(); // Retourner le résultat
        } else {
            return QString(); // Retourne une chaîne vide si aucun résultat n'est trouvé
        }
}


