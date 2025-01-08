#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QProcess>
#include <QFileDialog>
#include <QDebug>
#include <QMessageBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QInputDialog>
#include <QTimer>
#include <QThread>
#include <QDialog>
#include <QStyle>
#include <QLayout>
#include <QSqlDatabase>
#include <QStandardItemModel>
#include <QRandomGenerator>
#include <QGraphicsDropShadowEffect>
#include <windows.h>
#include <QCloseEvent>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    QIcon windowIcon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
    this->setWindowIcon(windowIcon);

     database.DatabaseConnexion();
     filtedData = database.recover_secretKeys();
     dataSecretKeys = database.recover_secretKeys();
     qDebug()<< "path: " << QCoreApplication::applicationDirPath() + "/images/key_12986731.png";

     dataPrivateKeys = database.recover_privateKeys();
     recordPrivateKeys = database.recover_privateKeys();

     dataPublicKeys = database.recover_publicKeys();
     recordPublicKeys = database.recover_publicKeys();




     bool exist =  database.createSecretKeysTable();

     if(exist){
         qDebug()<<"Tables créees avec succès";
     }else{
          qDebug() << "Erreur lors de la création de la table secrets keys:";
     }

     getSecretKeys();

     bool privateKeysTableexist =  database.createPrivateKeysTable();

     if(privateKeysTableexist){
         qDebug()<<"Tables clés privées créees avec succès";
     }else{
          qDebug() << "Erreur lors de la création de la table private Keys:";
     }

    getPrivateKeys();

    bool publicKeysTableexist =  database.createPublicKeysTable();

    if(publicKeysTableexist){
        qDebug()<<"Tables clés publiques créees avec succès";
    }else{
         qDebug() << "Erreur lors de la création de la table private Keys:";
    }

    getPublicKeys();

    //FIND SECREY KEY

    bool fileCryptedReferencesTableExist =  database.createfileCryptedReferencesTable();

    if(fileCryptedReferencesTableExist){
        qDebug()<<"Tables clés fileCryptedReferencesTableExist créees avec succès";
    }else{
         qDebug() << "Erreur lors de la création de la table fileCryptedReferencesTableExist:";
    }

    referencesFilesCrypted = database.recover_referencesFileCrypted();
    qDebug() << "Files crypted references: " << referencesFilesCrypted;

    //FIND PUBLIC KEY

    if( database.createKeyCryptedReferencesTable()){
        qDebug()<<"Tables clés keysCryptedReferencesTableExist créees avec succès";
    }else{
         qDebug() << "Erreur lors de la création de la table keysCryptedReferencesTableExist:";
    }

    referencesKeysCrypted = database.recover_referencesKeyCrypted();
    qDebug() << "Keys crypted references: " << referencesKeysCrypted;

    // FIND PUBLIC KEY FOR PRIVATE KEY


    if( database.createPubReferencesTable()){
        qDebug()<<"Tables  créees avec succès";
    }else{
         qDebug() << "Erreur lors de la création de la table";
    }

    referencesPubkeysForPrivateKeys = database.recover_referencesPubKey();
    qDebug() << "Public keys for private keys references: " << referencesPubkeysForPrivateKeys;

    //FIND PRIVATE KEY FOR PUBLIC KEY

    if( database.createPemReferencesTable()){
        qDebug()<<"Tables  créees avec succès";
    }else{
         qDebug() << "Erreur lors de la création de la table";
    }

    referencesPemkeysForPublicKeys = database.recover_referencesPemKey();
    qDebug() << "Private keys for public keys references: " << referencesPubkeysForPrivateKeys;

    //FIND PRIVATE KEY FOR SIGNATURE

    if( database.createsignaturesReferencesTable()){
        qDebug()<<"Tables  créees avec succès";
    }else{
         qDebug() << "Erreur lors de la création de la table";
    }

    referencesSignature = database.recover_referencesSignatures();
    qDebug() << "Signatures references: " << referencesSignature;


    ui->frame->hide();
    ui->frame_6->hide();
    ui->pushButton_2->setCursor(Qt::PointingHandCursor);
    ui->pushButton_3->setCursor(Qt::PointingHandCursor);
    ui->pushButton_4->setCursor(Qt::PointingHandCursor);
    ui->pushButton_5->setCursor(Qt::PointingHandCursor);
    ui->pushButton_6->setCursor(Qt::PointingHandCursor);
    ui->pushButton_57->setCursor(Qt::PointingHandCursor);


    this->setFixedSize(750, 435);
    this->setWindowFlags((this->windowFlags() & ~Qt::WindowMaximizeButtonHint) | Qt::MSWindowsFixedSizeDialogHint);

    QPixmap pixmap(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
    int w = ui->label_2->width();
    int h = ui->label_2->height();

    ui->label_2->setPixmap(pixmap.scaled(w,h, Qt::KeepAspectRatio));

    QPixmap backgroundImage(QCoreApplication::applicationDirPath() + "/images/3820574.jpg");

    int width_l1 = ui->label->width();
    int height_l1 = ui->label->height();

    ui->label->setPixmap(backgroundImage.scaled(width_l1, height_l1, Qt::KeepAspectRatio));

    opensslProcess = new QProcess(this);

        // Connexion du signal finished
    connect(opensslProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                this, &MainWindow::onProcessFinished);

          ;}

MainWindow::~MainWindow()
{
    delete ui;
    database.closeConnexion();
}

void MainWindow::closeEvent(QCloseEvent *event)
{

    if(opensslProcess->state() == QProcess::Running){
        QMessageBox msgBox;
        msgBox.setWindowTitle("SecureMator");
        QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
        msgBox.setWindowIcon(icon);

        msgBox.setText("Voulez-vous annuler la tâche en cours d'exécution ?");

        QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
        QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);
        msgBox.setDefaultButton(qobject_cast<QPushButton*>(pButtonNo));

        msgBox.exec();

        if(msgBox.clickedButton()== pButtonYes){
            opensslProcess->kill();
            event->accept();
        }
        else if(msgBox.clickedButton() == pButtonNo){
            event->ignore();
        }
    }
 }


void MainWindow::getSecretKeys()
{

    // Créer un QTableWidget avec le nombre de lignes et colonnes approprié
    ui->tableWidget->setRowCount(filtedData.size());
    ui->tableWidget->setColumnCount(3); // Clé, Date Création, Action

    // Ajouter les en-têtes de colonne
    ui->tableWidget->setHorizontalHeaderLabels({ "Clé", "Date Création", "Actions" });

    ui->tableWidget->setColumnWidth(2, 240);


    // Ajouter les données récupérées dans le QTableWidget
    for (int i = 0; i < filtedData.size(); i++) {
        QStringList rowData = filtedData[i];
        //qDebug() << rowData;
        if (rowData.size() >= 4) {
            QString fileName = rowData[1];
            QString dateCreated = rowData[7];

            QDate date = QDate::fromString(dateCreated, "yyyy/MM/dd");
                    QString formattedDate = date.toString("dd/MM/yyyy");

            ui->tableWidget->setItem(i, 0, new QTableWidgetItem(fileName));
            ui->tableWidget->setItem(i, 1, new QTableWidgetItem(formattedDate));

            // Créer un QWidget pour contenir les deux boutons
            QWidget *buttonWidget = new QWidget();
            QHBoxLayout *layout = new QHBoxLayout(buttonWidget);
            layout->setContentsMargins(5, 2, 5, 2);

            // Créer les boutons
            QPushButton *chargerBtn = new QPushButton("Charger Clé Secrète");

            chargerBtn->setCursor(Qt::PointingHandCursor);
            chargerBtn->setStyleSheet("background-color: #4054f6; border-radius: 1px; color: white; font-weight: bold");

            QPushButton *deleteBtn = new QPushButton("Supprimer");
            deleteBtn->setStyleSheet("background-color: red; border-radius: 1px; color: white; font-weight: bold");
            deleteBtn->setCursor(Qt::PointingHandCursor);

            // Ajouter les boutons au layout
            layout->addWidget(chargerBtn);
            layout->addWidget(deleteBtn);

            // Définir le widget contenant les boutons dans la cellule
            ui->tableWidget->setCellWidget(i, 2, buttonWidget);

            connect(chargerBtn, &QPushButton::clicked,this,  [this, rowData]() {
                //qDebug() << "Charger Clé Secrète button clicked in row:" << i;
               QString passwordDb = rowData[6];

               bool ok;
               QInputDialog passwordDialog(this);
               QString password;

               do{
                    password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé secrète :", QLineEdit::Password, "", &ok);

                   if(password.isEmpty()){
                       return;
                   }

                   password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

                   if(password == passwordDb){
                       passwordDb = password;
                   }
                   else{
                       QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
                   }
               } while(passwordDb != password);

               symetricKeyFromDb  = rowData[2];
               fileNameFromDb = rowData[1];
               iv = rowData[3];
               symetric_key_path = "";
               decrypted = "0";
               crypted = "0";
                showMessage("information", fileNameFromDb + " charger avec succès");

             //  qDebug() << "symetric key: " + symetricKeyFromDb;

            });


            connect(deleteBtn, &QPushButton::clicked, this, [this, rowData]() {
                qDebug() << "Supprimer button clicked in row:" << rowData;

                if(!symetricKeyFromDb.isEmpty() && fileNameFromDb == rowData[1]){
                    QApplication::beep();

                    QMessageBox::warning(this,  tr("SecureMator"), fileNameFromDb +" en cours d'utilisation. \n Suppression impossible.");
                    return;
                }
                QApplication::beep();
                QString passwordDb = rowData[6];

                bool ok;
                QInputDialog passwordDialog(this);
                QString password;

                do{
                     password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé secrète :", QLineEdit::Password, "", &ok);

                    if(password.isEmpty()){
                        return;
                    }

                    password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

                    if(password == passwordDb){
                        passwordDb = password;
                    }
                    else{
                        QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
                    }
                } while(passwordDb != password);

                QMessageBox msgBox;
                msgBox.setWindowTitle("SecureMator");
                QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
                msgBox.setWindowIcon(icon);

                msgBox.setText("Voulez-vous vraiment supprimer " + rowData[1] + " ? \n Assurez-vous que vous n'avez plus de fichier chiffré avec cette clé.");

                QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
                QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);
                msgBox.setDefaultButton(qobject_cast<QPushButton*>(pButtonNo));

                msgBox.exec();

                if(msgBox.clickedButton()== pButtonYes){

                    if(database.deleteSecretKey(rowData[0])){
                        database.deleteFileCryptedReference(rowData[5]);
                        referencesFilesCrypted = database.recover_referencesFileCrypted();
                        qDebug() << "Files crypted references: " << referencesFilesCrypted;

                        filtedData = database.recover_secretKeys();
                        dataSecretKeys = database.recover_secretKeys();

                        getSecretKeys();
                        QMessageBox::information(this,  tr("SecureMator"), rowData[1] + " supprimer avec succès !");
                    }
                    else{
                        QMessageBox::warning(this,  tr("SecureMator"),"Erreur lors de la suppression");
                    }
                }
                if(msgBox.clickedButton()==pButtonNo){
                    return;
                }
            });
        }
    }
}

void MainWindow::getPrivateKeys()
{
     //data = database.recover_secretKeys();

    // Créer un QTableWidget avec le nombre de lignes et colonnes approprié
    ui->tableWidget_2->setRowCount(dataPrivateKeys.size());
    ui->tableWidget_2->setColumnCount(3); // Clé, Date Création, Action

    // Ajouter les en-têtes de colonne
    ui->tableWidget_2->setHorizontalHeaderLabels({ "Clé", "Date Création", "Actions" });

    ui->tableWidget_2->setColumnWidth(2, 340);


    // Ajouter les données récupérées dans le QTableWidget
    for (int i = 0; i < dataPrivateKeys.size(); i++) {
        QStringList rowData = dataPrivateKeys[i];
        //qDebug() << rowData;
        if (rowData.size() >= 4) {
            QString fileName = rowData[1];
            QString dateCreated = rowData[5];

            QDate date = QDate::fromString(dateCreated, "yyyy/MM/dd");
                    QString formattedDate = date.toString("dd/MM/yyyy");

            ui->tableWidget_2->setItem(i, 0, new QTableWidgetItem(fileName));
            ui->tableWidget_2->setItem(i, 1, new QTableWidgetItem(formattedDate));

            // Créer un QWidget pour contenir les deux boutons
            QWidget *buttonWidget = new QWidget();
            QHBoxLayout *layout = new QHBoxLayout(buttonWidget);
            layout->setContentsMargins(5, 2, 5, 2);

            // Créer les boutons
            QPushButton *chargerBtn = new QPushButton("Charger Clé privée");
            chargerBtn->setStyleSheet("background-color: #4054f6; border-radius: 1px; color: white; font-weight: bold");
            chargerBtn->setCursor(Qt::PointingHandCursor);

            QPushButton *deleteBtn = new QPushButton("Supprimer");
            deleteBtn->setStyleSheet("background-color: red; border-radius: 1px; color: white; font-weight: bold");
            deleteBtn->setCursor(Qt::PointingHandCursor);

            QPushButton *findBtn = new QPushButton("Retrouver ma Clé publique");
            findBtn->setStyleSheet("background-color: #26a846; border-radius: 1px; color: white; font-weight: bold");
            findBtn->setCursor(Qt::PointingHandCursor);

            // Ajouter les boutons au layout
            layout->addWidget(chargerBtn);
            layout->addWidget(deleteBtn);
            layout->addWidget(findBtn);

            // Définir le widget contenant les boutons dans la cellule
            ui->tableWidget_2->setCellWidget(i, 2, buttonWidget);

            connect(chargerBtn, &QPushButton::clicked,this,  [this, rowData]() {
                //qDebug() << "Charger Clé Secrète button clicked in row:" << i;
               QString passwordDb = rowData[4];

               bool ok;
               QInputDialog passwordDialog(this);
               QString password;

               do{
                    password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé privée :", QLineEdit::Password, "", &ok);

                   if(password.isEmpty()){
                       return;
                   }

                   password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

                   if(password == passwordDb){
                       passwordDb = password;
                   }
                   else{
                       QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
                   }
               } while(passwordDb != password);
                passwordPrivateKey = passwordDb;
               privateKeyFromDb  = rowData[2];
               fileNamePrivateKeyFromDb = rowData[1];
               privateKeyPath = "";
                decryptedKey =  "0";
                showMessage("information", fileNamePrivateKeyFromDb + " charger avec succès");


            });


            connect(findBtn, &QPushButton::clicked,this,  [this, rowData](){
               QString empreintePrivateKey = rowData[3];
               QString keyName = database.findPubKeyName(empreintePrivateKey);

                if(keyName.isEmpty()){
                    QMessageBox::warning(this,  tr("SecureMator"), "La clé Publique correspondante à " + rowData[1] + " est introuvable.");
                }else{
                    showMessage("information","La clé publique correspondante " + rowData[1] + " est: " + keyName + ".");
                }
                qDebug() << "Row Data: " << rowData;
            });

            connect(deleteBtn, &QPushButton::clicked, this, [this, rowData]() {
                qDebug() << "Supprimer button clicked in row:" << rowData;

                if(!privateKeyFromDb.isEmpty() && fileNamePrivateKeyFromDb == rowData[1]){
                    QApplication::beep();

                    QMessageBox::warning(this,  tr("SecureMator"), fileNamePrivateKeyFromDb +" en cours d'utilisation. \n Suppression impossible.");

                    return;
                }
                QApplication::beep();
                QString passwordDb = rowData[4];

                bool ok;
                QInputDialog passwordDialog(this);
                QString password;

                do{
                     password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé privée :", QLineEdit::Password, "", &ok);

                    if(password.isEmpty()){
                        return;
                    }

                    password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

                    if(password == passwordDb){
                        passwordDb = password;
                    }
                    else{
                        QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
                    }
                } while(passwordDb != password);
                QMessageBox msgBox;
                msgBox.setWindowTitle("SecureMator");
                QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
                msgBox.setWindowIcon(icon);

                msgBox.setText("Voulez-vous vraiment supprimer " + rowData[1] + " ?");

                QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
                QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);
                msgBox.setDefaultButton(qobject_cast<QPushButton*>(pButtonNo));

                msgBox.exec();

                if(msgBox.clickedButton()== pButtonYes){

                    if(database.deletePrivateKey(rowData[0])){
                        database.deletePubReference(rowData[3]);
                        referencesPubkeysForPrivateKeys = database.recover_referencesPubKey();
                        //qDebug() << "Pub references: " << referencesPubkeysForPrivateKeys;


                        database.deleteSignatureReference(rowData[3]);
                        referencesSignature = database.recover_referencesSignatures();
                        qDebug() << "Signatures references: " << referencesSignature;

                        dataPrivateKeys = database.recover_privateKeys();
                        recordPrivateKeys = database.recover_privateKeys();

                        getPrivateKeys();
                        QMessageBox::information(this,  tr("SecureMator"), rowData[1] + " supprimer avec succès !");
                    }
                    else{
                        QMessageBox::warning(this,  tr("SecureMator"),"Erreur lors de la suppression");
                    }
                }
                if(msgBox.clickedButton()==pButtonNo){
                    return;
                }
            });
        }
    }
}

void MainWindow::getPublicKeys()
{
     //data = database.recover_secretKeys();

    // Créer un QTableWidget avec le nombre de lignes et colonnes approprié
    ui->tableWidget_3->setRowCount(dataPublicKeys.size());
    ui->tableWidget_3->setColumnCount(3); // Clé, Date Création, Action

    // Ajouter les en-têtes de colonne
    ui->tableWidget_3->setHorizontalHeaderLabels({ "Clé", "Date Création", "Actions" });

    ui->tableWidget_3->setColumnWidth(2, 340);


    // Ajouter les données récupérées dans le QTableWidget
    for (int i = 0; i < dataPublicKeys.size(); i++) {
        QStringList rowData = dataPublicKeys[i];
        //qDebug() << rowData;
        if (rowData.size() >= 4) {
            QString fileName = rowData[1];
            QString dateCreated = rowData[4];

            QDate date = QDate::fromString(dateCreated, "yyyy/MM/dd");
                              QString formattedDate = date.toString("dd/MM/yyyy");

            ui->tableWidget_3->setItem(i, 0, new QTableWidgetItem(fileName));
            ui->tableWidget_3->setItem(i, 1, new QTableWidgetItem(formattedDate));

            // Créer un QWidget pour contenir les deux boutons
            QWidget *buttonWidget = new QWidget();
            QHBoxLayout *layout = new QHBoxLayout(buttonWidget);
            layout->setContentsMargins(5, 2, 5, 2);

            // Créer les boutons
            QPushButton *chargerBtn = new QPushButton("Charger Clé publique");
            chargerBtn->setStyleSheet("background-color: #4054f6; border-radius: 1px; color: white; font-weight: bold");
            chargerBtn->setCursor(Qt::PointingHandCursor);

            QPushButton *deleteBtn = new QPushButton("Supprimer");
            deleteBtn->setStyleSheet("background-color: red; border-radius: 1px; color: white; font-weight: bold");
            deleteBtn->setCursor(Qt::PointingHandCursor);

            QPushButton *findBtn = new QPushButton("Retrouver ma Clé privée");
            findBtn->setStyleSheet("background-color: #26a846; border-radius: 1px; color: white; font-weight: bold");
            findBtn->setCursor(Qt::PointingHandCursor);


            // Ajouter les boutons au layout
            layout->addWidget(chargerBtn);
            layout->addWidget(deleteBtn);
            layout->addWidget(findBtn);


            // Définir le widget contenant les boutons dans la cellule
            ui->tableWidget_3->setCellWidget(i, 2, buttonWidget);

            connect(chargerBtn, &QPushButton::clicked,this,  [this, rowData]() {
                //qDebug() << "Charger Clé Secrète button clicked in row:" << i;
               publicKeyFromDb = rowData[2];
               fileNamePublicKeyFromDb = rowData[1];
               publicKeyPath = "";
               cryptedKey = "0";
               //qDebug() << publicKeyFromDb;
                showMessage("information", fileNamePublicKeyFromDb + " charger avec succès");
            });

            connect(findBtn, &QPushButton::clicked,this,  [this, rowData](){
                          QString empreintePublicKey = rowData[3];
                          QString keyName = database.findPemReferenceName(empreintePublicKey);

                           if(keyName.isEmpty()){
                               QMessageBox::warning(this,  tr("SecureMator"), "La clé Privée correspondante à " + rowData[1] + " est introuvable.");
                           }else{
                               showMessage("information","La clé Privée correspondante " + rowData[1] + " est: " + keyName + ".");
                           }
                           qDebug() << "Row Data: " << rowData;
                       });


            connect(deleteBtn, &QPushButton::clicked, this, [this, rowData]() {
                qDebug() << "Supprimer button clicked in row:" << rowData;

                if(!publicKeyFromDb.isEmpty()&& fileNamePublicKeyFromDb == rowData[1] ){
                    QApplication::beep();

                     QMessageBox::warning(this,  tr("SecureMator"), fileNamePublicKeyFromDb +" en cours d'utilisation. \n Suppression impossible.");
                         return;
                    }
                QApplication::beep();

                QMessageBox msgBox;
                msgBox.setWindowTitle("SecureMator");
                QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
                msgBox.setWindowIcon(icon);

                msgBox.setText("Voulez-vous vraiment supprimer " + rowData[1] + " ?");

                QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
                QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);
                msgBox.setDefaultButton(qobject_cast<QPushButton*>(pButtonNo));

                msgBox.exec();

                if(msgBox.clickedButton()== pButtonYes){

                    if(database.deletePublicKey(rowData[0])){

                        database.deleteKeyCryptedReference(rowData[3]);
                        referencesKeysCrypted = database.recover_referencesKeyCrypted();
                        //qDebug() << "Keys crypted references: " << referencesKeysCrypted;

                        database.deletePemReference(rowData[3]);
                        referencesPemkeysForPublicKeys = database.recover_referencesPemKey();
                        qDebug() << "referencesPemkeysForPublicKeys: " << referencesPemkeysForPublicKeys;

                        dataPublicKeys = database.recover_publicKeys();
                        recordPublicKeys = database.recover_publicKeys();

                        getPublicKeys();
                        QMessageBox::information(this,  tr("SecureMator"), rowData[1] + " supprimer avec succès !");
                    }
                    else{
                        QMessageBox::warning(this,  tr("SecureMator"),"Erreur lors de la suppression");
                    }
                }
                if(msgBox.clickedButton()==pButtonNo){
                    return;
                }
            });
        }
    }
}


QByteArray generateIV(int ivSize = 16) {
    QByteArray iv;
    iv.resize(ivSize);
    QRandomGenerator::global()->generate(iv.begin(), iv.end());
    return iv;
}

void MainWindow::showMessage(QString type, QString message)
{
    /*QMessageBox msgBox;
    msgBox.setText(tr("Confirm?"));
    QAbstractButton* pButtonYes = msgBox.addButton(tr("Yeah!"), QMessageBox::YesRole);
    msgBox.addButton(tr("Nope"), QMessageBox::NoRole);

    msgBox.exec();

    if (msgBox.clickedButton()==pButtonYes) {
        //Execute command
    }  */

    if(type == "information"){
        QMessageBox::information(this,  tr("SecureMator"), message);
    }

    if(type == "error"){
        QMessageBox::critical(this, tr("SecureMator") , message);
    }

    if(type == "warning"){
        QMessageBox msgBox(QMessageBox::Warning, tr("SecureMator"), message, QMessageBox::Ok, this);
        msgBox.setStyleSheet("QLabel{min-width: 500px;}"); // Ajustez la largeur selon vos besoins
        msgBox.exec();
    }

    if(type == "critical"){
        QMessageBox msgBox(QMessageBox::Critical, tr("SecureMator"), message, QMessageBox::Ok, this);
        msgBox.setStyleSheet("QLabel{min-width: 500px;}"); // Ajustez la largeur selon vos besoins
        msgBox.exec();
    }
}



bool fileExists(const QString &directory, const QString &fileName) {
    QDir dir(directory);
    return dir.exists(fileName);
}



void MainWindow::generateSymmetricKey()
{
    bool ok;
    QInputDialog passwordDialog(this);
    QInputDialog confirmDialog(this);

    QString password;
    QString confirmPassword;
    do{
         password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé secrète :", QLineEdit::Password, "", &ok);

        if(password.isEmpty()){
            return;
        }

         confirmPassword = confirmDialog.getText(this, "Confirmation...", "Confirmez le mot de passe :", QLineEdit::Password, "", &ok);

        if(confirmPassword.isEmpty()){
            return;
        }

        if(password == confirmPassword){
            confirmPassword = password;
        }
        else{
            QMessageBox::warning(this,  tr("SecureMator"), "Les mots de passe ne correspondent pas.");
        }
    } while(confirmPassword != password);


    QString outputFilePath = QFileDialog::getSaveFileName(this, "Enregistrer la clé secrète", !directoryGenerateSymetricKey.isEmpty() ?
                                                              directoryGenerateSymetricKey :
                                                              QDir::homePath(), "Fichiers DAT (*.dat)");

    if (outputFilePath.isEmpty()) {
        return;
    }

    symetric_key_path = outputFilePath;
    symetricKeyFromDb = "";
    fileNameFromDb = "";
    passwordSecretKey = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

    QFileInfo fileInfo(outputFilePath);
     directoryGenerateSymetricKey = fileInfo.absolutePath();

    QStringList args;
    args << "enc"
         << "-aes-256-cbc"
         << "-pbkdf2"
         << "-k" << password
         << "-P"
         << "-md" << "sha256";

    opensslProcess->start(opensslExecutable, args);
    processusEnCours = "generateSecretKey";
    crypted = "0";


    //QString dateCreated = QDate::currentDate().toString("dd/MM/yyyy");
    /*database.InsertSecretKey(fileInfo.fileName().toUpper(), symmetricKey.toHex(), ivHex, dateCreated);
    if(database.symetricKeyExist()){
        QMessageBox::warning(this,  tr("SecureMator"), "Cette clé existe déjà.");
        database.resetSecretKeyExitValue();
        return;
    }*/

    //filtedData = database.recover_secretKeys();
}

void MainWindow::generatePrivateKeyWithPassword() {
    // Demander à l'utilisateur de saisir le mot de passe
    bool ok;
    QInputDialog passwordDialog(this);
    QInputDialog confirmDialog(this);

    QString password;
    QString confirmPassword;
    do{
         password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé privée :", QLineEdit::Password, "", &ok);

        if(password.isEmpty()){
            return;
        }

         confirmPassword = confirmDialog.getText(this, "Confirmation...", "Confirmez le mot de passe :", QLineEdit::Password, "", &ok);

        if(confirmPassword.isEmpty()){
            return;
        }

        if(password == confirmPassword){
            confirmPassword = password;
        }
        else{
            QMessageBox::warning(this,  tr("SecureMator"), "Les mots de passe ne correspondent pas.");
        }
    } while(confirmPassword != password);

    QString outputFilePath = QFileDialog::getSaveFileName(this, "Enregistrer la clé privée", !directoryPrivateKey.isEmpty() ?
                                                              directoryPrivateKey :
                                                              QDir::homePath(), "Fichiers PEM (*.pem)");

    if (outputFilePath.isEmpty()) {
        return;
    }
    privateKeyPath = outputFilePath;
    passwordPrivateKey = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

    privateKeyFromDb  = "";
    fileNamePrivateKeyFromDb = "";

    QFileInfo fileInfo(outputFilePath);
    directoryPrivateKey = fileInfo.absolutePath();

    QStringList args;
    args << "genpkey"
         << "-algorithm"
         << "RSA" << "-out"
         << outputFilePath
         << "-aes256"
         << "-pass"
         << "pass:" + passwordPrivateKey
         << "-pkeyopt"
         << "rsa_keygen_bits:4096";


    opensslProcess->start(opensslExecutable, args);
    processusEnCours = "generatePrivateKey";

}

void MainWindow::generateRSAPublicKey()
{
    QString privateKeyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé privée",
                                                   !directoryPrivateKey.isEmpty() ? directoryPrivateKey : QDir::homePath(), "Fichiers de clé (*.pem)");

    if (privateKeyFilePath.isEmpty()) {
        return;
    }

    QFile file(privateKeyFilePath);
    QString key;
    if(file.open(QIODevice::ReadOnly)){
        key = file.readAll();
        file.close();
    }
    QString empreinte = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();

    QString passwordFromDb = database.getPasswordPrivateKey(empreinte);

     QFileInfo fileInfo(privateKeyFilePath);
     directoryPrivateKey = fileInfo.absolutePath();
     directoryPublicKey = fileInfo.absolutePath();

    // Demander à l'utilisateur de saisir le mot de passe pour déchiffrer la clé privée
    bool ok;
    do{
        QString password = QInputDialog::getText(this, "Mot de passe", "Entrez le mot de passe de la clé privée:", QLineEdit::Password, "", &ok);
        if (!ok || password.isEmpty()) {
            return;
        }

        password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

        if(passwordFromDb == password){
            break;
        } else{
            QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
        }

    }while(true);


    // Demander à l'utilisateur où enregistrer la clé publique
    QString publicKeyFilePath = QFileDialog::getSaveFileName(this, "Enregistrer la clé publique (" + fileInfo.fileName() + ")" ,

                                             !directoryPublicKey.isEmpty() ? directoryPublicKey : QDir::homePath(), "Fichiers de clé (*.pub)");

    // Vérifier si l'utilisateur a annulé la sélection ou n'a pas choisi de fichier
    if (publicKeyFilePath.isEmpty()) {
        return;
    }
    publicKeyPath = publicKeyFilePath;
    publicKeyFromDb = "";
    fileNamePublicKeyFromDb = "";

    QFileInfo publicKeyInfo(publicKeyFilePath);
    directoryPublicKey = publicKeyInfo.absolutePath();
    temp_publicKeyPath =  publicKeyInfo.absolutePath();

    // Exécuter OpenSSL pour générer la clé publique à partir de la clé privée
    //qDebug() << "Mot de passe: " << passwordFromDb;
    opensslProcess->start(opensslExecutable, QStringList() << "rsa"
                          << "-pubout"
                          << "-in" << privateKeyFilePath
                          << "-out" << publicKeyFilePath
                           << "-passin" << "pass:" + passwordFromDb
                          );

    processusEnCours = "generatePublicKey";

    /* Attendre que le processus soit terminé
    if (opensslProcess.waitForFinished() && opensslProcess.exitCode() == 0) {
        QMessageBox::information(this, "Succès", "Votre clé publique est générée et sauvegardée dans " + publicKeyFilePath);
    } else {
        QMessageBox::critical(this, "Erreur", "Une erreur s'est produite lors de la génération de la clé publique. Vérifiez que le mot de passe est correct.");
    }*/
}

void MainWindow::encryptSymmetricKey(const QString &symmetricKeyFilePath, const QString &publicKeyFilePath)
{
    QString directoryPath = QFileDialog::getExistingDirectory(this, "Choisir un dossier pour enregistrer la clé chiffrée" ,
                                                          !directoryKeyCrypted.isEmpty() ? directoryKeyCrypted :
                                                                                                          QDir::homePath());
    if(directoryPath.isEmpty()){
        return;
    }

    directoryKeyCrypted = directoryPath;
     QFileInfo fileInfo(symmetricKeyFilePath);
     QString encryptedSymmetricKeyFilePath = directoryPath + QDir::separator() + fileInfo.fileName() + ".exe";

     if (fileExists(directoryPath, encryptedSymmetricKeyFilePath)) {
         QMessageBox::warning(this,  tr("SecureMator"), fileInfo.fileName() + ".exe" + " existe déjà.\n"
                                                                                    " \n Vous pouvez changer d'emplacement pour pouvoir enregistrer votre clé.\n "
                                                              "Cependant, nous vous recommandons d'utiliser des clés avec des noms différents,"
                                                              " sinon vous risquez de vous tromper de clé ou de perdre vos données. \n");
         return;
     }

     if(!publicKeyFromDb.isEmpty()){
         QFile publicKey(QDir::homePath() + QDir::separator() + "tempPub");
           tempPathPublicKey = QDir::homePath() + QDir::separator() + "tempPub";

         if(publicKey.open(QIODevice::WriteOnly)){
             publicKey.write(publicKeyFromDb.toUtf8());
             publicKey.close();
             publicKey.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
         }
         opensslProcess->start(opensslExecutable, QStringList() << "pkeyutl"
                               << "-encrypt"
                               << "-pubin"
                               << "-inkey"
                               << tempPathPublicKey
                               << "-in"
                               << symmetricKeyFilePath
                               << "-out" << encryptedSymmetricKeyFilePath);

     }


     if(opensslProcess->state() == QProcess::NotRunning){
         opensslProcess->start(opensslExecutable, QStringList()
                               << "pkeyutl"
                               << "-encrypt"
                               << "-pubin"
                               << "-inkey" << publicKeyFilePath
                               << "-in"  << symmetricKeyFilePath
                               << "-out" << encryptedSymmetricKeyFilePath);
     }
     processusEnCours = "encryptPublicKey";

 }

void MainWindow::decryptSymmetricKey(const QString &encryptedSymmetricKeyFilePath, const QString &privateKeyFilePath) {
    // Demander à l'utilisateur où enregistrer la clé symétrique déchiffrée
   // qDebug() << "Password for Db: " + passwordPrivateKey;
    QFileInfo privateKeyInfo(privateKeyFilePath);
    QString fileName = !privateKeyFromDb.isEmpty() ? fileNamePrivateKeyFromDb : privateKeyInfo.fileName();
    QString directory = QFileDialog::getExistingDirectory(this, "Choisir un dossier pour enregistrer la clé secrète déchiffrée (" + fileName + ") ",
                                                                          !directorySymetricDecrypted.isEmpty() ? directorySymetricDecrypted :
                                                                                                             QDir::homePath());
    if (directory.isEmpty()) {
        return; // L'utilisateur a annulé la sélection ou n'a pas choisi de fichier de sortie
    }
    directorySymetricDecrypted = directory;

    QString decryptedSymmetricKeyFilePath;
    QString keyEncryptedPath = encryptedSymmetricKeyFilePath;
    keyEncryptedPath = keyEncryptedPath.left(keyEncryptedPath.length() - 4);    
    decryptedSymmetricKeyFilePath = keyEncryptedPath;

    QFileInfo fileInfo(decryptedSymmetricKeyFilePath);
    decryptedSymmetricKeyFilePath = directorySymetricDecrypted + QDir::separator() + fileInfo.fileName();


    if (fileExists(directory, decryptedSymmetricKeyFilePath)) {
        QMessageBox::warning(this,  tr("SecureMator"), fileInfo.fileName() + " existe déjà.\n"
                                                                            " \n Vous pouvez changer d'emplacement pour pouvoir enregistrer votre clé.\n "
                                                      "Cependant, nous vous recommandons d'utiliser des clés avec des noms différents,"
                                                      " sinon vous risquez de vous tromper de clé ou de perdre vos données. \n");
        return;
    }

    if(!privateKeyFromDb.isEmpty()){
        QFile privateKey(QDir::homePath() + QDir::separator() + "tempPem");
          tempPathPrivateKey = QDir::homePath() + QDir::separator() + "tempPem";

        if(privateKey.open(QIODevice::WriteOnly)){
            privateKey.write(privateKeyFromDb.toUtf8());
            privateKey.close();
            privateKey.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
        }
        opensslProcess->start(opensslExecutable, QStringList() << "pkeyutl"
                              << "-decrypt"
                              << "-inkey"
                              << tempPathPrivateKey
                              << "-in" << encryptedSymmetricKeyFilePath
                              << "-out" << decryptedSymmetricKeyFilePath
                              << "-passin" << "pass:" + passwordPrivateKey);

    }

    if(opensslProcess->state() == QProcess::NotRunning){
        opensslProcess->start(opensslExecutable, QStringList() << "pkeyutl"
                              << "-decrypt"
                              << "-inkey"
                              << privateKeyFilePath
                              << "-in"
                              << encryptedSymmetricKeyFilePath
                              << "-out" << decryptedSymmetricKeyFilePath
                              << "-passin" << "pass:" + passwordPrivateKey);
    }
    processusEnCours = "decryptedKey";

}


void MainWindow::signFile(const QString &inputFilePath, const QString &privateKeyFilePath) {

    QFileInfo fileInfoprivateKey(privateKeyFilePath);
    QFileInfo fileInfoForFile(inputFilePath);
    QString fileName = !privateKeyFromDb.isEmpty() ? fileNamePrivateKeyFromDb : fileInfoprivateKey.fileName();
     outputFileSignaturePath = QFileDialog::getSaveFileName(this, "Enregistrer la signature (" + fileInfoForFile.fileName() + ")  ("+fileName+")",
                                                          !directorySignaturePath.isEmpty() ? directorySignaturePath :
                                                          QDir::homePath(), "Fichiers signés (*.msi)");

    // Vérifier si l'utilisateur a annulé la sélection ou n'a pas choisi de fichier
    if (outputFileSignaturePath.isEmpty()) {
        return;
    }

    if(!privateKeyFromDb.isEmpty()){
        QFile privateKey(QDir::homePath() + QDir::separator() + "tempPem");
          tempPathPrivateKey = QDir::homePath() + QDir::separator() + "tempPem";

        if(privateKey.open(QIODevice::WriteOnly)){
            privateKey.write(privateKeyFromDb.toUtf8());
            privateKey.close();
            privateKey.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
        }
        QStringList args;
        args << "dgst" << "-sha256"
             << "-passin" << "pass:" + passwordPrivateKey
             << "-sign" << tempPathPrivateKey
             << "-out" << outputFileSignaturePath
             << inputFilePath;

        opensslProcess->start(opensslExecutable, args);
    }

    QFileInfo fileInfo(outputFileSignaturePath);
    directorySignaturePath= fileInfo.absolutePath();

    if(opensslProcess->state() == QProcess::NotRunning){
        QStringList args;
        args << "dgst" << "-sha256"
             << "-passin" << "pass:" + passwordPrivateKey
             << "-sign" << privateKeyFilePath
             << "-out" << outputFileSignaturePath
             << inputFilePath;

        opensslProcess->start(opensslExecutable, args);
    }


    processusEnCours = "generateSignature";
}

void MainWindow::verifySignature( const QString &originalFilePath ,const QString &signature, const QString &publicKeyFilePath)
{

    if(!publicKeyFromDb.isEmpty()){
        QFile publicKey(QDir::homePath() + QDir::separator() + "tempPub");
          tempPathPublicKey = QDir::homePath() + QDir::separator() + "tempPub";

        if(publicKey.open(QIODevice::WriteOnly)){
            publicKey.write(publicKeyFromDb.toUtf8());
            publicKey.close();
            publicKey.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
        }
        opensslProcess->start(opensslExecutable, QStringList() << "dgst" << "-sha256" << "-verify" << tempPathPublicKey << "-signature" << signature << originalFilePath);

    }

    if(opensslProcess->state() == QProcess::NotRunning){
        opensslProcess->start(opensslExecutable, QStringList() << "dgst" << "-sha256" << "-verify" << publicKeyFilePath << "-signature" << signature << originalFilePath);

    }
    processusEnCours = "verifySignature";

    /*// Vérifier le code de sortie pour déterminer si la signature est valide
    if (opensslProcess.exitCode() == 0) {
        showIformationMessageBox(this, "La signature est valide.");

     } else {
        showWarningMessageBox(this, "La signature n'est pas valide.");

     }*/
}


void MainWindow::encryptFiles(const QStringList &inputFilePaths) {
    // Demander à l'utilisateur où enregistrer les fichiers chiffrés
    outputDirPath = QFileDialog::getExistingDirectory(this, "Choisir un dossier pour enregistrer les fichiers chiffrés",
                                                      !directoryFilesCrypted.isEmpty() ? directoryFilesCrypted :
                                                                                         QDir::homePath());

    if (outputDirPath.isEmpty()) {
        return;
    }

    directoryFilesCrypted = outputDirPath;
    temp_directory_files_decrypted = outputDirPath;


    filesToEncrypt = inputFilePaths;
    qDebug()<< filesToEncrypt;
    currentFileIndex = 0;

    ui->frame->setVisible(true);
    ui->label_8->setText("Nombre de fichiers chiffrés: 0/" +QString::number(filesToEncrypt.size()));
    ui->progressBar->setRange(0, filesToEncrypt.size());
    ui->progressBar->setValue(0);

    continueEncryption = true;
    startNextEncryption();
    processusEnCours = "chiffrement";
}

void MainWindow::decryptFiles(const QStringList &inputFilePaths)
{
    directory_files_decrypted = QFileDialog::getExistingDirectory(this, "Choisir un dossier pour enregistrer les fichiers déchiffrés",
                                                      !temp_directory_files_decrypted.isEmpty() ? temp_directory_files_decrypted :
                                                                                         QDir::homePath());
    if (directory_files_decrypted.isEmpty()) {
        return;
    }

    temp_directory_files_decrypted = directory_files_decrypted;

    filesToDecrypt = inputFilePaths;
    currentFileIndex = 0;

    ui->frame_6->setVisible(true);
    ui->label_15->setText("Nombre de fichiers déchiffrés: 0/" +QString::number(filesToDecrypt.size()));
    ui->progressBar_2->setRange(0, inputFilePaths.size());
    ui->progressBar_2->setValue(0);

    continueDecryption = true;
    startNextDecryption();
    processusEnCours = "dechiffrement";

}

void MainWindow::startNextEncryption() {

    //qDebug()<< "Ryttep: " <<  anyFileEncrypted;

    if (currentFileIndex >= filesToEncrypt.size()) {
        ui->frame->setVisible(false);

        if (anyFileEncrypted) {
                crypted = "1";
                anyFileEncrypted = false;

                  if (filesToEncrypt.size() == 1)
                      showMessage("information", "Fichier chiffré avec succès");
                  else
                      showMessage("information", " Fichiers chiffrés avec succès (" + QString::number(currentFileIndex) +

                                  "/" + QString::number(filesToEncrypt.size()) + ")." );
              } else {
                  showMessage("information", "Aucun fichier n'a été chiffré.");
              }

       return;
    }

    QFileInfo fileInfo(filesToEncrypt[currentFileIndex]);
    ui->label_7->setText("Chiffrement du fichier: " + fileInfo.fileName());
    QString outputFilePath = outputDirPath + QDir::separator() + fileInfo.fileName() + ".exe";

    if (fileExists(outputDirPath, outputFilePath)) {
        QApplication::beep();

        QMessageBox msgBox;
        msgBox.setWindowTitle("SecureMator");
        QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
        msgBox.setWindowIcon(icon);

        msgBox.setText( fileInfo.fileName() +".exe" + " existe déjà. Voulez-vous la remplacer ? \n"
                                                      "Si vous la remplacez, les données de ce fichier seront irrécupérables.");

        QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
        QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);
        msgBox.setDefaultButton(qobject_cast<QPushButton*>(pButtonNo));

        msgBox.exec();

        if(msgBox.clickedButton()== pButtonYes){
            QFile file(outputFilePath);
            if(file.exists()){
                file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
            }
            //Exécute le code
        }
        if(msgBox.clickedButton()==pButtonNo){
            filesToEncrypt.removeAt(currentFileIndex);
            ui->progressBar->setRange(0, filesToEncrypt.size());
            ui->label_8->setText("Nombre de fichiers chiffrés: " + QString::number(currentFileIndex)+ "/" +QString::number(filesToEncrypt.size()));

            qDebug() << filesToEncrypt.size();
             qDebug() << "Fichier courant: " << currentFileIndex;
            //currentFileIndex++;
            //qDebug() << filesToEncrypt[currentFileIndex];
             startNextEncryption();
            return;
        }
    }

    if(!symetricKeyFromDb.isEmpty()){
        QStringList arguments;

        arguments  << "enc" << "-aes-256-cbc"
                   << "-k" << symetricKeyFromDb
                   << "-in" << filesToEncrypt[currentFileIndex]
                      <<  "-iv" << iv
                      << "-pbkdf2"
                      << "-out" << outputFilePath;

           opensslProcess->start(opensslExecutable, arguments);

    }


    if(opensslProcess->state() == QProcess::NotRunning){
        QString symetricKey;

        QFile file(symetric_key_path);
        if(file.open(QIODevice::ReadOnly)){
           symetricKey = file.readAll();
           file.close();
        }
        QStringList keyParts = QString(symetricKey).split(':');

        qDebug() << "IV: "<< iv;
        qDebug() << "Key: "<< keyParts[0];

        QStringList args;
        args << "enc" << "-aes-256-cbc"
             << "-k" << keyParts[0]
             << "-in" << filesToEncrypt[currentFileIndex]
             <<  "-iv" << iv
             << "-pbkdf2"
             << "-out" << outputFilePath ;


        qDebug() << "Chiffrement du fichier:" << filesToEncrypt[currentFileIndex];
        opensslProcess->start(opensslExecutable, args);
    }

}

void MainWindow::startNextDecryption()
{
    if(currentFileIndex >= filesToDecrypt.size()){
        ui->frame_6->setVisible(false);
        if (anyFileDecrypted) {
                decrypted = "1";
                anyFileDecrypted = false;

                  if (filesToDecrypt.size() == 1)
                      showMessage("information", "Fichier déchiffré avec succès");
                  else
                      showMessage("information", " Fichiers déchiffrés avec succès (" + QString::number(currentFileIndex) +

                                  "/" + QString::number(filesToDecrypt.size()) + ")." );
              } else {
                  showMessage("information", "Aucun fichier n'a été chiffré.");
              }

        return;
    }

    QFileInfo fileInfo(filesToDecrypt[currentFileIndex]);
    ui->label_14->setText("Déchiffrement du fichier: " + fileInfo.fileName());

    QString fileEncryptedPath = filesToDecrypt[currentFileIndex];

    fileEncryptedPath = fileEncryptedPath.left(fileEncryptedPath.length() - 4);
    //qDebug() << "file Decrypted: " << fileEncryptedPath;

    QFileInfo file(fileEncryptedPath);
     QString outputFilePath = directory_files_decrypted + QDir::separator() + file.fileName();

   if (fileExists(directory_files_decrypted, outputFilePath)) {
       QApplication::beep();

       QMessageBox msgBox;
       msgBox.setWindowTitle("SecureMator");
       QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
       msgBox.setWindowIcon(icon);

       msgBox.setText( file.fileName() + " existe déjà. Voulez-vous la remplacer ? \n"
                                                     "Si vous la remplacez, les données de ce fichier seront irrécupérables.");

       QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
       QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);
       msgBox.setDefaultButton(qobject_cast<QPushButton*>(pButtonNo));

       msgBox.exec();

       if(msgBox.clickedButton()== pButtonYes){
           //Exécute le code
       }
       if(msgBox.clickedButton()==pButtonNo){
           filesToDecrypt.removeAt(currentFileIndex);
           ui->progressBar_2->setRange(0, filesToDecrypt.size());
           ui->label_15->setText("Nombre de fichiers déchiffrés: " + QString::number(currentFileIndex)+ "/" +QString::number(filesToDecrypt.size()));

           qDebug() << filesToEncrypt.size();
            qDebug() << "Fichier courant: " << currentFileIndex;
           //currentFileIndex++;
           //qDebug() << filesToEncrypt[currentFileIndex];
            startNextDecryption();
           return;
       }
   }

   if(!symetricKeyFromDb.isEmpty()){
       QStringList arguments;

       arguments << "enc" << "-aes-256-cbc"
                 << "-d" << "-k"
                 << symetricKeyFromDb
                 << "-in" << filesToDecrypt[currentFileIndex]
                 <<  "-iv" << iv
                 << "-pbkdf2"
                 << "-out" << outputFilePath;

          opensslProcess->start(opensslExecutable, arguments);

   }

   if(opensslProcess->state() == QProcess::NotRunning){
       QString symetricKey;

       QFile file(symetric_key_path_for_decryption);
       if(file.open(QIODevice::ReadOnly)){
          symetricKey = file.readAll();
          file.close();
       }
       qDebug() << symetricKey;
       QStringList keyParts = QString(symetricKey).split(':');
       qDebug() << "IV: " + iv;
       qDebug() << "key: " + keyParts[0];


       QStringList args;
           args << "enc" << "-aes-256-cbc" << "-d" << "-k" << keyParts[0] << "-in" << filesToDecrypt[currentFileIndex]
                <<  "-iv" << iv
                << "-pbkdf2"
                << "-out" << outputFilePath ;

        qDebug() << "Déchiffrement du fichier: " << fileInfo.fileName();
        opensslProcess->start(opensslExecutable, args);
   }

}

void MainWindow::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus) {

    if(processusEnCours == "chiffrement") {

        QFileInfo fileInfo(filesToEncrypt[currentFileIndex]);
        QString error = opensslProcess->readAllStandardError();
        if (!error.isEmpty()) {
            qDebug() << "OpenSSL Error:" << error;
        }

        if (exitCode != 0 || exitStatus == QProcess::CrashExit) {
            if (!continueEncryption) {
                QString message = "Le chiffrement a été arrêté. Nombre de fichiers chiffrés: " + QString::number(currentFileIndex) +
                        " sur " + QString::number(filesToEncrypt.size()) + "\n Erreur lors du chiffrement du fichier: " +fileInfo.fileName() ;
                showMessage("warning", message);
                return;
            }

            ui->frame->setVisible(false);
            showMessage("critical", "Nombre de fichiers chiffrés: " + QString::number(currentFileIndex) +
                                    " sur " + QString::number(filesToEncrypt.size()) +
                                    "\nErreur lors du chiffrement du fichier: " + fileInfo.fileName() +
                                    "\n Assurez-vous de charger la bonne clé secrète"
                        );

            return;
            qDebug() << "Erreur lors du chiffrement du fichier: " << filesToEncrypt[currentFileIndex] << " " << opensslProcess->errorString();
        } else {
            qDebug() << "Chiffrement réussi du fichier:" << filesToEncrypt[currentFileIndex] + ".exe";
            QString pathFileToEncrypt  =  outputDirPath + QDir::separator() + fileInfo.fileName() + ".exe";
            QFile fileToEncrypt(pathFileToEncrypt);

            if(fileToEncrypt.exists()){
                fileToEncrypt.setPermissions(QFile::ReadOwner | QFile::ReadGroup |QFile::ReadOther);
                qDebug()<< "Good good!!";

            }else{
                qDebug()<< "Fichier introuvable.....";
            }

            QFileInfo secretKeyInfo(symetric_key_path);
           // qDebug()<< "SymetricKey: " << secretKeyInfo.fileName();
            qDebug() << "Symetric key: " + symetric_key_path;
            QFile fileSecretKey(symetric_key_path);
            QString secretKey;
            QString empreinteKey;
            QString fileName = !symetricKeyFromDb.isEmpty() ? fileNameFromDb : secretKeyInfo.fileName();

            qDebug() << "File name: " + fileName;
            if(fileSecretKey.open(QIODevice::ReadOnly)){
                secretKey = fileSecretKey.readAll();
                fileSecretKey.close();
                empreinteKey = QCryptographicHash::hash(secretKey.toUtf8(), QCryptographicHash::Sha256).toHex();
                qDebug()<< "L'empreinte from pc: " + empreinteKey;

            }else if (!symetricKeyFromDb.isEmpty()) {
                empreinteKey = QCryptographicHash::hash(symetricKeyFromDb.toUtf8(), QCryptographicHash::Sha256).toHex();
                qDebug()<< "L'empreinte Db: " + empreinteKey;

            }

            QString outputFilePath = outputDirPath + QDir::separator() + fileInfo.fileName() + ".exe";
            QFile fileCrypted(outputFilePath);
            QString filecontent;
            QString empreinteFileCrypted;

            if(fileCrypted.open(QIODevice::ReadOnly)){
                filecontent = fileCrypted.readAll();
                fileCrypted.close();
                empreinteFileCrypted = QCryptographicHash::hash(filecontent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
            qDebug()<< "Empreinte file crypted: " + empreinteFileCrypted;

            database.insertFileCryptedReference(empreinteKey, empreinteFileCrypted, fileName);
            referencesFilesCrypted = database.recover_referencesFileCrypted();
           // qDebug() << "Les références: " << referencesFilesCrypted;

            anyFileEncrypted = true;
            ui->progressBar->setValue(currentFileIndex + 1);
            currentFileIndex++;
            ui->label_8->setText("Nombre de fichiers chiffrés: " + QString::number(currentFileIndex)+ "/" +QString::number(filesToEncrypt.size()));

            QCoreApplication::processEvents(); // Pour mettre à jour l'interface utilisateur
            startNextEncryption();
        }
    }

    else if (processusEnCours == "dechiffrement"){
        QFileInfo fileInfo(filesToDecrypt[currentFileIndex]);


       /* QString sortie = opensslProcess->readAllStandardOutput();
        qDebug() << sortie;*/

        QString error = opensslProcess->readAllStandardError();
        if (!error.isEmpty()) {
            qDebug() << "OpenSSL Error:" << error;
        }

        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            if (!continueDecryption) {
                QString message = "Le déchiffrement a été arrêté. Nombre de fichiers déchiffrés: " + QString::number(currentFileIndex) +
                        " sur " + QString::number(filesToDecrypt.size()) + "\n Erreur lors du déchiffrement du fichier: " +fileInfo.fileName() ;
                showMessage("warning", message);
                return;
            }

            ui->frame_6->setVisible(false);
            showMessage("critical", "Nombre de fichiers déchiffrés: " + QString::number(currentFileIndex) +
                                    " sur " + QString::number(filesToDecrypt.size()) +
                                    "\nErreur lors du déchiffrement du fichier : " + fileInfo.fileName()+
                                    "\nAssurez-vous de charger la bonne Clé"
                        );
            return;

        }
        else{
            qDebug() << "Déchiffrement réussi du fichier: " << filesToDecrypt[currentFileIndex];
            anyFileDecrypted = true;
            ui->progressBar_2->setValue(currentFileIndex + 1);
            currentFileIndex++;
            ui->label_15->setText("Nombre de fichiers déchiffrés: " + QString::number(currentFileIndex)+ "/" +QString::number(filesToDecrypt.size()));
            QCoreApplication::processEvents();
            startNextDecryption();
        }
    }

    else if(processusEnCours == "generatePrivateKey"){


        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            showMessage("critical", "Une erreur s'est produite lors de la génération de la clé privée.");
            return;
        }
        else{

            QFile file(privateKeyPath);
            QFileInfo fileInfo(privateKeyPath);
            QString key;
            if(file.open(QIODevice::ReadOnly)){
                key = file.readAll();
                file.close();
                file.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
            }
            QString empreinte = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();
            QString dateCreated = QDate::currentDate().toString("yyyy/MM/dd");


            database.InsertPrivateKey(fileInfo.fileName().toUpper(), key, empreinte, dateCreated, passwordPrivateKey);
            privateKeyFromDb = "";
            fileNamePrivateKeyFromDb = "";
            if(database.privateKeyExist()){
                file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                file.remove();
                QMessageBox::warning(this,  tr("SecureMator"), "Cette clé privée existe déjà.");
                database.resetPrivateKeyExitValue();

                return;
            }
            dataPrivateKeys = database.recover_privateKeys();
            recordPrivateKeys = database.recover_privateKeys();
            decryptedKey = "0";
            showMessage("information", "Clé privée générée avec succès ");
            return;
        }
    }

    else if(processusEnCours == "generatePublicKey"){
        QString sortie = opensslProcess->readAllStandardError();

        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            showMessage("critical", "Une erreur s'est produite lors de la génération de la clé publique."
                                    "\n"
                                    "Assurez-vous que le mot de passe de la clé privé est correct.");
            return;
            qDebug() <<"Sortie: " << sortie;
        }
        else{
            QFile file(publicKeyPath);
            QFileInfo fileInfo(publicKeyPath);
            QString key;
            if(file.open(QIODevice::ReadOnly)){
                key = file.readAll();
                file.close();
                file.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
            }

            QString empreinte = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();
            QString dateCreated = QDate::currentDate().toString("yyyy/MM/dd");
            database.InsertPublicKey(fileInfo.fileName().toUpper(), key, empreinte, dateCreated);


            if(database.publicKeyExist()){
                file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                file.remove();
                QMessageBox::warning(this,  tr("SecureMator"), "Cette clé publique existe déjà.");
                database.resetPublicKeyExitValue();

                return;
            }
            dataPublicKeys = database.recover_publicKeys();
            recordPublicKeys = database.recover_publicKeys();


            QFile filePrivateKey(privateKeyPath);
            QString privateKeyContent;
            QFileInfo privateKeyInfo(privateKeyPath);
            QString empreintePrivate;

            if(filePrivateKey.open(QIODevice::ReadOnly)){
                privateKeyContent = filePrivateKey.readAll();
                filePrivateKey.close();
                empreintePrivate = QCryptographicHash::hash(privateKeyContent.toUtf8(), QCryptographicHash::Sha256).toHex();
                qDebug()<< "Empreinte private key from pc: " + empreintePrivate;

            }

            database.insertPubReference(empreintePrivate, fileInfo.fileName());
            referencesPubkeysForPrivateKeys = database.recover_referencesPubKey();

            database.insertpemReference(empreinte, privateKeyInfo.fileName());
            referencesPemkeysForPublicKeys = database.recover_referencesPemKey();

            qDebug()<< "Private key: " + privateKeyPath;
            qDebug()<< "Public key: " + fileInfo.fileName();

            cryptedKey = "0";
            showMessage("information", "Clé publique générée avec succès ");
            return;
        }

    }

    else if (processusEnCours == "encryptPublicKey"){
        QString error;
        error = opensslProcess->readAllStandardError();
        if(!error.isEmpty()){
            qDebug() << "Erreur: " + error;
        }

        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            showMessage("critical", "Une erreur s'est produite lors du chiffrement de la clé symétrique.");
            return;
        }
        else{
            if(!publicKeyFromDb.isEmpty()){
                QFile file(tempPathPublicKey);
                file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                file.remove();
            }

            QFileInfo secretKeyInfo(symetric_key_path);
            qDebug() << "Symetric key: " + symetric_key_path;
            QFileInfo publicKeyInfo(publicKeyPath);
            qDebug() << "Public key: " + publicKeyPath;

            QFile filePublicKey(publicKeyPath);
            QString publicKey;
            QString empreinteKey;

            QString fileName = !publicKeyFromDb.isEmpty() ? fileNamePublicKeyFromDb : publicKeyInfo.fileName();

            qDebug() << "File name: " + fileName;
            if(filePublicKey.open(QIODevice::ReadOnly)){
                publicKey = filePublicKey.readAll();
                filePublicKey.close();
                empreinteKey = QCryptographicHash::hash(publicKey.toUtf8(), QCryptographicHash::Sha256).toHex();
                qDebug()<< "L'empreinte from pc: " + empreinteKey;

            }else if (!publicKeyFromDb.isEmpty()) {
                empreinteKey = QCryptographicHash::hash(publicKeyFromDb.toUtf8(), QCryptographicHash::Sha256).toHex();
                qDebug()<< "L'empreinte Db: " + empreinteKey;

            }

            QString outputFilePath = directoryKeyCrypted + QDir::separator() + secretKeyInfo.fileName() + ".exe";
            QFile keyCrypted(outputFilePath);

            QString filecontent;
            QString empreinteKeyCrypted;

            if(keyCrypted.open(QIODevice::ReadOnly)){
                filecontent = keyCrypted.readAll();
                keyCrypted.close();
                empreinteKeyCrypted = QCryptographicHash::hash(filecontent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
            qDebug()<< "Empreinte key crypted: " + empreinteKeyCrypted;

            database.insertKeyCryptedReference(empreinteKey, empreinteKeyCrypted, fileName);
            referencesKeysCrypted = database.recover_referencesKeyCrypted();
            qDebug() << "Les références: " << referencesKeysCrypted;

            cryptedKey = "1";
            showMessage("information", "Clé secrète chiffrée avec succès ");
            return;
        }
    }

    else if(processusEnCours =="decryptedKey"){
        QString error;
        error = opensslProcess->readAllStandardError();
        QString sortie;
        sortie = opensslProcess->readAllStandardOutput();
        if(!sortie.isEmpty()){
            qDebug()<<"Sortie: " + sortie;
        }
        if(!error.isEmpty()){
            qDebug()<<error;
        }
        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            if(!privateKeyFromDb.isEmpty()){
                           QFile file(tempPathPrivateKey);
                           file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                           file.remove();
                       }
            showMessage("critical", "Une erreur s'est produite lors du déchiffrement de la clé symétrique.\n Clé secrète ou mot de passe invalide.");
            return;
        }
        else{

            QString decryptedSymmetricKeyFilePath;
            QFileInfo fileInfo(symetric_key_cypher_path);
            QString keyEncryptedPath = fileInfo.fileName();
            keyEncryptedPath = keyEncryptedPath.left(keyEncryptedPath.length() - 4);
            decryptedSymmetricKeyFilePath = directorySymetricDecrypted + QDir::separator() + keyEncryptedPath;
            QFileInfo fileDecryptedInfo(decryptedSymmetricKeyFilePath);

            if(!privateKeyFromDb.isEmpty()){
                           QFile file(tempPathPrivateKey);
                           file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                           file.remove();
                       }

            if(!symetric_key_cypher_path.isEmpty()){
                QFile file(decryptedSymmetricKeyFilePath);
                if(file.exists()){
                    if(fileDecryptedInfo.size() > 97 || fileDecryptedInfo.size() < 97){
                         file.remove();
                        showMessage("critical", "Une erreur s'est produite lors du déchiffrement de la clé symétrique.\n Clé privée invalide. \n"
                                                                  " Veuillez charger la clé privée correspondante.");
                        return;
                    }
                    else{
                        file.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
                    }

                }
            }

             showMessage("information", "Clé secrète déchiffrée avec succès ");
            return;
        }
    }

    else if (processusEnCours == "generateSignature"){
        if(exitCode != 0 || exitStatus == QProcess::CrashExit){

            QFile file(outputFileSignaturePath);
            file.remove();
            showMessage("critical", "Une erreur s'est produite lors de la génération du signature.\n Assurez-vous de charger une clé privée valide.");
            return;
        }
        else{
            QFile file(outputFileSignaturePath);
            if(file.exists()){
                file.setPermissions(QFile::ReadOwner | QFile::ReadGroup);
            }
            showMessage("information", "Signature générée avec succès ");
            if(!privateKeyFromDb.isEmpty()){
                           QFile file(tempPathPrivateKey);
                           file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                           file.remove();
                       }

            /*qDebug() << "PrivateKey: " + privateKeyPath;
            qDebug() << "signature: " + outputFileSignaturePath;*/
            QFile filePrivate(privateKeyPath);
            QFileInfo privateKeyInformation(privateKeyPath);
            QString filePrivateContent;
            QString empreintePrivateKey;

            if(filePrivate.open(QIODevice::ReadOnly)){
                filePrivateContent = filePrivate.readAll();
                filePrivate.close();
                empreintePrivateKey = QCryptographicHash::hash(filePrivateContent.toUtf8(), QCryptographicHash::Sha256).toHex();

            } else if(!privateKeyFromDb.isEmpty()){
                empreintePrivateKey = QCryptographicHash::hash(privateKeyFromDb.toUtf8(), QCryptographicHash::Sha256).toHex();

            }


            QString fileName = !privateKeyFromDb.isEmpty() ? fileNamePrivateKeyFromDb : privateKeyInformation.fileName();

            QFile fileSignature(outputFileSignaturePath);
            QString fileContent;
            QString empreinteSignature;

           if(fileSignature.open(QIODevice::ReadOnly)){
               fileContent = fileSignature.readAll();
               fileSignature.close();
               empreinteSignature = QCryptographicHash::hash(fileContent.toUtf8(), QCryptographicHash::Sha256).toHex();
           }


           database.insertSignatureReference(empreinteSignature, empreintePrivateKey, fileName);
           referencesSignature = database.recover_referencesSignatures();

           qDebug() << "Références signatures: " << referencesSignature;

            file_Path = "";
            privateKeyPath = "";
            return;
        }
    }

    else if (processusEnCours == "verifySignature"){

        QString error = opensslProcess->readAllStandardError();
        if (!error.isEmpty()) {
            qDebug() << "OpenSSL Error:" << error;
        }

        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            showMessage("critical", "Une erreur s'est produite lors de l'authentification du fichier.\n Votre fichier a été modifié ou clé publique invalide.");
            return;
        }
        else{
            if(!publicKeyFromDb.isEmpty()){
                QFile file(tempPathPublicKey);
                file.setPermissions(QFile::ReadOwner | QFile::WriteOwner);
                file.remove();
            }
            showMessage("information", "Authentification réussie.\n Le fichier est valide");
            return;
        }
    }

    else if (processusEnCours == "generateSecretKey"){
        QString sortie = opensslProcess->readAllStandardOutput();
        QString error = opensslProcess->readAllStandardError();

       if(!error.isEmpty()){
           qDebug()<<"Erreur" << error;
       }

        if(exitCode != 0 || exitStatus == QProcess::CrashExit){
            showMessage("critical", "Une erreur s'est produite lors de la génération de la clé secrète.");
            return;

        }
        else{
            qDebug() <<"Sortie: " << sortie;

            QString salt, key, ivHex;
            QRegularExpression saltRegex("salt=([0-9A-F]+)");
            QRegularExpression keyRegex("key=([0-9A-F]+)");
            QRegularExpression ivRegex("iv =([0-9A-F]+)");

            QRegularExpressionMatch matchSalt = saltRegex.match(sortie);
            QRegularExpressionMatch matchKey = keyRegex.match(sortie);
            QRegularExpressionMatch matchIv = ivRegex.match(sortie);

            if (matchSalt.hasMatch() && matchKey.hasMatch() && matchIv.hasMatch()) {
                salt = matchSalt.captured(1);
                key = matchKey.captured(1);
                ivHex = matchIv.captured(1);

               /* qDebug() << "Salt:" << salt;
                qDebug() << "Key:" << key;
                qDebug() << "IV:" << ivHex;*/
            }
            iv = ivHex;
            QFile file(symetric_key_path);
            QFileInfo fileInfo(symetric_key_path);

            QString dateCreated = QDate::currentDate().toString("yyyy/MM/dd");
            QString empreinteKey  = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();
            database.InsertSecretKey(fileInfo.fileName().toUpper(), key.toUtf8(), ivHex, salt,empreinteKey, dateCreated, passwordSecretKey);
            passwordSecretKey = "";
            if(database.symetricKeyExist()){
                QMessageBox::warning(this,  tr("SecureMator"), "Cette clé existe déjà.");
                database.resetSecretKeyExitValue();
                return;
            }

            filtedData = database.recover_secretKeys();
            dataSecretKeys = database.recover_secretKeys();


            if(file.open(QIODevice::WriteOnly)){
                QByteArray keyBytes = key.toUtf8();
                file.write(keyBytes +':'+ivHex.toUtf8());
                file.close();
                file.setPermissions(QFile::ReadOwner | QFile::ReadGroup | QFile::ReadOther);
            }

            showMessage("information", "Clé secrète générée avec succès ");
            return;
        }
    }
}


void MainWindow::on_pushButton_4_clicked()
{
    MainWindow::generateSymmetricKey();
}


void MainWindow::on_pushButton_5_clicked()
{
    qint64 maxFileSize = 21474836480;
    double fileSizeInGigabytes = static_cast<double>(maxFileSize) / (1024.0 * 1024.0 * 1024.0);
    QString tempInputFilePath;
    qint64 currentFilesSize =0;


        if (symetric_key_path.isEmpty() && symetricKeyFromDb.isEmpty()) {

               // Afficher un message d'alerte à l'utilisateur
            QMessageBox::warning(this,  tr("SecureMator"), "Veuillez générer ou charger une clé secrète.");
               return;
           }


        QFileInfo file(symetric_key_path);
        QString fileName = !fileNameFromDb.isEmpty() ? fileNameFromDb : file.fileName();


        if(crypted == "1"){
            QFileInfo file(symetric_key_path);
            QString fileName = !fileNameFromDb.isEmpty() ? fileNameFromDb : file.fileName();

            QMessageBox msgBox;
            msgBox.setWindowTitle("SecureMator");
            QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
            msgBox.setWindowIcon(icon);

            msgBox.setText("Voulez-vous utiliser " + fileName + " pour chiffrer ?");

            QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
            QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);

            msgBox.exec();

            if(msgBox.clickedButton()== pButtonYes){
                //Exécute le code
            }
            if(msgBox.clickedButton()==pButtonNo){
                return;
            }
        }


        QStringList extensionFiltre;
        extensionFiltre << "Fichiers (*.*)";

        QStringList inputFilePaths = QFileDialog::getOpenFileNames(this, "Choisir les fichiers à chiffrer (" + fileName +")",
                                                                   !directory.isEmpty() ?  directory : QDir::homePath(), extensionFiltre.join(";;"));

        if (!inputFilePaths.isEmpty()) {
            tempInputFilePath = inputFilePaths.first();
        } else {
               return;
           }

        //Calucle de la taille des fichiers

           for(int i=0; i<inputFilePaths.size(); i++){
               QFileInfo fileInfo(inputFilePaths[i]);
               currentFilesSize += fileInfo.size();
           }

         //Vérification de la taille des fichiers

           if(inputFilePaths.size() > 1 && currentFilesSize > maxFileSize){

               QFileInfo fileInfo(tempInputFilePath);
               directory = fileInfo.absolutePath();
               QString message = QString("La taille de vos fichiers est supérieure à %1 Go. Veuillez réduire le nombre de fichiers").arg(fileSizeInGigabytes);
               showMessage("warning", message);
               QStringList inputFilePaths = QFileDialog::getOpenFileNames(this, "Choisir les fichiers à chiffrer (" + file.fileName() +")",
                                                                         directory, extensionFiltre.join(";;"));

               if (inputFilePaths.isEmpty()) {
                      return;
                  }
           }

           MainWindow::encryptFiles(inputFilePaths);
           QFileInfo fileInfo(tempInputFilePath);
           directory = fileInfo.absolutePath();
    }


//Déchiffrement
void MainWindow::on_pushButton_10_clicked()
{

    qint64 maxFileSize = 21474836480;
    double fileSizeInGigabytes = static_cast<double>(maxFileSize) / (1024.0 * 1024.0 * 1024.0);
    QString tempInputFilePath;
    qint64 currentFilesSize =0;

   // qDebug() << "Vérification: " + symetricKeyFromDb;
    if (symetric_key_path_for_decryption.isEmpty()  && symetricKeyFromDb.isEmpty()) {
           // Afficher un message d'alerte à l'utilisateur
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez charger une clé secrète");
           return;
       }

    QFileInfo file(symetric_key_path_for_decryption);
    QString fileName = !fileNameFromDb.isEmpty() ? fileNameFromDb : file.fileName();

    if(decrypted == "1"){
        QFileInfo file(symetric_key_path_for_decryption);
        QString fileName = !fileNameFromDb.isEmpty() ? fileNameFromDb : file.fileName();

        QMessageBox msgBox;
        msgBox.setWindowTitle("SecureMator");
        QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
        msgBox.setWindowIcon(icon);

        msgBox.setText("Voulez-vous utiliser " + fileName + " pour déchiffrer ?");

        QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
        QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);

        msgBox.exec();

        if(msgBox.clickedButton()== pButtonYes){
            //Exécute le code
        }
        if(msgBox.clickedButton()==pButtonNo){
            return;
        }
    }
    QStringList inputFilePaths = QFileDialog::getOpenFileNames(this, "Choisir les fichiers à déchiffrer (" + fileName +")",
                                                               !directoryFilesCrypted.isEmpty() ?  directoryFilesCrypted :
                                                                !directory_for_filesCrypted.isEmpty() ? directory_for_filesCrypted:
                                                                QDir::homePath(), "Fichiers (*.exe)");

    if (!inputFilePaths.isEmpty()) {
        tempInputFilePath = inputFilePaths.first();
    } else {
           return;
       }


    //Calucle de la taille des fichiers

       for(int i=0; i<inputFilePaths.size(); i++){
           QFileInfo fileInfo(inputFilePaths[i]);
           currentFilesSize += fileInfo.size();
       }

     //Vérification de la taille des fichiers

       if(inputFilePaths.size() > 1 && currentFilesSize > maxFileSize){

           QFileInfo fileInfo(tempInputFilePath);
           directory_for_filesCrypted = fileInfo.absolutePath();
           QString message = QString("La taille de vos fichiers est supérieure à %1 Go. Veuillez réduire le nombre de fichiers").arg(fileSizeInGigabytes);
           showMessage("warning", message);
           QStringList inputFilePaths = QFileDialog::getOpenFileNames(this, "Choisir les fichiers à déchiffrer (" + file.fileName() +")",
                                                                      !directoryFilesCrypted.isEmpty() ?  directoryFilesCrypted :
                                                                       !directory_for_filesCrypted.isEmpty() ? directory_for_filesCrypted:
                                                                       QDir::homePath(), "Fichiers (*.exe)");

           if (inputFilePaths.isEmpty()) {
                  return;
              }
       }


    MainWindow::decryptFiles(inputFilePaths);
    QFileInfo fileInfo(tempInputFilePath);
    directory_for_filesCrypted = fileInfo.absolutePath();
}


void MainWindow::on_pushButton_6_clicked()
{

    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé secrète",
                                                       !temp_symetric_key_path.isEmpty() ? temp_symetric_key_path :
                                                                                           QDir::homePath(),"(*.dat)");

    if(keyFilePath.isEmpty()){
        return;
    }

    QString empreintekey;
    QByteArray key;

    QFile file(keyFilePath);

    if(file.open(QIODevice::ReadOnly)){
        key = file.readAll();
        file.close();
    }

    qDebug() <<"La clé" << key;
    QStringList keyParts = QString(key).split(':');

    empreintekey =  QCryptographicHash::hash(keyParts[0].toUtf8(), QCryptographicHash::Sha256).toHex();

    QString passwordDb;
    passwordDb = database.getPassword(empreintekey);
    bool ok;
    QInputDialog passwordDialog(this);
    QString password;

    do{
         password = passwordDialog.getText(this, "Mot de passe", "Entrez le mot de passe pour la clé secrète :", QLineEdit::Password, "", &ok);

        if(password.isEmpty()){
            return;
        }

        password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

        if(password == passwordDb){
            passwordDb = password;
        }
        else{
            QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
        }
    } while(passwordDb != password);

    symetric_key_path = keyFilePath;
    QFileInfo fileInfo(keyFilePath);
    QString fileName = fileInfo.fileName();
    temp_symetric_key_path  = fileInfo.absolutePath();

    showMessage("information", fileName + " charger avec succès");
    symetricKeyFromDb = "";
    fileNameFromDb = "";
    iv = database.getIV(empreintekey);
    crypted = "0";

    //qDebug() << crypted;
}


void MainWindow::on_pushButton_7_clicked()
{
    continueEncryption = false;
       if (opensslProcess->state() == QProcess::Running) {
           opensslProcess->kill();
           ui->frame->setVisible(false);
           qDebug() << "Chiffrement arrêté par l'utilisateur";
       }
}


void MainWindow::on_pushButton_2_clicked()
{
    if(opensslProcess->state() == QProcess::Running){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez attendre la fin de l'opération en cours.");
        return;
    }
    zoneDechiffrementClicked = true;


    QPixmap pixmap(QCoreApplication::applicationDirPath() + "/images/Sans titre-1.jpg");
    int w =ui->label_9->width();
    int h = ui->label_9->height();
    ui->label_9->setPixmap(pixmap.scaled(w,h, Qt::KeepAspectRatio));

    QPixmap logo_here(QCoreApplication::applicationDirPath() + "/images/go-down.png");
    int w_logoHere = ui->label_10->width();
    int h_logoHere = ui->label_10->height();
    ui->label_10->setPixmap(logo_here.scaled(w_logoHere, h_logoHere, Qt::KeepAspectRatio));

    QPixmap file_logo(QCoreApplication::applicationDirPath() + "/images/paper.png");
    int w_fileLogo = ui->label_12->width();
    int h_fileLogo = ui->label_12->height();
    ui->label_12->setPixmap(file_logo.scaled(w_fileLogo, h_fileLogo, Qt::KeepAspectRatio));

    int w_logoHere2 = ui->label_27->width();
    int h_logoHere2 = ui->label_27->height();
    ui->label_27->setPixmap(logo_here.scaled(w_logoHere2, h_logoHere2, Qt::KeepAspectRatio));

    QPixmap logo_here3 (QCoreApplication::applicationDirPath() + "/images/unlocked.png");
    int w_logoHere3 = ui->label_29->width();
    int h_logoHere3 = ui->label_29->height();
    ui->label_29->setPixmap(logo_here3.scaled(w_logoHere3, h_logoHere3, Qt::KeepAspectRatio));

    ui->pushButton_8->setCursor(Qt::PointingHandCursor);
    ui->pushButton_9->setCursor(Qt::PointingHandCursor);
    ui->pushButton_10->setCursor(Qt::PointingHandCursor);
    ui->pushButton_23->setCursor(Qt::PointingHandCursor);
    ui->pushButton_24->setCursor(Qt::PointingHandCursor);


    QIcon arrowIcon(QCoreApplication::applicationDirPath() + "/images/left.png");
    ui->pushButton_8->setIcon(arrowIcon);
    ui->pushButton_8->setIconSize(QSize(20, 20));
    ui->stackedWidget->setCurrentIndex(1);
}


void MainWindow::on_pushButton_8_clicked()
{
    if(opensslProcess->state() == QProcess::Running){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez attendre la fin de l'opération en cours.");
        return;
    }

    ui->stackedWidget->setCurrentIndex(0);
}


void MainWindow::on_pushButton_9_clicked()
{
    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé secrète",
                                                       !temp_symetric_key_path_for_decryption.isEmpty() ? temp_symetric_key_path :
                                                                                           QDir::homePath(),"(*.dat)");
    if(keyFilePath.isEmpty()){
        return;
    }

    QString empreintekey;
    QByteArray key;

    QFile file(keyFilePath);

    if(file.open(QIODevice::ReadOnly)){
        key = file.readAll();
        file.close();
    }


    qDebug() <<"La clé" << key;
    empreintekey =  QCryptographicHash::hash(key, QCryptographicHash::Sha256).toHex();

    QStringList keyParts  = QString(key).split(':');

    symetric_key_path_for_decryption = keyFilePath;

    QFileInfo fileInfo(keyFilePath);
    QString fileName = fileInfo.fileName();
    temp_symetric_key_path_for_decryption = fileInfo.absolutePath();

    showMessage("information", fileName + " charger avec succès");
    iv =  keyParts[1];
    symetricKeyFromDb = "";
    fileNameFromDb = "";
    decrypted = "0";
}


void MainWindow::on_pushButton_11_clicked()
{
    continueDecryption = false;
       if (opensslProcess->state() == QProcess::Running) {
           opensslProcess->kill();
           ui->frame_6->setVisible(false);
           qDebug() << "Déchiffrement arrêté par l'utilisateur";
       }
}


void MainWindow::on_pushButton_3_clicked()
{

    if(opensslProcess->state() == QProcess::Running){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez attendre la fin de l'opération en cours.");
        return;
    }

    ui->pushButton_15->setCursor(Qt::PointingHandCursor);
    ui->pushButton_16->setCursor(Qt::PointingHandCursor);
    ui->pushButton_17->setCursor(Qt::PointingHandCursor);
    ui->pushButton_18->setCursor(Qt::PointingHandCursor);
    ui->pushButton_19->setCursor(Qt::PointingHandCursor);


    QIcon arrowIcon(QCoreApplication::applicationDirPath() + "/images/left.png");
    ui->pushButton_12->setIcon(arrowIcon);
    ui->pushButton_12->setIconSize(QSize(20,20));
    ui->pushButton_12->setCursor(Qt::PointingHandCursor);

    QIcon security(QCoreApplication::applicationDirPath() + "/images/security.png");
    ui->pushButton_13->setIcon(security);
    ui->pushButton_13->setIconSize(QSize(20,20));
    ui->pushButton_13->setCursor(Qt::PointingHandCursor);

    QIcon key(QCoreApplication::applicationDirPath() + "/images/approve.png");
    ui->pushButton_14->setIcon(key);
    ui->pushButton_14->setIconSize(QSize(20,20));
    ui->pushButton_14->setCursor(Qt::PointingHandCursor);

    QPixmap backgroundImage(QCoreApplication::applicationDirPath() + "/images/2151637765.jpg");
    int w = ui->label_16->width();
    int h = ui->label_16->height();
    ui->label_16->setPixmap(backgroundImage.scaled(w,h, Qt::KeepAspectRatio));

    ui->stackedWidget->setCurrentIndex(2);
}


void MainWindow::on_pushButton_12_clicked()
{
 qDebug()<< "Mot de passe: " + passwordPrivateKey;
    ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::on_pushButton_15_clicked()
{
 MainWindow::generatePrivateKeyWithPassword();
}


void MainWindow::on_pushButton_16_clicked()
{
    MainWindow::generateRSAPublicKey();
}


void MainWindow::on_pushButton_14_clicked()
{
    ui->pushButton->setCursor(Qt::PointingHandCursor);
    QIcon arrowIcon(QCoreApplication::applicationDirPath() + "/images/left.png");
    ui->pushButton->setIcon(arrowIcon);
    ui->pushButton->setIconSize(QSize(20,20));

    ui->pushButton_25->setCursor(Qt::PointingHandCursor);
    ui->pushButton_26->setCursor(Qt::PointingHandCursor);
    ui->pushButton_27->setCursor(Qt::PointingHandCursor);
    ui->pushButton_28->setCursor(Qt::PointingHandCursor);

    QPixmap backgroundImage(QCoreApplication::applicationDirPath() + "/images/3820574.jpg");
    int w = ui->label_21->width();
    int h = ui->label_21->height();
    ui->label_21->setPixmap(backgroundImage.scaled(w,h, Qt::KeepAspectRatio));


    QPixmap image(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
    int width = ui->label_30->width();
    int height = ui->label_30->height();
    ui->label_30->setPixmap(image.scaled(width,height, Qt::KeepAspectRatio));

    ui->stackedWidget->setCurrentIndex(4);
}


void MainWindow::on_pushButton_clicked()
{
    ui->stackedWidget->setCurrentIndex(2);
}


void MainWindow::on_pushButton_13_clicked()
{
    ui->pushButton_21->setCursor(Qt::PointingHandCursor);
    ui->pushButton_22->setCursor(Qt::PointingHandCursor);

    QPixmap backgroundImage(QCoreApplication::applicationDirPath() + "/images/3820574.jpg");
    int w = ui->label_22->width();
    int h = ui->label_22->height();
    ui->label_22->setPixmap(backgroundImage.scaled(w,h, Qt::KeepAspectRatio));

    QPixmap pixmap(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
    int w_logo = ui->label_24->width();
    int h_logo = ui->label_24->height();
    ui->label_24->setPixmap(pixmap.scaled(w_logo,h_logo, Qt::KeepAspectRatio));

    QIcon arrowIcon(QCoreApplication::applicationDirPath() + "/images/left.png");
    ui->pushButton_20->setIcon(arrowIcon);
    ui->pushButton_20->setIconSize(QSize(20,20));
    ui->pushButton_20->setCursor(Qt::PointingHandCursor);

    ui->stackedWidget->setCurrentIndex(3);
}


void MainWindow::on_pushButton_20_clicked()
{
    symetric_key_path = "";
    ui->stackedWidget->setCurrentIndex(2);

}

void MainWindow::on_pushButton_22_clicked()
{
    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé publique",
                                                       !temp_publicKeyPath.isEmpty() ? temp_publicKeyPath :
                                                                                           QDir::homePath(),"(*.pub)");

    if(keyFilePath.isEmpty()){
        return;
    }

    publicKeyPath = keyFilePath;


    QFileInfo fileInfo(keyFilePath);
    QString fileName = fileInfo.fileName();
    temp_publicKeyPath  = fileInfo.absolutePath();
    publicKeyFromDb = "";
    fileNamePublicKeyFromDb = "";
    showMessage("information", fileName + " charger avec succès");
    cryptedKey = "0";
}


void MainWindow::on_pushButton_21_clicked()
{
    if (publicKeyPath.isEmpty() && publicKeyFromDb.isEmpty()) {
           // Afficher un message d'alerte à l'utilisateur
         QMessageBox::warning(this,  tr("SecureMator"), "Veuillez charger la clé publique.");
        return;
       }

    QFileInfo key(publicKeyPath);
    QString fileName = !publicKeyFromDb.isEmpty() ? fileNamePublicKeyFromDb : key.fileName();

    if(cryptedKey == "1"){
        QFileInfo file(publicKeyPath);
        QString fileName = !publicKeyFromDb.isEmpty() ? fileNamePublicKeyFromDb : file.fileName();

        QMessageBox msgBox;
        msgBox.setWindowTitle("SecureMator");
        QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
        msgBox.setWindowIcon(icon);

        msgBox.setText("Voulez-vous utiliser " + fileName + " pour chiffrer ?");

        QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
        QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);

        msgBox.exec();

        if(msgBox.clickedButton()== pButtonYes){
            //Exécute le code
        }
        if(msgBox.clickedButton()==pButtonNo){
            return;
        }
    }

    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé secrète (" + fileName + ")",
                                                       !temp_symetric_key_path.isEmpty() ? temp_symetric_key_path :
                                                                                           QDir::homePath(),"(*.dat)");
    if(keyFilePath.isEmpty()){
        return;
    }
    symetric_key_path = keyFilePath;
    QFileInfo fileInfo(keyFilePath);
    temp_symetric_key_path = fileInfo.absolutePath();

    MainWindow::encryptSymmetricKey(symetric_key_path, publicKeyPath);
}


void MainWindow::on_pushButton_23_clicked()
{

    if(opensslProcess->state() == QProcess::Running){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez attendre la fin de l'opération en cours.");
        return;
    }

    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé privée",
                                                       !directoryPrivateKey.isEmpty() ? directoryPrivateKey :
                                                                                           QDir::homePath(),"(*.pem)");
    if(keyFilePath.isEmpty()){
           return;
       }

    QFile file(keyFilePath);
    QString key;
    if(file.open(QIODevice::ReadOnly)){
        key = file.readAll();
        file.close();
    }
    QString empreinte = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();
    QString passwordFromDb = database.getPasswordPrivateKey(empreinte);

    bool ok;
       do{
           QString password = QInputDialog::getText(this, "Mot de passe", "Entrez le mot de passe de la clé privée:", QLineEdit::Password, "", &ok);
           if (!ok || password.isEmpty()) {
               return;
           }

           password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

           if(passwordFromDb == password){
               break;
           } else{
               QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
           }

       }while(true);

      passwordPrivateKey = passwordFromDb;

    privateKeyPath = keyFilePath;
    QFileInfo fileInfo(keyFilePath);
    QString fileName = fileInfo.fileName();
    directoryPrivateKey = fileInfo.absolutePath();
    privateKeyFromDb = "";
    fileNamePrivateKeyFromDb = "";
    showMessage("information", fileName + " charger avec succès");
    decryptedKey = "0";

}


void MainWindow::on_pushButton_24_clicked()
{

    if(opensslProcess->state() == QProcess::Running){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez attendre la fin de l'opération en cours.");
        return;
    }

    if (privateKeyPath.isEmpty() && privateKeyFromDb.isEmpty()) {
           // Afficher un message d'alerte à l'utilisateur
         QMessageBox::warning(this,  tr("SecureMator"), "Veuillez charger la clé privée.");
        return;
       }

    QFileInfo key(privateKeyPath);
    QString fileName = !privateKeyFromDb.isEmpty() ? fileNamePrivateKeyFromDb : key.fileName();

    if(decryptedKey == "1"){
        QFileInfo file(privateKeyPath);
        QString fileName = !privateKeyFromDb.isEmpty() ? fileNamePrivateKeyFromDb : file.fileName();

        QMessageBox msgBox;
        msgBox.setWindowTitle("SecureMator");
        QIcon icon(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
        msgBox.setWindowIcon(icon);

        msgBox.setText("Voulez-vous utiliser " + fileName + " pour déchiffrer ?");

        QAbstractButton* pButtonYes = msgBox.addButton(tr("Oui"), QMessageBox::YesRole);
        QAbstractButton* pButtonNo = msgBox.addButton(tr("Non"), QMessageBox::NoRole);

        msgBox.exec();

        if(msgBox.clickedButton()== pButtonYes){
            //Exécute le code
        }
        if(msgBox.clickedButton()==pButtonNo){
            return;
        }
    }

    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé secrète chifrrée (" + fileName + ")",
                                                       !directorySymetrickeyCypherPath.isEmpty() ? directorySymetrickeyCypherPath :
                                                                                           QDir::homePath(),"(*.exe)");
    if(keyFilePath.isEmpty()){
        return;
    }
    symetric_key_cypher_path = keyFilePath;
    QFileInfo fileInfo(keyFilePath);
    directorySymetrickeyCypherPath = fileInfo.absolutePath();



    MainWindow::decryptSymmetricKey(symetric_key_cypher_path, privateKeyPath);
    decryptedKey = "1";
}


void MainWindow::on_pushButton_17_clicked()
{
    QString filePath =QFileDialog::getOpenFileName(this, "Sélectionner un fichier ",
                                                   !directoryFilePath.isEmpty() ? directoryFilePath :
                                                                                     QDir::homePath(),"(*.*)");

     if(filePath.isEmpty()){
         return;
     }

    file_Path = filePath;
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    directoryFilePath = fileInfo.absolutePath();
    showMessage("information", fileName + " charger avec succès");

}


void MainWindow::on_pushButton_18_clicked()
{
    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé privée",
                                                       !directoryPrivateKey.isEmpty() ? directoryPrivateKey :
                                                                                           QDir::homePath(),"(*.pem)");
    if(keyFilePath.isEmpty()){
           return;
       }

    QFile file(keyFilePath);
    QString key;
    if(file.open(QIODevice::ReadOnly)){
        key = file.readAll();
        file.close();
    }
    QString empreinte = QCryptographicHash::hash(key.toUtf8(), QCryptographicHash::Sha256).toHex();
    QString passwordFromDb = database.getPasswordPrivateKey(empreinte);

    bool ok;
       do{
           QString password = QInputDialog::getText(this, "Mot de passe", "Entrez le mot de passe de la clé privée:", QLineEdit::Password, "", &ok);
           if (!ok || password.isEmpty()) {
               return;
           }

           password = QCryptographicHash::hash(password.toUtf8(), QCryptographicHash::Sha256).toHex();

           if(passwordFromDb == password){
               break;
           } else{
               QMessageBox::warning(this,  tr("SecureMator"), "Mot de passe incorrect.");
           }

       }while(true);

    passwordPrivateKey = passwordFromDb;


    privateKeyPath = keyFilePath;
    QFileInfo fileInfo(keyFilePath);
    QString fileName = fileInfo.fileName();
    directoryPrivateKey = fileInfo.absolutePath();
    privateKeyFromDb = "";
    fileNamePrivateKeyFromDb = "";
    showMessage("information", fileName + " charger avec succès");
}


void MainWindow::on_pushButton_19_clicked()
{
    if (file_Path.isEmpty()) {
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner un fichier.");
            return;
       }
    if (privateKeyPath.isEmpty() && privateKeyFromDb.isEmpty()) {
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez charger la clé privée.");
            return;
       }

       MainWindow::signFile(file_Path, privateKeyPath);

}


void MainWindow::on_pushButton_27_clicked()
{
    QString filePath =QFileDialog::getOpenFileName(this, "Sélectionner un fichier ",
                                                   !directoryFilePath.isEmpty() ? directoryFilePath :
                                                                                     QDir::homePath(),"(*.*)");

     if(filePath.isEmpty()){
         return;
     }

    file_Path = filePath;
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    directoryFilePath = fileInfo.absolutePath();
    showMessage("information", fileName + " charger avec succès");
}


void MainWindow::on_pushButton_25_clicked()
{
    QString filePath =QFileDialog::getOpenFileName(this, "Sélectionner la signature ",
                                                   !directorySignaturePath.isEmpty() ? directorySignaturePath :
                                                                                     QDir::homePath(),"(*.msi)");

     if(filePath.isEmpty()){
         return;
     }

    signature = filePath;
    QFileInfo fileInfo(filePath);
    QString fileName = fileInfo.fileName();
    directorySignaturePath = fileInfo.absolutePath();
    showMessage("information", fileName + " charger avec succès");
}


void MainWindow::on_pushButton_26_clicked()
{
    QFileInfo fileInfoForfile(!file_Path.isEmpty() ? file_Path : "");
    QString file = "("+fileInfoForfile.fileName() +") ";

    QFileInfo fileInfoForSignature(!signature.isEmpty() ? signature : "");
    QString signatureName = " (" + fileInfoForSignature.fileName() + ")";

    QFileInfo fileInfoForPublicKey(!publicKeyPath.isEmpty() ? publicKeyPath : "");
    QString publicKeyName = !fileNamePublicKeyFromDb.isEmpty() ? fileNamePublicKeyFromDb :  fileInfoForPublicKey.fileName() ;



    QString keyFilePath = QFileDialog::getOpenFileName(this, "Sélectionner la clé publique " + file + signatureName + " ("+ publicKeyName + ")",
                                                       !temp_publicKeyPath.isEmpty() ? temp_publicKeyPath :
                                                                                           QDir::homePath(),"(*.pub)");

    if(keyFilePath.isEmpty()){
        return;
    }

    publicKeyPath = keyFilePath;



    QFileInfo fileInfo(keyFilePath);
    QString fileName = fileInfo.fileName();

    temp_publicKeyPath  = fileInfo.absolutePath();
    publicKeyFromDb = "";
    fileNamePublicKeyFromDb = "";
    showMessage("information", fileName + " charger avec succès");
}


void MainWindow::on_pushButton_28_clicked()
{

    if (file_Path.isEmpty()) {
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner un fichier.");
            return;
       }

    if (publicKeyPath.isEmpty() && publicKeyFromDb.isEmpty()) {
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez charger la clé publique.");
            return;
       }
    if(signature.isEmpty()){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez charger la signature.");
            return;
    }

    MainWindow::verifySignature(file_Path, signature ,publicKeyPath);
}

QGraphicsDropShadowEffect* buildShadow(QGraphicsDropShadowEffect* shadow){
    shadow->setBlurRadius(10);  // Définit la taille de l'ombre
    shadow->setOffset(2, 2);    // Déplace légèrement l'ombre
    shadow->setColor(QColor(0, 0, 0, 80));  // Couleur et transparence de l'ombre

    return shadow;
}

void MainWindow::on_pushButton_57_clicked()
{
    if(opensslProcess->state() == QProcess::Running){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez attendre la fin de l'opération en cours.");
        return;
    }

    getSecretKeys();
    getPrivateKeys();
    getPublicKeys();

    QGraphicsDropShadowEffect* shadowEffect = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect);
    QGraphicsDropShadowEffect* shadowEffect2 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect2);
    QGraphicsDropShadowEffect* shadowEffect3 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect3);
    QGraphicsDropShadowEffect* shadowEffect4 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect4);
    QGraphicsDropShadowEffect* shadowEffect5 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect5);
    QGraphicsDropShadowEffect* shadowEffect6 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect6);
    QGraphicsDropShadowEffect* shadowEffect7 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect7);
    QGraphicsDropShadowEffect* shadowEffect8 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect8);
    QGraphicsDropShadowEffect* shadowEffect9 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect9);

    QGraphicsDropShadowEffect* shadowEffect10 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect10);
    QGraphicsDropShadowEffect* shadowEffect11 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect11);
    QGraphicsDropShadowEffect* shadowEffect12 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect12);
    QGraphicsDropShadowEffect* shadowEffect13 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect13);
    QGraphicsDropShadowEffect* shadowEffect14 = new QGraphicsDropShadowEffect();
    buildShadow(shadowEffect14);

    ui->pushButton_32->setCursor(Qt::PointingHandCursor);
    ui->pushButton_34->setCursor(Qt::PointingHandCursor);
    ui->pushButton_36->setCursor(Qt::PointingHandCursor);
    ui->pushButton_37->setCursor(Qt::PointingHandCursor);
    ui->pushButton_38->setCursor(Qt::PointingHandCursor);
    ui->pushButton_39->setCursor(Qt::PointingHandCursor);

    QPixmap pixmap(QCoreApplication::applicationDirPath() + "/images/Sans titre-2.jpg");
    int w = ui->label_34->width();
    int h = ui->label_34->height();
    ui->label_34->setPixmap(pixmap.scaled(w,h, Qt::KeepAspectRatio));


    QPixmap logo(QCoreApplication::applicationDirPath() + "/images/key_12986731.png");
    int width = ui->label_35->width();
    int height = ui->label_35->height();
    ui->label_35->setPixmap(logo.scaled(width,height, Qt::KeepAspectRatio));

    QIcon arrowIcon(QCoreApplication::applicationDirPath() + "/images/left.png");
    ui->pushButton_29->setIcon(arrowIcon);
    ui->pushButton_29->setIconSize(QSize(15,15));
    ui->pushButton_29->setCursor(Qt::PointingHandCursor);

    ui->frame_10->setGraphicsEffect(shadowEffect);
    ui->frame_9->setGraphicsEffect(shadowEffect2);
    ui->frame_12->setGraphicsEffect(shadowEffect3);

    ui->frame_14->setGraphicsEffect(shadowEffect4);
    ui->frame_15->setGraphicsEffect(shadowEffect5);
    ui->frame_16->setGraphicsEffect(shadowEffect6);

    ui->frame_18->setGraphicsEffect(shadowEffect7);
    ui->frame_19->setGraphicsEffect(shadowEffect8);
    ui->frame_20->setGraphicsEffect(shadowEffect9);

    ui->frame_22->setGraphicsEffect(shadowEffect10);
    ui->frame_23->setGraphicsEffect(shadowEffect11);
    ui->frame_24->setGraphicsEffect(shadowEffect12);
    ui->frame_25->setGraphicsEffect(shadowEffect13);
    ui->frame_26->setGraphicsEffect(shadowEffect14);

    ui->calendarWidget->setGridVisible(true);
    ui->calendarWidget_2->setGridVisible(true);
    ui->calendarWidget_3->setGridVisible(true);

    QDate startDate = ui->dateEdit->date();
    beginDate = startDate.toString("yyyy/MM/dd");
    QDate finDate = ui->dateEdit_2->date();
    endDate = finDate.toString("yyyy/MM/dd");

    QDate startDateprivateKey = ui->dateEdit_3->date();
    beginDatePrivateKey = startDateprivateKey.toString("yyyy/MM/dd");
    QDate finDatePrivateKey = ui->dateEdit_4->date();
    endDatePrivateKey = finDatePrivateKey.toString("yyyy/MM/dd");

    QDate startDatepublicKey = ui->dateEdit_5->date();
    beginDatePublicKey = startDatepublicKey.toString("yyyy/MM/dd");
    QDate finDatePublicKey = ui->dateEdit_6->date();
    endDatePublicKey = finDatePublicKey.toString("yyyy/MM/dd");


    ui->stackedWidget->setCurrentIndex(5);
}


void MainWindow::on_pushButton_29_clicked()
{
    ui->stackedWidget->setCurrentIndex(0);
}


void MainWindow::on_lineEdit_textChanged(const QString &arg1)
{
    QString lowerArg1 = arg1.toLower();
    QStringList row;
    QVector<QStringList> tempData;
    QString fileName;

    for(int i=0; i<dataSecretKeys.size(); i++){
        row = dataSecretKeys[i];
        fileName =row[1].toLower();
        if(fileName.contains(lowerArg1)){
            tempData.append(row);
        }
    }
    ui->tableWidget->clear();
    filtedData = tempData;
    getSecretKeys();
}


void MainWindow::on_calendarWidget_clicked(const QDate &date)
{

    dateSelected = date.toString("yyyy/MM/dd");

    filtedData = database.filterByDate(dateSelected);
    getSecretKeys();

}

void MainWindow::on_dateEdit_userDateChanged(const QDate &date)
{
    beginDate = date.toString("yyyy/MM/dd");
    qDebug() << " Date début: " + beginDate;
}


void MainWindow::on_dateEdit_2_userDateChanged(const QDate &date)
{
    endDate = date.toString("yyyy/MM/dd");
    qDebug() << " Date de fin: " + endDate;
}


void MainWindow::on_pushButton_32_clicked()
{
   filtedData = database.filterByPeriod(beginDate,endDate);
   getSecretKeys();

}

void MainWindow::on_pushButton_37_clicked()
{
    filtedData = database.recover_secretKeys();
    getSecretKeys();
}

void MainWindow::on_calendarWidget_2_clicked(const QDate &date)
{
    dateSelected = date.toString("yyyy/MM/dd");
    dataPrivateKeys = database.filterByDatePrivateKey(dateSelected);
    getPrivateKeys();


}

void MainWindow::on_pushButton_34_clicked()
{
    dataPrivateKeys = database.filterByPeriodPrivateKey(beginDatePrivateKey,endDatePrivateKey);
    getPrivateKeys();
}


void MainWindow::on_dateEdit_3_userDateChanged(const QDate &date)
{
    beginDatePrivateKey = date.toString("yyyy/MM/dd");

}


void MainWindow::on_dateEdit_4_userDateChanged(const QDate &date)
{
    endDatePrivateKey = date.toString("yyyy/MM/dd");

}

void MainWindow::on_calendarWidget_3_clicked(const QDate &date)
{
    dateSelected = date.toString("yyyy/MM/dd");
    dataPublicKeys = database.filterByDatePublicKey(dateSelected);
    getPublicKeys();
}


void MainWindow::on_pushButton_36_clicked()
{
    dataPublicKeys = database.filterByPeriodPublicKey(beginDatePublicKey,endDatePublicKey);
    getPublicKeys();
}


void MainWindow::on_dateEdit_5_userDateChanged(const QDate &date)
{
    beginDatePublicKey = date.toString("yyyy/MM/dd");

}


void MainWindow::on_dateEdit_6_userDateChanged(const QDate &date)
{
    endDatePublicKey = date.toString("yyyy/MM/dd");
}


void MainWindow::on_pushButton_38_clicked()
{
    dataPrivateKeys = database.recover_privateKeys();
    getPrivateKeys();
}


void MainWindow::on_pushButton_39_clicked()
{
    dataPublicKeys = database.recover_publicKeys();
    getPublicKeys();
}

void MainWindow::on_lineEdit_2_textChanged(const QString &arg1)
{
    QString lowerArg1 = arg1.toLower();
    QStringList row;
    QVector<QStringList> tempData;
    QString fileName;

    for(int i=0; i<recordPrivateKeys.size(); i++){
        row = recordPrivateKeys[i];
        fileName =row[1].toLower();
        if(fileName.contains(lowerArg1)){
            tempData.append(row);
        }
    }
    ui->tableWidget_2->clear();
    dataPrivateKeys = tempData;
    getPrivateKeys();
}

void MainWindow::on_lineEdit_3_textChanged(const QString &arg1)
{
    QString lowerArg1 = arg1.toLower();
    QStringList row;
    QVector<QStringList> tempData;
    QString fileName;

    for(int i=0; i<recordPublicKeys.size(); i++){
        row = recordPublicKeys[i];
        fileName =row[1].toLower();
        if(fileName.contains(lowerArg1)){
            tempData.append(row);
        }
    }
    ui->tableWidget_3->clear();
    dataPublicKeys = tempData;
    getPublicKeys();
}


void MainWindow::on_pushButton_30_clicked()
{
     inputFileCryptedPaths = QFileDialog::getOpenFileNames(this, "Choisir les fichiers chiffrés ",
                                                             QDir::homePath(),  "(*.exe)" );
     if(inputFileCryptedPaths.isEmpty()){
         return;
     }

    if(inputFileCryptedPaths.size() == 1){
        showMessage("information", "Fichier charger avec succès");

    }else{
        showMessage("information", "Fichiers charger avec succès");

    }

}


void MainWindow::on_pushButton_31_clicked()
{
    if(inputFileCryptedPaths.isEmpty()){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner un fichier chiffré.");
            return;
    }

    for(int i=0 ; i < inputFileCryptedPaths.size(); i++){

        QFile file(inputFileCryptedPaths[i]);
        QFileInfo fileInfo(inputFileCryptedPaths[i]);
        QString fileContent;
        QString empreinteFileCrypted;

        if(file.open(QIODevice::ReadOnly)){
            fileContent = file.readAll();
            file.close();
            empreinteFileCrypted = QCryptographicHash::hash(fileContent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
        QString keyName;
        keyName = database.findSecretKeyName(empreinteFileCrypted);
        qDebug() << "L'empreinte: " + empreinteFileCrypted;

        if(keyName.isEmpty()){
            QMessageBox::warning(this,  tr("SecureMator"), "La Clé Secrète correspondante à " + fileInfo.fileName() + " est introuvable.");
        }else{
            showMessage("information","La Clé Secrète correspondante " + fileInfo.fileName() + " est: " + keyName + ".");
        }
    }

}


void MainWindow::on_pushButton_33_clicked()
{
    inputKeyCryptedPaths = QFileDialog::getOpenFileNames(this, "Choisir les clés secrètes chiffrées ",
                                                            QDir::homePath(),  "(*.exe)" );
    if(inputKeyCryptedPaths.isEmpty()){
        return;
    }

   if(inputKeyCryptedPaths.size() == 1){
       showMessage("information", "Clé secrète charger avec succès");

   }else{
       showMessage("information", "Clés secrètes charger avec succès");

   }

}


void MainWindow::on_pushButton_35_clicked()
{
    if(inputKeyCryptedPaths.isEmpty()){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner une Clé secrète chiffrée.");
            return;
    }

    for(int i=0 ; i < inputKeyCryptedPaths.size(); i++){

        QFile file(inputKeyCryptedPaths[i]);
        QFileInfo fileInfo(inputKeyCryptedPaths[i]);
        QString fileContent;
        QString empreinteFileCrypted;

        if(file.open(QIODevice::ReadOnly)){
            fileContent = file.readAll();
            file.close();
            empreinteFileCrypted = QCryptographicHash::hash(fileContent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
        QString keyName;
        keyName = database.findPublicKeyName(empreinteFileCrypted);
        qDebug() << "L'empreinte: " + empreinteFileCrypted;

        if(keyName.isEmpty()){
            QMessageBox::warning(this,  tr("SecureMator"), "La Clé Publique correspondante à " + fileInfo.fileName() + " est introuvable.");
        }else{
            showMessage("information","La Clé Publique correspondante " + fileInfo.fileName() + " est: " + keyName + ".");
        }
}
}

void MainWindow::on_pushButton_40_clicked()
{
    privateKeysPaths = QFileDialog::getOpenFileNames(this, "Choisir les clés privées ",
                                                            QDir::homePath(),  "(*.pem)" );
    if(privateKeysPaths.isEmpty()){
        return;
    }

   if(privateKeysPaths.size() == 1){
       showMessage("information", "Clé privée charger avec succès");

   }else{
       showMessage("information", "Clés privées charger avec succès");

   }
}


void MainWindow::on_pushButton_41_clicked()
{
    if(privateKeysPaths.isEmpty()){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner une Clé Privée.");
            return;
    }

    for(int i=0 ; i < privateKeysPaths.size(); i++){

        QFile file(privateKeysPaths[i]);
        QFileInfo fileInfo(privateKeysPaths[i]);
        QString fileContent;
        QString empreintePrivatekey;

        if(file.open(QIODevice::ReadOnly)){
            fileContent = file.readAll();
            file.close();
            empreintePrivatekey = QCryptographicHash::hash(fileContent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
        QString keyName;
        keyName = database.findPubKeyName(empreintePrivatekey);
        qDebug() << "L'empreinte: " + empreintePrivatekey;

        if(keyName.isEmpty()){
            QMessageBox::warning(this,  tr("SecureMator"), "La Clé Publique correspondante à " + fileInfo.fileName() + " est introuvable.");
        }else{
            showMessage("information","La Clé Publique correspondante " + fileInfo.fileName() + " est: " + keyName + ".");
        }
    }
}


void MainWindow::on_pushButton_42_clicked()
{
    publicKeysPaths = QFileDialog::getOpenFileNames(this, "Choisir les clés publiques ",
                                                            QDir::homePath(),  "(*.pub)" );
    if(publicKeysPaths.isEmpty()){
        return;
    }

   if(publicKeysPaths.size() == 1){
       showMessage("information", "Clé publique charger avec succès");

   }else{
       showMessage("information", "Clés publiques charger avec succès");

   }
}


void MainWindow::on_pushButton_43_clicked()
{
    if(publicKeysPaths.isEmpty()){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner une Clé Publique.");
            return;
    }

    for(int i=0 ; i < publicKeysPaths.size(); i++){

        QFile file(publicKeysPaths[i]);
        QFileInfo fileInfo(publicKeysPaths[i]);
        QString fileContent;
        QString empreintePublicKey;

        if(file.open(QIODevice::ReadOnly)){
            fileContent = file.readAll();
            file.close();
            empreintePublicKey = QCryptographicHash::hash(fileContent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
        QString keyName;
        keyName = database.findPemReferenceName(empreintePublicKey);
        qDebug() << "L'empreinte: " + empreintePublicKey;

        if(keyName.isEmpty()){
            QMessageBox::warning(this,  tr("SecureMator"), "La Clé Privée correspondante à " + fileInfo.fileName() + " est introuvable.");
        }else{
            showMessage("information","La Clé Privée correspondante " + fileInfo.fileName() + " est: " + keyName + ".");
        }
    }
}


void MainWindow::on_pushButton_44_clicked()
{
    signaturesPaths = QFileDialog::getOpenFileNames(this, "Choisir les signatures ",
                                                            QDir::homePath(),  "(*.msi)" );
    if(signaturesPaths.isEmpty()){
        return;
    }

   if(signaturesPaths.size() == 1){
       showMessage("information", "Signature charger avec succès");

   }else{
       showMessage("information", "Signatures charger avec succès");

   }
}


void MainWindow::on_pushButton_45_clicked()
{
    if(signaturesPaths.isEmpty()){
        QMessageBox::warning(this,  tr("SecureMator"), "Veuillez sélectionner une Signature.");
            return;
    }

    for(int i=0 ; i < signaturesPaths.size(); i++){

        QFile file(signaturesPaths[i]);
        QFileInfo fileInfo(signaturesPaths[i]);
        QString fileContent;
        QString empreinteSignature;

        if(file.open(QIODevice::ReadOnly)){
            fileContent = file.readAll();
            file.close();
            empreinteSignature = QCryptographicHash::hash(fileContent.toUtf8(), QCryptographicHash::Sha256).toHex();
        }
        QString keyName;
        keyName = database.findSignatureName(empreinteSignature);
        qDebug() << "L'empreinte: " + empreinteSignature;

        if(keyName.isEmpty()){
            QMessageBox::warning(this,  tr("SecureMator"), "La Clé Privée correspondante à " + fileInfo.fileName() + " est introuvable.");
        }else{
            showMessage("information","La Clé Privée correspondante " + fileInfo.fileName() + " est: " + keyName + ".");
        }
    }
}

