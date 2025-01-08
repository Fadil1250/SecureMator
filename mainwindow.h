#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QProcess>
#include <QSqlDatabase>
#include "DatabaseManager.h"
#include <QCoreApplication>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void generateSymmetricKey();
    void showMessage(QString type,QString message);
    void encryptFiles(const QStringList &inputFilePaths);
    void decryptFiles(const QStringList &inputFilePaths);
    void generatePrivateKeyWithPassword();
    void generateRSAPublicKey();
    void encryptSymmetricKey(const QString &symmetricKeyFilePath, const QString &publicKeyFilePath);

    void decryptSymmetricKey(const QString &encryptedSymmetricKeyFilePath, const QString &privateKeyFilePath);
    void signFile(const QString &inputFilePath, const QString &privateKeyFilePath);
    void verifySignature(const QString &originalFilePath, const QString &signature, const QString &publicKeyFilePath);

    void showSecretKeys();

    void getSecretKeys();
    void getPrivateKeys();
    void getPublicKeys();

private slots:
    void on_pushButton_4_clicked();

    void on_pushButton_5_clicked();

    void on_pushButton_6_clicked();

    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);

    void startNextEncryption();

    void startNextDecryption();

    void on_pushButton_7_clicked();

    void on_pushButton_2_clicked();

    void on_pushButton_8_clicked();

    void on_pushButton_9_clicked();


    void on_pushButton_10_clicked();

    void on_pushButton_11_clicked();

    void on_pushButton_3_clicked();

    void on_pushButton_12_clicked();

    void on_pushButton_15_clicked();

    void on_pushButton_16_clicked();

    void on_pushButton_14_clicked();

    void on_pushButton_clicked();

    void on_pushButton_13_clicked();

    void on_pushButton_20_clicked();


    void on_pushButton_22_clicked();

    void on_pushButton_21_clicked();

    void on_pushButton_23_clicked();

    void on_pushButton_24_clicked();

    void on_pushButton_17_clicked();

    void on_pushButton_18_clicked();

    void on_pushButton_19_clicked();

    void on_pushButton_27_clicked();

    void on_pushButton_25_clicked();

    void on_pushButton_26_clicked();

    void on_pushButton_28_clicked();

    void on_pushButton_57_clicked();

    void on_pushButton_29_clicked();

    void on_lineEdit_textChanged(const QString &arg1);

    void on_calendarWidget_clicked(const QDate &date);

    void on_dateEdit_userDateChanged(const QDate &date);

    void on_dateEdit_2_userDateChanged(const QDate &date);

    void on_pushButton_32_clicked();

    void on_pushButton_37_clicked();



    void on_calendarWidget_2_clicked(const QDate &date);


    void on_pushButton_34_clicked();

    void on_dateEdit_3_userDateChanged(const QDate &date);

    void on_dateEdit_4_userDateChanged(const QDate &date);

    void on_calendarWidget_3_clicked(const QDate &date);

    void on_pushButton_36_clicked();

    void on_dateEdit_5_userDateChanged(const QDate &date);

    void on_dateEdit_6_userDateChanged(const QDate &date);

    void on_pushButton_38_clicked();

    void on_pushButton_39_clicked();


    void on_lineEdit_2_textChanged(const QString &arg1);


    void on_lineEdit_3_textChanged(const QString &arg1);

    void on_pushButton_30_clicked();

    void on_pushButton_31_clicked();

    void on_pushButton_33_clicked();

    void on_pushButton_35_clicked();

    void on_pushButton_40_clicked();

    void on_pushButton_41_clicked();

    void on_pushButton_42_clicked();

    void on_pushButton_43_clicked();

    void on_pushButton_44_clicked();

    void on_pushButton_45_clicked();

protected:
    void closeEvent(QCloseEvent *event) override;


private:
    Ui::MainWindow *ui;
    bool continueEncryption;
    QStringList filesToEncrypt;
    int currentFileIndex = 0;
    QString outputDirPath;
    QString directory;
    QString directoryFilesCrypted;
    QString crypted = "0";
    QString decrypted = "0";
    QString symetric_key_path;
    QString temp_symetric_key_path;
    QString symetric_key_cypher_path;
    QString directorySymetrickeyCypherPath;
    QString directorySymetricDecrypted;
    QString opensslExecutable = QCoreApplication::applicationDirPath() + "/OpenSSL-Win64/bin/openssl.exe";
    QProcess *opensslProcess;
    QVector<QProcess*> processList;  // Liste pour stocker les processus en cours
    bool zoneDechiffrementClicked = false;
    QString processusEnCours;
    QString directoryGenerateSymetricKey;
    bool anyFileEncrypted = false;
    bool anyFileDecrypted = false;
    QString passwordSecretKey;
    QString passwordPrivateKey;
   QString outputFileSignaturePath;
    //Déchiffrement variables
    QString symetric_key_path_for_decryption;
    QString temp_symetric_key_path_for_decryption;
    QString directory_for_filesCrypted;

    QString directory_files_decrypted;
    QString temp_directory_files_decrypted;
    QStringList filesToDecrypt;
    bool continueDecryption;

    //Options avancées variables

    QString directoryPrivateKey;
    QString directoryPublicKey;
    QString publicKeyPath;
    QString privateKeyPath;
    QString temp_publicKeyPath;
    QString directoryKeyCrypted;
    QString cryptedKey;
    QString decryptedKey;
    QString file_Path;
    QString directoryFilePath;
    QString directorySignaturePath;
    QString signature;

    //Database
    Database database;
    QString symetricKeyFromDb;
    QString fileNameFromDb;
    QString iv;

    QString privateKeyFromDb;
    QString fileNamePrivateKeyFromDb;
    QString  tempPathPrivateKey;


    QString publicKeyFromDb;
    QString fileNamePublicKeyFromDb;
    QString  tempPathPublicKey;

    //Gestion des clés

      QString dateSelected;
      QString beginDate;
      QString endDate;

      QString beginDatePrivateKey;
      QString endDatePrivateKey;

      QString beginDatePublicKey;
      QString endDatePublicKey;

      QVector<QStringList> dataSecretKeys ;
      QVector<QStringList> filtedData;
      QVector<QStringList> dataPrivateKeys;
      QVector<QStringList> recordPrivateKeys;

      QVector<QStringList> dataPublicKeys;
      QVector<QStringList> recordPublicKeys;

      QVector<QStringList> referencesFilesCrypted;
      QString fileCrypted;
      QStringList inputFileCryptedPaths;
      QStringList inputKeyCryptedPaths;
      QStringList privateKeysPaths;
      QStringList publicKeysPaths;
      QStringList signaturesPaths;

      QVector<QStringList> referencesKeysCrypted;
      QVector<QStringList> referencesPubkeysForPrivateKeys;
      QVector<QStringList> referencesPemkeysForPublicKeys;
      QVector<QStringList> referencesSignature;


 };
#endif // MAINWINDOW_H
