#include "mainwindow.h"

#include <QApplication>
#include <QDebug>
#include <QCryptographicHash>

#include <QDateTime>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();



    /*QString hash  = QCryptographicHash::hash("Bonjour", QCryptographicHash::Sha256).toHex();
    qDebug()<< "Hash généré: "<< hash;

    qDebug()<< "Hash généré: "<< hash[0] << hash[1] << hash[10];*/
     /* QString letters = "abcédef";

    QByteArray utf8letters = letters.toUtf8();
    qDebug() << "letters:" << utf8letters;

    for(int i=0; i< utf8letters.size(); i++){
        qDebug()<< "utf8letters[" << i <<"]: " << static_cast<int>(utf8letters[i]);
   }*/

    return a.exec();
}
