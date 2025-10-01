#include <QCoreApplication>
#include <QPair>
#include <QString>
#include <QMap>
#include <QSet>

#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QScopedPointer>
#include <QSettings>
#include <QUuid>
#include <QDebug>
#include <QDir>
#include <QPair>

#include <QtConcurrent/QtConcurrent>
#include <QFutureInterface>
#include <QFuture>

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

#include <QtHttpServer>
#include <QHostAddress>

#include <QCryptographicHash>
#include <QRegularExpression>

#include <optional>
#include <algorithm>

static const QString rapidApiKey {"1fc5c415838a24f187d9501d2988c92423d508f8d8aa040cf201161c033cf8be9c22d7beea680b1e3591e44d8a8449102c390b4ab06084c481f032d3eba886c2"};

static const QString REGEX_NEUER_AUSWEIS {"([A-Z0-9]{9,11})"};

static const QMap<QString, QString> buchstabeToZahl
{
    {"A", "10"},
    {"B", "11"},
    {"C", "12"},
    {"D", "13"},
    {"E", "14"},
    {"F", "15"},
    {"G", "16"},
    {"H", "17"},
    {"I", "18"},
    {"J", "19"},
    {"K", "20"},
    {"L", "21"},
    {"M", "22"},
    {"N", "23"},
    {"O", "24"},
    {"P", "25"},
    {"Q", "26"},
    {"R", "27"},
    {"S", "28"},
    {"T", "29"},
    {"U", "30"},
    {"V", "31"},
    {"W", "32"},
    {"X", "33"},
    {"Y", "34"},
    {"Z", "35"}
};

bool isPruefzifferValide(const QString &ausweisnummer)
{
    const QString ausweisnummerUmgewandeltOhnePruefziffer {ausweisnummer.left(ausweisnummer.size() - 1)};

    //ziffer1 mal 7 dann ziffer2 mal 3 dann ziffer3 mal 1 und wieder von vorne
    const qint64 summeAllerMultiplikationen = [](const QString &ausweisnummer) -> qint64
    {
        qint64 summeAllerMultiplikationen {0};
        qint64 multiplikator {1}; //start mit 1, da im ersten Durchlauf dann direkt auf 7 umgeschrieben wird

        for (const QChar &zeichen : ausweisnummer)
        {
            if (multiplikator == 7)
                multiplikator = 3;

            else if (multiplikator == 3)
                multiplikator = 1;

            else if (multiplikator == 1)
                multiplikator = 7;

            if (buchstabeToZahl.contains(zeichen))
            {
                summeAllerMultiplikationen +=  buchstabeToZahl.value(zeichen).toInt() * multiplikator;
                continue;
            }

            summeAllerMultiplikationen += QString{zeichen}.toInt() * multiplikator;
        }

        return summeAllerMultiplikationen;

    }(ausweisnummerUmgewandeltOhnePruefziffer);

    if (QString::number(summeAllerMultiplikationen).last(1) == ausweisnummer.last(1))
        return true;

    return false;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QCoreApplication app {argc, argv};

    const quint16 PORT {50003};
    const QScopedPointer<QHttpServer> httpServer {new QHttpServer {&app}};

    httpServer->route("/ping", QHttpServerRequest::Method::Get,
    [](const QHttpServerRequest &request) -> QFuture<QHttpServerResponse>
    {
        qDebug() << "Ping verarbeitet";

#ifdef QT_DEBUG
        Q_UNUSED(request)
#else
        const bool requestIsFromRapidAPI = [](const QHttpServerRequest &request) -> bool
        {
            for (const QPair<QByteArray, QByteArray> &header : request.headers())
                if (header.first == "X-RapidAPI-Proxy-Secret" && QCryptographicHash::hash(header.second, QCryptographicHash::Sha512).toHex() == rapidApiKey)
                    return true;

            return false;

        }(request);

        if (!requestIsFromRapidAPI)
            return QtConcurrent::run([]()
            {
                return QHttpServerResponse
                {
                    QJsonObject
                    {
                        {"Message", "HTTP-Requests allowed only via RapidAPI-Gateway."}
                    }
                };
            });
#endif
        return QtConcurrent::run([]()
        {
            return QHttpServerResponse
            {
                QJsonObject
                {
                    {"Message", "pong"}
                }
            };
        });
    });

    httpServer->route("/validate", QHttpServerRequest::Method::Get     |
                                   QHttpServerRequest::Method::Put     |
                                   QHttpServerRequest::Method::Head    |
                                   QHttpServerRequest::Method::Trace   |
                                   QHttpServerRequest::Method::Patch   |
                                   QHttpServerRequest::Method::Delete  |
                                   QHttpServerRequest::Method::Options |
                                   QHttpServerRequest::Method::Connect |
                                   QHttpServerRequest::Method::Unknown,
    [](const QHttpServerRequest &request) -> QFuture<QHttpServerResponse>
    {
#ifdef QT_DEBUG
        Q_UNUSED(request)
#else
       const bool requestIsFromRapidAPI = [](const QHttpServerRequest &request) -> bool
       {
           for (const QPair<QByteArray, QByteArray> &header : request.headers())
           {
               if (header.first == "X-RapidAPI-Proxy-Secret" && QCryptographicHash::hash(header.second, QCryptographicHash::Sha512).toHex() == rapidApiKey)
                   return true;
           }

           return false;

       }(request);

       if (!requestIsFromRapidAPI)
           return QtConcurrent::run([]()
           {
               return QHttpServerResponse
               {
                   QJsonObject
                   {
                       {"Message", "HTTP-Requests allowed only via RapidAPI-Gateway."}
                   }
               };
           });
#endif
       return QtConcurrent::run([]()
       {
           return QHttpServerResponse
           {
               QJsonObject
               {
                   {"Message", "The used HTTP-Method is not implemented."}
               }
           };
       });
    });

    httpServer->route("/validate", QHttpServerRequest::Method::Post,
    [](const QHttpServerRequest &request) -> QFuture<QHttpServerResponse>
    {
        qDebug() << "Anfrage von IP: " << request.remoteAddress().toString();

#ifdef QT_DEBUG
        Q_UNUSED(request)
#else
        const bool requestIsFromRapidAPI = [](const QHttpServerRequest &request) -> bool
        {
            for (const QPair<QByteArray, QByteArray> &header : request.headers())
            {
                if (header.first == "X-RapidAPI-Proxy-Secret" && QCryptographicHash::hash(header.second, QCryptographicHash::Sha512).toHex() == rapidApiKey)
                    return true;
            }

            return false;

        }(request);

        if (!requestIsFromRapidAPI)
            return QtConcurrent::run([]()
            {
                return QHttpServerResponse
                {
                    QJsonObject
                    {
                        {"Message", "HTTP-Requests allowed only via RapidAPI-Gateway."}
                    }
                };
            });
#endif

        if (request.body().isEmpty())
            return QtConcurrent::run([]()
            {
                return QHttpServerResponse
                {
                    QJsonObject
                    {
                        {"Message", "HTTP-Request body is empty."}
                    }
                };
            });

        const QJsonDocument jsonDocument {QJsonDocument::fromJson(request.body())};

        if (jsonDocument.isNull())
            return QtConcurrent::run([]()
            {
                return QHttpServerResponse
                {
                    QJsonObject
                    {
                        {"Message", "Invalid data sent. Please send a valid JSON-Object."}
                    }
                };
            });

        const QJsonObject jsonObject {jsonDocument.object()};

        if (jsonObject.isEmpty())
            return QtConcurrent::run([]()
            {
                return QHttpServerResponse
                {
                    QJsonObject
                    {
                        {"Message", "Invalid data sent. Please send a valid JSON-Object."}
                    }
                };
            });


        if (!jsonObject.contains("ID-Number"))
             return QtConcurrent::run([]()
             {
                 return QHttpServerResponse
                 {
                     QJsonObject
                     {
                         {"Message", "Invalid data sent. ID-Number-key is missing."}
                     }
                 };
             });

        if (jsonObject.value("ID-Number").toString().isEmpty())
             return QtConcurrent::run([]()
             {
                 return QHttpServerResponse
                 {
                     QJsonObject
                     {
                         {"Message", "Invalid data sent. ID-Number-value is missing."}
                     }
                 };
             });

        isPruefzifferValide(jsonObject.value("ID-Number").toString());

        if (QRegularExpression{REGEX_NEUER_AUSWEIS}.match(jsonObject.value("ID-Number").toString()).hasMatch())
        {
             if (jsonObject.value("ID-Number").toString().size() == 9)
                 return QtConcurrent::run([=]()
                 {
                     return QHttpServerResponse
                     {
                         QJsonObject
                         {
                            {"Valid",   false},
                            {"Message", "Please submit the ID-Number located on the back of the German citizen ID card (Personalausweis)."}
                         }
                     };
                 });

            if (jsonObject.value("ID-Number").toString().size() == 10)
                return QtConcurrent::run([=]()
                {
                    return QHttpServerResponse
                    {
                        QJsonObject
                        {
                            {"Valid", isPruefzifferValide(jsonObject.value("ID-Number").toString())}
                        }
                    };
                });
        }

        return QtConcurrent::run([=]()
        {
            return QHttpServerResponse
            {
                QJsonObject
                {
                    {"Valid",   false},
                    {"Message", "The submitted value is not a valid ID-Number of a German citizen ID card (Personalausweis)."}
                }
            };
        });
    });

    if (httpServer->listen(QHostAddress::Any, static_cast<quint16>(PORT)) == 0)
        return -1;

    return a.exec();
}
