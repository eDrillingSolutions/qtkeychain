/******************************************************************************
 *   Copyright (C) 2011-2015 Frank Osterfeld <frank.osterfeld@gmail.com>      *
 *                                                                            *
 * This program is distributed in the hope that it will be useful, but        *
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
 * or FITNESS FOR A PARTICULAR PURPOSE. For licensing and distribution        *
 * details, check the accompanying file 'COPYING'.                            *
 *****************************************************************************/
#include "keychain_p.h"
#include "gnomekeyring_p.h"
#include "libsecret_p.h"
#include "plaintextstore_p.h"

#include <QScopedPointer>

using namespace QKeychain;

enum KeyringBackend {
    Backend_None,
    Backend_LibSecretKeyring,
    Backend_GnomeKeyring
};

static KeyringBackend detectKeyringBackend()
{
    /* Libsecret unifies access to KDE and GNOME
     * password services. */
    if (LibSecretKeyring::isAvailable()) {
        return Backend_LibSecretKeyring;
    }

    if ( GnomeKeyring::isAvailable() ) {
       return Backend_GnomeKeyring;
    }

    return Backend_None;
}

static KeyringBackend getKeyringBackend()
{
    static KeyringBackend backend = detectKeyringBackend();
    return backend;
}

void ReadPasswordJobPrivate::scheduledStart() {
    switch ( getKeyringBackend() ) {
    case Backend_LibSecretKeyring: {
        if ( !LibSecretKeyring::findPassword(key, q->service(), this) ) {
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
        }
    } break;
    case Backend_GnomeKeyring:
        this->mode = JobPrivate::Text;
        if ( !GnomeKeyring::find_network_password( key.toUtf8().constData(),
                                                   q->service().toUtf8().constData(),
                                                   "plaintext",
                                                   reinterpret_cast<GnomeKeyring::OperationGetStringCallback>( &JobPrivate::gnomeKeyring_readCb ),
                                                   this, 0 ) )
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
        break;
    case Backend_None:
        q->emitFinishedWithError(NoBackendAvailable, tr("No Backend Available"));
    }
}

static QPair<Error, QString> mapGnomeKeyringError( int result )
{
    Q_ASSERT( result != GnomeKeyring::RESULT_OK );

    switch ( result ) {
    case GnomeKeyring::RESULT_DENIED:
        return qMakePair( AccessDenied, QObject::tr("Access to keychain denied") );
    case GnomeKeyring::RESULT_NO_KEYRING_DAEMON:
        return qMakePair( NoBackendAvailable, QObject::tr("No keyring daemon") );
    case GnomeKeyring::RESULT_ALREADY_UNLOCKED:
        return qMakePair( OtherError, QObject::tr("Already unlocked") );
    case GnomeKeyring::RESULT_NO_SUCH_KEYRING:
        return qMakePair( OtherError, QObject::tr("No such keyring") );
    case GnomeKeyring::RESULT_BAD_ARGUMENTS:
        return qMakePair( OtherError, QObject::tr("Bad arguments") );
    case GnomeKeyring::RESULT_IO_ERROR:
        return qMakePair( OtherError, QObject::tr("I/O error") );
    case GnomeKeyring::RESULT_CANCELLED:
        return qMakePair( OtherError, QObject::tr("Cancelled") );
    case GnomeKeyring::RESULT_KEYRING_ALREADY_EXISTS:
        return qMakePair( OtherError, QObject::tr("Keyring already exists") );
    case GnomeKeyring::RESULT_NO_MATCH:
        return qMakePair(  EntryNotFound, QObject::tr("No match") );
    default:
        break;
    }

    return qMakePair( OtherError, QObject::tr("Unknown error") );
}

void JobPrivate::gnomeKeyring_readCb( int result, const char* string, JobPrivate* self )
{
    if ( result == GnomeKeyring::RESULT_OK ) {
        if (self->mode == JobPrivate::Text)
            self->data = QByteArray(string);
        else
            self->data = QByteArray::fromBase64(string);

        self->q->emitFinished();
    } else if (self->mode == JobPrivate::Text) {
        self->mode = JobPrivate::Binary;
        if ( !GnomeKeyring::find_network_password( self->key.toUtf8().constData(),
                                                   self->q->service().toUtf8().constData(),
                                                   "base64",
                                                   reinterpret_cast<GnomeKeyring::OperationGetStringCallback>( &JobPrivate::gnomeKeyring_readCb ),
                                                   self, 0 ) )
            self->q->emitFinishedWithError( OtherError, tr("Unknown error") );
    } else {
        const QPair<Error, QString> errorResult = mapGnomeKeyringError( result );
        self->q->emitFinishedWithError( errorResult.first, errorResult.second );
    }
}

//Must be in sync with KWallet::EntryType (kwallet.h)
enum KWalletEntryType {
    Unknown=0,
    Password,
    Stream,
    Map
};

void WritePasswordJobPrivate::scheduledStart() {
    switch ( getKeyringBackend() ) {
    case Backend_LibSecretKeyring: {
        if ( !LibSecretKeyring::writePassword(service, key, service, mode,
                                              data, this) ) {
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
        }
    } break;
    case Backend_GnomeKeyring: {
        QString type;
        QByteArray password;

        switch(mode) {
        case JobPrivate::Text:
            type = QLatin1String("plaintext");
            password = data;
            break;
        default:
            type = QLatin1String("base64");
            password = data.toBase64();
            break;
        }

        QByteArray service = q->service().toUtf8();
        if ( !GnomeKeyring::store_network_password( GnomeKeyring::GNOME_KEYRING_DEFAULT,
                                                    service.constData(),
                                                    key.toUtf8().constData(),
                                                    service.constData(),
                                                    type.toUtf8().constData(),
                                                    password.constData(),
                                                    reinterpret_cast<GnomeKeyring::OperationDoneCallback>( &JobPrivate::gnomeKeyring_writeCb ),
                                                    this, 0 ) )
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
    }
        break;
    case Backend_None:
        q->emitFinishedWithError(NoBackendAvailable, tr("No Backend Available"));
    }
}

void JobPrivate::gnomeKeyring_writeCb(int result, JobPrivate* self )
{
    if ( result == GnomeKeyring::RESULT_OK ) {
        self->q->emitFinished();
    } else {
        const QPair<Error, QString> errorResult = mapGnomeKeyringError( result );
        self->q->emitFinishedWithError( errorResult.first, errorResult.second );
    }
}

void DeletePasswordJobPrivate::scheduledStart() {
    switch ( getKeyringBackend() ) {
    case Backend_LibSecretKeyring: {
        if ( !LibSecretKeyring::deletePassword(key, q->service(), this) ) {
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
        }
    } break;
    case Backend_GnomeKeyring: {
        if ( !GnomeKeyring::delete_network_password(
                 key.toUtf8().constData(), q->service().toUtf8().constData(),
                 reinterpret_cast<GnomeKeyring::OperationDoneCallback>( &JobPrivate::gnomeKeyring_writeCb ),
                 this, 0 ) )
            q->emitFinishedWithError( OtherError, tr("Unknown error") );
    }
        break;
    case Backend_None:
        q->emitFinishedWithError(NoBackendAvailable, tr("No Backend Available"));
    }
}
