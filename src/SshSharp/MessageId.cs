namespace SshSharp;

internal enum MessageId : byte
{
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,
    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,
    SSH_MSG_KEXDH_INIT = 30,
    SSH_MSG_KEXDH_REPLY = 31,
    // SSH_MSG_KEX_DH_GEX_REQUEST_OLD = 30,
    // SSH_MSG_KEX_DH_GEX_GROUP = 31,
    // SSH_MSG_KEX_DH_GEX_INIT = 32,
    // SSH_MSG_KEX_DH_GEX_REPLY = 33,
    // SSH_MSG_KEX_DH_GEX_REQUEST = 34,
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,
    // SSH_MSG_USERAUTH_INFO_REQUEST = 60,
    // SSH_MSG_USERAUTH_INFO_RESPONSE = 61,
    SSH_MSG_USERAUTH_PK_OK = 60,
    // SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60,
    // SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60,
    // SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61,
    // SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63,
    // SSH_MSG_USERAUTH_GSSAPI_ERROR = 64,
    // SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65,
    // SSH_MSG_USERAUTH_GSSAPI_MIC = 66,
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100,
}