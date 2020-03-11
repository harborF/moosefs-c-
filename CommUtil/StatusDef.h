#ifndef _STATUS_H__
#define _STATUS_H__

enum E_FsError
{
   STATUS_OK            =  0,	// OK

   ERROR_EPERM          =  1,	// Operation not permitted
   ERROR_ENOTDIR        =  2,	// Not a directory
   ERROR_ENOENT         =  3,	// No such file or directory
   ERROR_EACCES         =  4,	// Permission denied
   ERROR_EEXIST         =  5,	// File exists
   ERROR_EINVAL         =  6,	// Invalid argument
   ERROR_ENOTEMPTY      =  7,	// Directory not empty
   ERROR_CHUNKLOST      =  8,	// Chunk lost
   ERROR_OUTOFMEMORY    =  9,	// Out of memory

   ERROR_INDEXTOOBIG    = 10,	// Index too big
   ERROR_LOCKED         = 11,	// Chunk locked
   ERROR_NOCHUNKSERVERS = 12,	// No chunk servers
   ERROR_NOCHUNK        = 13,	// No such chunk
   ERROR_CHUNKBUSY	    = 14,	// Chunk is busy
   ERROR_REGISTER       = 15,	// Incorrect register BLOB
   ERROR_NOTDONE        = 16,	// None of chunk servers performed requested operation
   ERROR_NOTOPENED      = 17,	// File not opened
   ERROR_NOTSTARTED     = 18,	// Write not started

   ERROR_WRONGVERSION   = 19,	// Wrong chunk version
   ERROR_CHUNKEXIST     = 20,	// Chunk already exists
   ERROR_NOSPACE        = 21,	// No space left
   ERROR_IO             = 22,	// IO error
   ERROR_BNUMTOOBIG     = 23,	// Incorrect block number
   ERROR_WRONGSIZE	    = 24,	// Incorrect size
   ERROR_WRONGOFFSET    = 25,	// Incorrect offset
   ERROR_CANTCONNECT    = 26,	// Can't connect
   ERROR_WRONGCHUNKID   = 27,	// Incorrect chunk id
   ERROR_DISCONNECTED   = 28,	// Disconnected
   ERROR_CRC            = 29,	// CRC error
   ERROR_DELAYED        = 30,	// Operation delayed
   ERROR_CANTCREATEPATH = 31,	// Can't create path

   ERROR_MISMATCH       = 32,	// Data mismatch

   ERROR_EROFS          = 33,	// Read-only file system
   ERROR_QUOTA          = 34,	// Quota exceeded
   ERROR_BADSESSIONID   = 35,	// Bad session id
   ERROR_NOPASSWORD     = 36,   // Password is needed
   ERROR_BADPASSWORD    = 37,   // Incorrect password

   ERROR_ENOATTR        = 38,   // Attribute not found
   ERROR_ENOTSUP        = 39,   // Operation not supported
   ERROR_ERANGE         = 40,   // Result too large

   ERROR_MAX            = 41,
};

#define ERROR_STRINGS \
    "OK", \
    "Operation not permitted", \
    "Not a directory", \
    "No such file or directory", \
    "Permission denied", \
    "File exists", \
    "Invalid argument", \
    "Directory not empty", \
    "Chunk lost", \
    "Out of memory", \
    "Index too big", \
    "Chunk locked", \
    "No chunk servers", \
    "No such chunk", \
    "Chunk is busy", \
    "Incorrect register BLOB", \
    "None of chunk servers performed requested operation", \
    "File not opened", \
    "Write not started", \
    "Wrong chunk version", \
    "Chunk already exists", \
    "No space left", \
    "IO error", \
    "Incorrect block number", \
    "Incorrect size", \
    "Incorrect offset", \
    "Can't connect", \
    "Incorrect chunk id", \
    "Disconnected", \
    "CRC error", \
    "Operation delayed", \
    "Can't create path", \
    "Data mismatch", \
    "Read-only file system", \
    "Quota exceeded", \
    "Bad session id", \
    "Password is needed", \
    "Incorrect password", \
    "Attribute not found", \
    "Operation not supported", \
    "Result too large", \
    "Unknown MFS error"

static inline const char* mfsstrerr(uint8_t status) {
    static const char* errtab[]={ERROR_STRINGS};
    if (status>ERROR_MAX) {
        status=ERROR_MAX;
    }
    return errtab[status];
}

#endif