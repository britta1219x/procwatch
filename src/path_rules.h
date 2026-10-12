#ifndef PROCWATCH_PATH_RULES_H
#define PROCWATCH_PATH_RULES_H

#define MAX_PATH_LEN 256

enum alert_type {
    ALERT_NONE = 0,
    ALERT_PASSWD = 1,
    ALERT_SHADOW = 2,
    ALERT_SSHKEY = 3,
    ALERT_SUDOERS = 4,
};

/* The caller supplies a zero-initialized, NUL-terminated MAX_PATH_LEN buffer. */
static inline __attribute__((always_inline)) unsigned char
classify_path(const char buf[MAX_PATH_LEN])
{
    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='p' && buf[6]=='a' && buf[7]=='s' &&
        buf[8]=='s' && buf[9]=='w' && buf[10]=='d' && buf[11]=='\0')
        return ALERT_PASSWD;

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='s' && buf[6]=='h' && buf[7]=='a' &&
        buf[8]=='d' && buf[9]=='o' && buf[10]=='w' && buf[11]=='\0')
        return ALERT_SHADOW;

    if (buf[0]=='/' && buf[1]=='e' && buf[2]=='t' && buf[3]=='c' &&
        buf[4]=='/' && buf[5]=='s' && buf[6]=='u' && buf[7]=='d' &&
        buf[8]=='o' && buf[9]=='e' && buf[10]=='r' && buf[11]=='s' &&
        buf[12]=='\0')
        return ALERT_SUDOERS;

#pragma unroll
    for (int i = 0; i < MAX_PATH_LEN - 6; i++) {
        if (buf[i] == '/' && buf[i + 1] == '.' &&
            buf[i + 2] == 's' && buf[i + 3] == 's' &&
            buf[i + 4] == 'h' && buf[i + 5] == '/')
            return ALERT_SSHKEY;
    }
    return ALERT_NONE;
}

#endif
