#ifndef __RPMMULTI_LOG_
#define __RPMMULTI_LOG_

#include <syslog.h>

#define DEBUG 1

#define LOGD(fmt, ...) \
    if(DEBUG) syslog(LOG_ERR, "[%s@%s,%d]: " fmt, \
        __func__, __FILE__, __LINE__, ##__VA_ARGS__)

#define LOGE(fmt, ...) \
    syslog(LOG_ERR, "[%s@%s,%d]: " fmt, \
        __func__, __FILE__, __LINE__, ##__VA_ARGS__)
#endif
