#include <time.h>

time_t time(time_t *t)
{
#ifdef TLS_COPROCESSOR
    extern time_t rtc_get_epoch_time(void);
    time_t now = rtc_get_epoch_time();
    if (t) {
        *t = now;
    }
    return now;
#else
    *t = 1359763200;
    return 0;
#endif
}

// struct tm *gmtime(time_t)
//{
//}

