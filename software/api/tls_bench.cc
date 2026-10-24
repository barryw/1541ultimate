// Temporary hardware benchmark. Fixed local peer and deterministic entropy;
// this file must never ship in a production firmware image.
#include "routes.h"
#include "rtc.h"
#include "rtc_epoch.h"

#include "FreeRTOS.h"
#include "task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "mbedtls/hmac_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

#include "tls_bench_ca.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#if defined(TLS_BENCH_PROFILE)
extern "C" volatile uint32_t tls_bench_ecp_mul_ms;
extern "C" volatile uint32_t tls_bench_ecp_mul_calls;
extern "C" volatile uint32_t tls_bench_ecp_muladd_ms;
extern "C" volatile uint32_t tls_bench_ecp_muladd_calls;
#endif

enum { BENCH_BYTES = 256 * 1024, BENCH_PORT = 18443, BENCH_STACK_WORDS = 8192 };

struct BenchResult {
    int error;
    int verify_flags;
    uint32_t tcp_ms;
    uint32_t setup_ms;
    uint32_t handshake_ms;
    uint32_t transfer_ms;
    uint32_t bytes;
    uint32_t plain_tcp_ms;
    uint32_t plain_transfer_ms;
    uint32_t plain_bytes;
    uint32_t heap_before;
    uint32_t heap_after;
    uint32_t global_min_heap;
    uint32_t stack_free_words;
#if defined(TLS_BENCH_PROFILE)
    uint32_t ecp_mul_ms;
    uint32_t ecp_mul_calls;
    uint32_t ecp_muladd_ms;
    uint32_t ecp_muladd_calls;
#endif
};

static BenchResult result;
static volatile int bench_state; // 0 idle, 1 running, 2 complete

extern "C" mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)xTaskGetTickCount() * portTICK_PERIOD_MS;
}

static mbedtls_time_t bench_time(mbedtls_time_t *out)
{
    int year, month, day, weekday, hour, minute, second;
    rtc.get_time(year, month, day, weekday, hour, minute, second);
    struct tm local;
    memset(&local, 0, sizeof(local));
    local.tm_year = RTC_EPOCH_YEAR + year - 1900;
    local.tm_mon = month - 1;
    local.tm_mday = day;
    local.tm_hour = hour;
    local.tm_min = minute;
    local.tm_sec = second;
    local.tm_isdst = -1;
    mbedtls_time_t utc = mktime(&local);
    if (out) *out = utc;
    return utc;
}

// Performance fixture only. Predictable entropy makes these connections unsafe
// for secrets, but leaves the CPU cost of DRBG and TLS handshake measurable.
static int bench_entropy(void *context, unsigned char *output, size_t length)
{
    unsigned int *counter = (unsigned int *)context;
    for (size_t i = 0; i < length; ++i)
        output[i] = (unsigned char)(0x5b ^ ((*counter + i) * 73u));
    *counter += (unsigned int)length;
    return 0;
}

static int bench_send(void *context, const unsigned char *buffer, size_t length)
{
    int socket = *(int *)context;
    int n = lwip_send(socket, buffer, length, 0);
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : n;
}

static int bench_recv(void *context, unsigned char *buffer, size_t length)
{
    int socket = *(int *)context;
    int n = lwip_recv(socket, buffer, length, 0);
    return n < 0 ? MBEDTLS_ERR_SSL_INTERNAL_ERROR : n;
}

static uint32_t elapsed(TickType_t started)
{
    return (xTaskGetTickCount() - started) * portTICK_PERIOD_MS;
}

static int run_plain(BenchResult *metrics)
{
    int socket = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (socket < 0) return -109;
    struct timeval timeout = {180, 0};
    lwip_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    lwip_setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_len = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = PP_HTONS(18444);
    address.sin_addr.s_addr = inet_addr("192.168.1.3");
    TickType_t started = xTaskGetTickCount();
    int error = 0;
    if (lwip_connect(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        error = -110;
        goto done;
    }
    metrics->plain_tcp_ms = elapsed(started);
    if (lwip_send(socket, "B", 1, 0) != 1) {
        error = -111;
        goto done;
    }
    started = xTaskGetTickCount();
    while (metrics->plain_bytes < BENCH_BYTES) {
        unsigned char buffer[1024];
        int n = lwip_recv(socket, buffer, sizeof(buffer), 0);
        if (n <= 0) { error = -112; goto done; }
        if (metrics->plain_bytes + (uint32_t)n > BENCH_BYTES) {
            error = -113;
            goto done;
        }
        for (int i = 0; i < n; ++i) {
            if (buffer[i] != (unsigned char)((metrics->plain_bytes + i) & 255)) {
                error = -114;
                goto done;
            }
        }
        metrics->plain_bytes += (uint32_t)n;
    }
    metrics->plain_transfer_ms = elapsed(started);
done:
    lwip_close(socket);
    return error;
}

static void run_benchmark(void)
{
    BenchResult metrics = {};
    metrics.heap_before = xPortGetFreeHeapSize();
    metrics.error = -1;
    int socket = -1;
    unsigned int entropy_counter = (unsigned int)xTaskGetTickCount();
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_hmac_drbg_context random;
    mbedtls_x509_crt ca;
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_hmac_drbg_init(&random);
    mbedtls_x509_crt_init(&ca);

    mbedtls_platform_set_time(bench_time);
    if (bench_time(NULL) < 1735689600) {
        metrics.error = -100; // RTC before 2025; certificate dates cannot be checked
        goto done;
    }

    {
        TickType_t started = xTaskGetTickCount();
        socket = lwip_socket(AF_INET, SOCK_STREAM, 0);
        if (socket < 0) { metrics.error = -101; goto done; }
        struct timeval timeout = { 180, 0 };
        lwip_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        lwip_setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        struct sockaddr_in address;
        memset(&address, 0, sizeof(address));
        address.sin_len = sizeof(address);
        address.sin_family = AF_INET;
        address.sin_port = PP_HTONS(BENCH_PORT);
        address.sin_addr.s_addr = inet_addr("192.168.1.3");
        if (lwip_connect(socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
            metrics.error = -102;
            goto done;
        }
        metrics.tcp_ms = elapsed(started);
    }

    {
        TickType_t started = xTaskGetTickCount();
        int code = mbedtls_x509_crt_parse_der(&ca, tls_bench_ca_der, tls_bench_ca_der_len);
        if (code) { metrics.error = code; goto done; }
        code = mbedtls_hmac_drbg_seed(&random, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                                     bench_entropy, &entropy_counter,
                                     (const unsigned char *)"nios-tls-benchmark", 18);
        if (code) { metrics.error = code; goto done; }
        code = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT);
        if (code) { metrics.error = code; goto done; }
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&config, &ca, NULL);
        mbedtls_ssl_conf_rng(&config, mbedtls_hmac_drbg_random, &random);
        static const int suites[] = {
            MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 0
        };
        mbedtls_ssl_conf_ciphersuites(&config, suites);
        code = mbedtls_ssl_setup(&ssl, &config);
        if (code) { metrics.error = code; goto done; }
        code = mbedtls_ssl_set_hostname(&ssl, "bench.local");
        if (code) { metrics.error = code; goto done; }
        mbedtls_ssl_set_bio(&ssl, &socket, bench_send, bench_recv, NULL);
        metrics.setup_ms = elapsed(started);
    }

    {
        TickType_t started = xTaskGetTickCount();
#if defined(TLS_BENCH_PROFILE)
        tls_bench_ecp_mul_ms = 0;
        tls_bench_ecp_mul_calls = 0;
        tls_bench_ecp_muladd_ms = 0;
        tls_bench_ecp_muladd_calls = 0;
#endif
        int code = mbedtls_ssl_handshake(&ssl);
        metrics.handshake_ms = elapsed(started);
#if defined(TLS_BENCH_PROFILE)
        metrics.ecp_mul_ms = tls_bench_ecp_mul_ms;
        metrics.ecp_mul_calls = tls_bench_ecp_mul_calls;
        metrics.ecp_muladd_ms = tls_bench_ecp_muladd_ms;
        metrics.ecp_muladd_calls = tls_bench_ecp_muladd_calls;
#endif
        metrics.verify_flags = (int)mbedtls_ssl_get_verify_result(&ssl);
        if (code || metrics.verify_flags) {
            metrics.error = code ? code : -103;
            goto done;
        }
    }

    {
        const unsigned char request = 'B';
        int code = mbedtls_ssl_write(&ssl, &request, 1);
        if (code != 1) { metrics.error = code ? code : -104; goto done; }
        TickType_t started = xTaskGetTickCount();
        unsigned char buffer[1024];
        while (metrics.bytes < BENCH_BYTES) {
            code = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
            if (code <= 0) { metrics.error = code ? code : -105; goto done; }
            if (metrics.bytes + (uint32_t)code > BENCH_BYTES) {
                metrics.error = -106;
                goto done;
            }
            for (int i = 0; i < code; ++i) {
                if (buffer[i] != (unsigned char)((metrics.bytes + i) & 255)) {
                    metrics.error = -107;
                    goto done;
                }
            }
            metrics.bytes += (uint32_t)code;
        }
        metrics.transfer_ms = elapsed(started);
        code = mbedtls_ssl_read(&ssl, buffer, sizeof(buffer));
        if (code != 0 && code != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            metrics.error = code ? code : -108;
            goto done;
        }
        mbedtls_ssl_close_notify(&ssl);
    }
    lwip_close(socket);
    socket = -1;
    metrics.error = run_plain(&metrics);

done:
    if (socket >= 0) lwip_close(socket);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
    mbedtls_hmac_drbg_free(&random);
    mbedtls_x509_crt_free(&ca);
    metrics.heap_after = xPortGetFreeHeapSize();
    metrics.global_min_heap = xPortGetMinimumEverFreeHeapSize();
    metrics.stack_free_words = uxTaskGetStackHighWaterMark(NULL);
    result = metrics;
    taskENTER_CRITICAL();
    bench_state = 2;
    taskEXIT_CRITICAL();
    printf("TLSBENCH error=%d verify=0x%X tcp=%lu setup=%lu handshake=%lu transfer=%lu bytes=%lu plain=%lu/%lu heap=%lu/%lu min=%lu stack=%lu\n",
           result.error, result.verify_flags, (unsigned long)result.tcp_ms,
           (unsigned long)result.setup_ms, (unsigned long)result.handshake_ms,
           (unsigned long)result.transfer_ms, (unsigned long)result.bytes,
           (unsigned long)result.plain_transfer_ms, (unsigned long)result.plain_bytes,
           (unsigned long)result.heap_before, (unsigned long)result.heap_after,
           (unsigned long)result.global_min_heap, (unsigned long)result.stack_free_words);
}

static void bench_task(void *)
{
    run_benchmark();
    vTaskDelete(NULL);
}

API_CALL(PUT, machine, tls_bench, NULL, ARRAY( { }))
{
    taskENTER_CRITICAL();
    bool busy = bench_state == 1;
    if (!busy) bench_state = 1;
    taskEXIT_CRITICAL();
    if (!busy && xTaskCreate(bench_task, "Nios TLS Bench", BENCH_STACK_WORDS,
                             NULL, PRIO_HW_SERVICE, NULL) != pdPASS) {
        bench_state = 0;
        resp->json->add("state", "task_create_failed");
    } else {
        resp->json->add("state", busy ? "busy" : "running");
    }
    resp->json_response(HTTP_OK);
}

API_CALL(GET, machine, tls_bench, NULL, ARRAY( { }))
{
    int state = bench_state;
    resp->json->add("state", state == 2 ? "complete" : state == 1 ? "running" : "idle");
    if (state == 2) {
        resp->json->add("error", result.error);
        resp->json->add("verify_flags", result.verify_flags);
        resp->json->add("tcp_ms", (int)result.tcp_ms);
        resp->json->add("setup_ms", (int)result.setup_ms);
        resp->json->add("handshake_ms", (int)result.handshake_ms);
        resp->json->add("transfer_ms", (int)result.transfer_ms);
        resp->json->add("bytes", (int)result.bytes);
        resp->json->add("plain_tcp_ms", (int)result.plain_tcp_ms);
        resp->json->add("plain_transfer_ms", (int)result.plain_transfer_ms);
        resp->json->add("plain_bytes", (int)result.plain_bytes);
        resp->json->add("heap_before", (int)result.heap_before);
        resp->json->add("heap_after", (int)result.heap_after);
        resp->json->add("global_min_heap", (int)result.global_min_heap);
        resp->json->add("stack_free_words", (int)result.stack_free_words);
#if defined(TLS_BENCH_PROFILE)
        resp->json->add("ecp_mul_ms", (int)result.ecp_mul_ms);
        resp->json->add("ecp_mul_calls", (int)result.ecp_mul_calls);
        resp->json->add("ecp_muladd_ms", (int)result.ecp_muladd_ms);
        resp->json->add("ecp_muladd_calls", (int)result.ecp_muladd_calls);
#endif
        resp->json->add("entropy", "deterministic_test_only");
        resp->json->add("tls", "1.2 ECDHE-ECDSA CHACHA20-POLY1305");
    }
    resp->json_response(HTTP_OK);
}
