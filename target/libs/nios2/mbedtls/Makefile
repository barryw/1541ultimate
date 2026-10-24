CROSS        = nios2-elf-
ELFTYPE      = elf32-littlenios2
ARCHITECTURE = nios2
AR           = $(CROSS)ar

include ../../../common/environment.mk

RESULT    = $(shell pwd)/result
OUTPUT    = ./output
OUTPUT_FP = $(shell pwd)/output
PRJ       = libmbedtls

VPATH = $(PATH_SW)/mbedtls/library \
        $(PATH_SW)/mbedtls/include \
        $(PATH_SW)/network

SRCS_C = asn1parse.c asn1write.c base64.c \
         bignum.c bignum_core.c bignum_mod.c bignum_mod_raw.c \
         chacha20.c chachapoly.c cipher.c cipher_wrap.c constant_time.c \
         ecdh.c ecdsa.c ecp.c ecp_curves.c hmac_drbg.c md.c oid.c \
         pem.c pk.c pk_ecc.c pk_wrap.c pkparse.c platform.c platform_util.c \
         poly1305.c sha256.c sha512.c \
         x509.c x509_crt.c \
         ssl_ciphersuites.c ssl_client.c ssl_msg.c ssl_tls.c ssl_tls12_client.c

SRCS_CC =
SRCS_ASM =

PATH_INC = -I$(PATH_SW)/mbedtls/include -I$(PATH_SW)/mbedtls/library -I$(PATH_SW)/network
OPTIONS  = -g -Os -mno-hw-div -mno-hw-mul -mno-hw-mulx -ffunction-sections -fdata-sections -DNIOS
COPTIONS = $(OPTIONS) -std=c99 -DMBEDTLS_CONFIG_FILE='"ultimate_mbedtls_config.h"'
CPPOPT   = $(OPTIONS)
LIBS     = -lc -lgcc
LFLAGS   = --gc-sections

VPATH += $(OUTPUT) $(RESULT)

all: $(OUTPUT) $(RESULT) $(RESULT)/$(PRJ).a

$(RESULT)/$(PRJ).a: $(OBJS_C)
	@echo "Creating Archive $@"
	$(AR) -rc $@ $(ALL_OBJS)

include ../../../common/rules.mk
