/*
 * File:   ngx_http_rqst_manager_module.h
 * Author: anton
 *
 * Created on 11 Апрель 2013 г., 12:19
 */

#ifndef NGX_HTTP_RQST_MANAGER_MODULE_H
#define	NGX_HTTP_RQST_MANAGER_MODULE_H

extern "C"
{
    #include <ngx_config.h>
    #include <ngx_core.h>
    #include <ngx_http.h>
}

#include <pthread.h>
#include <iconv.h>
#include <ctype.h>
#include <sys/time.h>
#include <openssl/md5.h>
#include <map>
#include "../../shared/config.h"
#include "../../logger_c/Lgr.h"

#define NGX_HTTP_RQST_MANAGER_MAX_NAME_DOMEN        255 // максимальная длина домена
#define NGX_HTTP_RQST_MANAGER_MAX_COOKIES           21  // максимальная длина куков
#define NGX_HTTP_RQST_MANAGER_MAX_COOKIE_HEADER_LEN 255 // максимальная длина заголовка куков
#define NGX_HTTP_RQST_MANAGER_MAX_HASH              32  // максимальная длина хеша
#define NGX_HTTP_RQST_MANAGER_MAX_HASH_AMOUNT       11  // максимальное количество хешей

// максимальная длина строки хешей
#define NGX_HTTP_RQST_MANAGER_MAX_STRING_HASH \
    NGX_HTTP_RQST_MANAGER_MAX_HASH * (NGX_HTTP_RQST_MANAGER_MAX_HASH_AMOUNT + 1)

#define NGX_HTTP_RQST_MANAGER_MAX_STRING_ADDRESS    512 // максимальная длина адреса страницы
#define NGX_HTTP_RQST_MANAGER_MAX_STRING_ARGS       1023// максимальная длина строки параметров
#define NGX_HTTP_RQST_MANAGER_MAX_PATH              200 // максимальная длина пути к файлу конфигурации системы
#define NGX_HTTP_RQST_MANAGER_MAX_PREFIX            256 // максимальная длина префикса
#define NGX_HTTP_RQST_MANAGER_MAX_EXTENSION         10  // максимальняа длина расширения файла
#define NGX_HTTP_RQST_MANAGER_MAX_REQUEST           2048// ограничение на длину принимаемых данных

const char *mon_short_names[] = 
{ 
    "Jan", "Feb", "Mar", "Apr", 
    "May", "Jun", "Jul", "Aug", 
    "Sep", "Oct", "Nov", "Dec" 
};
const char *day_short_names[] = 
{	
    "Sun", "Mon", "Tue", "Wed", 
    "Thu", "Fri", "Sat" 
};

// структура для считывания из файла конфигурациии (server)
typedef struct
{
    ngx_str_t default_prefix;                               // префикс дефолтного файла баннера
    ngx_str_t default_extension;                            // расширение дефолтного файла баннера
    ngx_int_t expires_day;                                  // количество дней жизни кука
    ngx_str_t path_config;                                  // путь к конфигу системы (протокол)
    ngx_int_t start_interval_msec;                          // время в м сек
} ngx_http_rqst_manager_module_serv_conf_t;

// структура для считывания из файла конфигурациии (location)
typedef struct
{
    ngx_int_t work;                                         // флаг запуска обработки запроса
                                                            // устанавливается для конкретой страницы
} ngx_http_rqst_manager_module_loc_conf_t;

typedef struct
{
    char default_prefix[NGX_HTTP_RQST_MANAGER_MAX_PREFIX + 1];      // префикс дефолтного файла баннера
    char default_extension[NGX_HTTP_RQST_MANAGER_MAX_EXTENSION + 1];    // расширение дефолтного файла баннера
    char path_config[NGX_HTTP_RQST_MANAGER_MAX_PATH + 1];           // путь к конфигу системы (протокол)
    ngx_int_t expires_day;                                          // количество дней жизни кука
    ngx_int_t start_interval;                               // время в мк сек, интервал запуска треда (проверка утечек памяти)
} ngx_http_rqst_manager_server_t;

// структура для разбора строки параметров
typedef struct
{
    uint32_t pp;                                            // id места
    int8_t tm;                                              // временная зона
    int8_t vb;                                              // видимость баннера
    uint16_t h;                                             // высота экрана
    uint16_t w;                                             // ширина экрана
    char *ptr_page;                                         // указатель на начало адреса страницы
    int16_t len_page;                                       // длина адреса страницы
    char *ptr_hash;                                         // указатель на начало хеша
    int len_hash;                                           // длина хеша
} args_data;

typedef struct
{
    int count;                                              // счетчик прошедшего времени
    uint16_t h;                                             // высота баннера
    uint16_t w;                                             // ширина баннера
    uint32_t p;                                             // место
} map_data_t;

// массив адресов запросов
// записывается адрес внутренней структуры указывающей на запрос, при приеме ответа делается проверка на
// наличие пришедшего адреса в данном массиве: если адреса нет, то ответ считается ошибочным
// раз в n секунд производится выдача ответов на старые запросы
typedef std::map <ngx_http_request_t *, map_data_t> rqst_manager_map_address_t;
typedef std::pair <ngx_http_request_t *, map_data_t> pair_address_t;

static ngx_int_t ngx_http_rqst_manager_handler(ngx_http_request_t *r);
void *ngx_http_rqst_manager_read(void *lg);
void ngx_http_rqst_manager_write(ngx_event_t *ev);
static ngx_int_t ngx_http_rqst_manager_init(ngx_conf_t *cf);

static void* ngx_http_rqst_manager_create_serv_conf(ngx_conf_t *cf);
static char* ngx_http_rqst_manager_merge_serv_conf(ngx_conf_t *cf, void *parent, void *child);
static void* ngx_http_rqst_manager_create_loc_conf(ngx_conf_t *cf);

char *ngx_http_rqst_manager_copy_value(ngx_str_t *data, char *ptr);
int ngx_http_rqst_manager_htoi(char *s);
int ngx_http_rqst_manager_url_decode(char *str, int len);
char *ngx_http_rqst_manager_copy_args(ngx_str_t *args, char *ptr, int *id_place, char *domen, char *hash, map_data_t *map_data);

void * f_tr1(void * str);
static ngx_int_t ngx_http_rqst_manager_init_process(ngx_cycle_t *cycle);
void ngx_http_rqst_manager_exit_process(ngx_cycle_t *lg);

void ngx_http_rqst_manager_finalize_request(ngx_http_request_t *r, map_data_t *map_data);

void gen_md_5(char *buf, int len);

char *check_error(char *str, int sz, const char *sender, ngx_http_request_t **r, char **p_mime_type, uint16_t *size_answer, ngx_log_t *p_log);

char *return_error(char *str, int sz, const char *sender, ngx_log_t *p_log);

ngx_int_t rqst_send_simple_answer(ngx_http_request_t *r, ngx_uint_t status,
    const char *mime_type, char *some_data, off_t some_data_size, ngx_log_t *p_log);

#ifndef LOG_REDEFS
#define LOG_REDEFS

    //#define DEBUG_LOG

    #define log_error(log, err, fmt, ...)\
        ngx_log_error(NGX_LOG_ERR, log, err, fmt, ##__VA_ARGS__),\
        LGR_MCRIT(fmt, ##__VA_ARGS__)

    #ifdef DEBUG_LOG

        #define log_error_core_debug(log, err, fmt, ...)\
            ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, ##__VA_ARGS__),\
            LGR_MDEBG(fmt, ##__VA_ARGS__)

        #define log_debug(log, err, fmt, ...)\
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, err, fmt, ##__VA_ARGS__),\
            LGR_MDEBG(fmt, ##__VA_ARGS__)

        #define log_debug0(log, err, fmt, ...)\
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, err, fmt),\
            LGR_MDEBG(fmt)

        #define log_debug1(log, err, fmt, arg1)\
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1),\
            LGR_MDEBG(fmt, arg1)

        #define log_debug2(log, err, fmt, arg1, arg2)\
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1, arg2),\
            LGR_MDEBG(fmt, arg1, arg2)

        #define log_debug3(log, err, fmt, arg1, arg2, arg3)\
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1, arg2, arg3),\
            LGR_MDEBG(fmt, arg1, arg2, arg3)

        #define log_debug4(log, err, fmt, arg1, arg2, arg3, arg4)\
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1, arg2, arg3, arg4),\
            LGR_MDEBG(fmt, arg1, arg2, arg3, arg4)

    #else

        #define log_error_core_debug(log, err, fmt, ...)\
            ngx_log_error_core(NGX_LOG_DEBUG, log, err, fmt, ##__VA_ARGS__)

        #define log_debug(log, err, fmt, ...)\
            ngx_log_debug(NGX_LOG_DEBUG_HTTP, log, err, fmt, ##__VA_ARGS__)

        #define log_debug0(log, err, fmt, ...)\
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, err, fmt)

        #define log_debug1(log, err, fmt, arg1)\
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1)

        #define log_debug2(log, err, fmt, arg1, arg2)\
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1, arg2)

        #define log_debug3(log, err, fmt, arg1, arg2, arg3)\
            ngx_log_debug3(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1, arg2, arg3)

        #define log_debug4(log, err, fmt, arg1, arg2, arg3, arg4)\
            ngx_log_debug4(NGX_LOG_DEBUG_HTTP, log, err, fmt, arg1, arg2, arg3, arg4)

    #endif

#endif

#endif	/* NGX_HTTP_RQST_MANAGER_MODULE_H */