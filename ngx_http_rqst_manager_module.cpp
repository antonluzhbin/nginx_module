/*
 * File:   ngx_http_rqst_manager_module.cpp
 * Author: anton
 *
 * Created on 11 Апрель 2013 г., 12:19
 */

#include "ngx_http_rqst_manager_module.h"

// сервер
ngx_http_rqst_manager_server_t ngx_http_rqst_manager_server;
// массив используемых адресов
rqst_manager_map_address_t rqst_manager_map_address;
// мьютекс для массива адресов
pthread_mutex_t rqst_manager_mutex_addr = PTHREAD_MUTEX_INITIALIZER;
// тред для разбора запросов на которые не было ответа
pthread_t rqst_manager_tr_map;
// флаг остановки треда
ngx_int_t rqst_manager_stop_thread;
// протокол
ucs_t *rqst_manager_uc;
// тред принимающий ответы от системы
pthread_t rqst_manager_tr_uc;
// для запуска треда
pthread_mutex_t rqst_manager_mutex_thread_all = PTHREAD_MUTEX_INITIALIZER;
int rqst_manager_thread_start = 0;

// описание директив из файла конфигурации
static ngx_command_t  ngx_http_rqst_manager_commands[] = {

    { ngx_string("rqst_manager_default_prefix"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_rqst_manager_module_serv_conf_t, default_prefix),
      NULL },
    { ngx_string("rqst_manager_default_extension"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_rqst_manager_module_serv_conf_t, default_extension),
      NULL },
    { ngx_string("rqst_manager_expires_day"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_rqst_manager_module_serv_conf_t, expires_day),
      NULL },
    { ngx_string("rqst_manager_work"),
      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_rqst_manager_module_loc_conf_t, work),
      NULL },
    { ngx_string("rqst_manager_path_config"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_rqst_manager_module_serv_conf_t, path_config),
      NULL },
    { ngx_string("rqst_manager_start_interval_msec"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_rqst_manager_module_serv_conf_t, start_interval_msec),
      NULL },
      ngx_null_command
};

static ngx_http_module_t  ngx_http_rqst_manager_module_ctx = {
    NULL,                                       /* preconfiguration */
    ngx_http_rqst_manager_init,                 /* postconfiguration */

    NULL,                                       /* create main configuration */
    NULL,                                       /* init main configuration */

    ngx_http_rqst_manager_create_serv_conf,     /* create server configuration */
    ngx_http_rqst_manager_merge_serv_conf,      /* merge server configuration */

    ngx_http_rqst_manager_create_loc_conf,      /* create location configuration */
    NULL                                        /* merge location configuration */
};

ngx_module_t  ngx_http_rqst_manager_module = {
    NGX_MODULE_V1,
    &ngx_http_rqst_manager_module_ctx,      /* module context */
    ngx_http_rqst_manager_commands,         /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    &ngx_http_rqst_manager_init_process,    /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    &ngx_http_rqst_manager_exit_process,    /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_rqst_manager_init_process(ngx_cycle_t *cycle)
{
    ngx_log_t *lg = cycle->log;

    pthread_mutex_lock(&rqst_manager_mutex_thread_all);
        if (rqst_manager_thread_start == 0)
        {
            // запускаем треды, если они еще не запущены
            rqst_manager_thread_start = 1;
            // флаг остановки
            rqst_manager_stop_thread = 0;
            
            #ifdef DEBUG_LOG
                Lgr_init_log(LGR_FACILITY_DEFAULT, LGR_FLAGS_DEFAULT, LGR_MSG_LENGTH_DEFAULT);
            #endif

            // запуск треда
            pthread_create(&rqst_manager_tr_map, NULL, f_tr1, (void *)(lg));
            log_error_core_debug(lg, 0, "RQST: address thread start");
            log_error_core_debug(lg, 0, "RQST: patch = %s", ngx_http_rqst_manager_server.path_config);

            // включение модуля в систему
            rqst_manager_uc = new ucs_t(ngx_http_rqst_manager_server.path_config, units, UNIT_COUNT);
            ucs_name_t un;
            // считываем название модуля
            rqst_manager_uc->get_unit_name(un);
            log_error_core_debug(lg, 0, "RQST: unit name = \"%s\"", un);

            // запуск треда
            pthread_create(&rqst_manager_tr_uc, NULL, ngx_http_rqst_manager_read, (void *)(lg));
            log_error_core_debug(lg, 0, "RQST: read thread start");
        }
    // разблокировка мьютекса
    pthread_mutex_unlock(&rqst_manager_mutex_thread_all);

    return NGX_OK;
}

void ngx_http_rqst_manager_exit_process(ngx_cycle_t *lg)
{
    // остановка треда
    log_error_core_debug(lg->log, 0, "RQST: address thread stop");

    // флаг остановки
    rqst_manager_stop_thread = 1;
    // ждем остановки треда
    usleep(ngx_http_rqst_manager_server.start_interval * 2);
}

// инициализация обработчика
static ngx_int_t ngx_http_rqst_manager_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = (ngx_http_handler_pt *)ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        log_error(cf->log, 0, "RQST: Error ngx_http_rqst_manager_init");
        return NGX_ERROR;
    }

    *h = ngx_http_rqst_manager_handler;

    return NGX_OK;
}
       
// обработчик HTTP запроса
static ngx_int_t ngx_http_rqst_manager_handler(ngx_http_request_t *r)
{
    ngx_http_rqst_manager_module_loc_conf_t  *rqst_manager_config;
    rqst_manager_config = (ngx_http_rqst_manager_module_loc_conf_t *)
                          ngx_http_get_module_loc_conf(r, ngx_http_rqst_manager_module);

    log_debug2(r->connection->log, 0, "RQST: Debug uri.data %s work %d", 
                   (char *)r->uri.data, rqst_manager_config->work);

    // проверка запрашиваемого файла
    if(rqst_manager_config->work != 1)
    {
        return NGX_DECLINED;
    }

    char str[NGX_HTTP_RQST_MANAGER_MAX_STRING_ARGS + 1];    // строка запроса
    char domen[NGX_HTTP_RQST_MANAGER_MAX_NAME_DOMEN + 1];   // домен страницы на которой установлен js
    char hash[NGX_HTTP_RQST_MANAGER_MAX_STRING_HASH + 1];   // строка хешей из js
    int id_place;                                           // id места
    int len;                                                // длина строки запроса
    char *p_str = str;                                      // указатель
    map_data_t map_data = { 0, 0, 0, 0 };                   // данные для массива адресов

    // ngx_http_request_t *r - указатель на структуру запроса
    str[0] = sizeof(r);             // размер адреса (ngx_http_request_t *r)
    p_str++;
    memcpy(p_str, &r, sizeof(r));    // адрес (ngx_http_request_t *r)
    p_str += sizeof(r);

    log_debug1(r->connection->log, 0, "RQST: Debug send pointer %p", r);

    // user_agent
    p_str = ngx_http_rqst_manager_copy_value(&r->headers_in.user_agent->value, p_str);

    // IP
    // r->headers_in.x_forwarded_for->value.data ?
    struct sockaddr_in   *sin;
    sin = (struct sockaddr_in *) r->connection->sockaddr;
    memcpy(p_str, &sin->sin_addr, 4);
    p_str += 4;

    // args - параметры запрашиваемой страницы (скрипта)
    // domen - выделенный из строки домен
    // hash - переменная хеш полученная с сайта
    // id_place - место
    p_str = ngx_http_rqst_manager_copy_args(&r->args, p_str, &id_place, domen, hash, &map_data);

    // завершение запроса из за нехватки данных, нет места, домена, хеша
    if (p_str == NULL)
    {
        log_error(r->connection->log, 0, "RQST: Error parameters args");
        // выдаем дефолт
        ngx_http_rqst_manager_finalize_request(r, &map_data);
        return NGX_AGAIN;
    }
    
    // генерация нового хеша и сравнение со старым (полученным с сайта)
    char new_hash[NGX_HTTP_RQST_MANAGER_MAX_HASH + 1];
    sprintf(new_hash, "%s_%d_poladis", domen, id_place);
    gen_md_5(new_hash, strlen(new_hash));

    log_debug1(r->connection->log, 0, "RQST: Debug new hash %s", new_hash);

    // сравнение сгенерированного хеша и хеша полученного из js
    char *hash_pos = strstr(hash, new_hash);
    if (hash_pos == NULL || (hash_pos > hash && *(hash_pos - 1) != ';'))
    {
        log_error(r->connection->log, 0, "RQST: Error new_hash %s != old_hash %s", new_hash, hash);
        // выдаем дефолт
        ngx_http_rqst_manager_finalize_request(r, &map_data);
        return NGX_AGAIN;
    }

    // cookies
    char cook[NGX_HTTP_RQST_MANAGER_MAX_COOKIES + 1];
    const char key_cook[] = "poladis";                      // имя куки
    int8_t key_cook_len = strlen(key_cook) + 1;             // + 1 - символ '='
    int8_t cook_len;
    int8_t cook_fl = 1;                                     // флаг для проверки установки новой куки

    // если в заголовках HTTP запроса есть установленные куки
    if (r->headers_in.cookies.nelts > 0)
    {
        ngx_table_elt_t **cookies = (ngx_table_elt_t **)r->headers_in.cookies.elts;
        char *cookie_data = (char *)cookies[0]->value.data;
        
        log_debug1(r->connection->log, 0, "RQST: Debug old cookies %s", cookie_data);

        // ищем имя куки
        char *p_cook = strstr(cookie_data, key_cook);
        if (p_cook != NULL)
        {
            cook_len = strlen(cookie_data) - (p_cook - cookie_data) + key_cook_len;
            if (cook_len > NGX_HTTP_RQST_MANAGER_MAX_COOKIES)
                cook_len = NGX_HTTP_RQST_MANAGER_MAX_COOKIES;
            // копируем кук в строку
            strncpy(cook, (p_cook + key_cook_len), cook_len);
            // установка конца строки
            if ((p_cook = strchr(cook, ';')) != NULL ||
                (p_cook = strchr(cook, ' ')) != NULL)
            {
                // если кук не один, обрезаем строку по символам ';' или ' '
                *p_cook = 0;
            }
            else
            {
                // если кук один, то обрезаем по длине
                cook[cook_len] = 0;
            }
            cook_fl = 0;
        }
    }

    int sec = 0, usec = 0, rnd = 0;
    // генерация новой куки
    if (cook_fl)
    {
        // генерация
        struct timeval tv;
        gettimeofday((struct timeval *) &tv, (struct timezone *) NULL);
        sec = (int) tv.tv_sec;
        // оставляем от микросерунд последние 5 байт
        usec = (int) (tv.tv_usec % 0x100000);
        rnd = (int) random();
        sprintf(cook, "%08x%05x%08x", sec, usec, rnd);      // длина 21 символ
    
        char cc[NGX_HTTP_RQST_MANAGER_MAX_COOKIE_HEADER_LEN];
        struct tm *time_t2;
        // преобразование метки времени в дату + время
        tv.tv_sec += 24 * 60 * 60 * ngx_http_rqst_manager_server.expires_day;   // количество секунд - время жизни кука
        time_t2 = gmtime (&tv.tv_sec);

        //expires=Thu, 21 Mar 2014 13:37:13 GMT
        // D, d-M-Y H:i:s T

        sprintf(cc, "poladis=%s; expires=%s, %d-%s-%d %d:%d:%d GMT; domain=localhost; path=/", cook,
            day_short_names[time_t2->tm_wday], time_t2->tm_mday,
            mon_short_names[time_t2->tm_mon], (time_t2->tm_year + 1900),
            time_t2->tm_hour, time_t2->tm_min, time_t2->tm_sec);

        cook_len = strlen(cc);        
        u_char *cookie = (u_char *)ngx_pnalloc(r->pool, cook_len);            // выделение памяти
        if (cookie == NULL)
        {
            log_error(r->connection->log, 0, "RQST: Error ngx_pnalloc cookie");
        }
        else
        {
            sprintf((char *)cookie, "%s", cc);
            ngx_table_elt_t  *set_cookie;
            set_cookie = (ngx_table_elt_t *)ngx_list_push(&r->headers_out.headers);    // установка куки в HTTP заголовок
            if (set_cookie == NULL)
            {
                log_error(r->connection->log, 0, "RQST: Error ngx_pnalloc cookie");
            }
            else
            {
                set_cookie->hash = 1;
                ngx_str_set(&set_cookie->key, "Set-Cookie");
                set_cookie->value.len = cook_len;
                set_cookie->value.data = cookie;
                log_debug1(r->connection->log, 0, "RQST: Debug new cookie %s", cook);
            }
        }
    }
    else
    {
        // преобразовываем старый кук в бинарный вид
        char tmp[10];
        strncpy(tmp, cook, 8);
        sscanf(tmp, "%x", &sec);
        tmp[8] = 0;
        strncpy(tmp, cook + 8, 5);
        tmp[5] = 0;
        sscanf(tmp, "%x", &usec);
        strncpy(tmp, cook + 13, 8);
        tmp[8] = 0;
        sscanf(tmp, "%x", &rnd);
    }

    sprintf(cook, "%08x%05x%08x", sec, usec, rnd);
    log_debug4(r->connection->log, 0, "RQST: cookie = %s (%d %d %d)", cook, sec, usec, rnd);

    // копируем куку в буфер
    p_str[0] = cook_fl;                         // 1 - кука новая, 0 - нет
    ++p_str;
    memcpy(p_str, &sec, 4);                      // значение куки
    p_str += 4;
    memcpy(p_str, &usec, 3);
    p_str += 3;
    memcpy(p_str, &rnd, 4);
    p_str += 4;

    // блокировка мьютекса
    pthread_mutex_lock(&rqst_manager_mutex_addr);
        // сохраняем адрес в массив
        rqst_manager_map_address.insert(pair_address_t (r, map_data));
    // разблокировка мьютекса
    pthread_mutex_unlock(&rqst_manager_mutex_addr);

    // параметры запроса
    ucs_message_t buff;
    buff.address = MODULE_GEO;
    len = p_str - str;
    buff.set_data(str, len);
    // отправка запроса
    rqst_manager_uc->send(&buff);
    log_debug0(r->connection->log, 0, "RQST: send OK");

    // нормальное завершение
    return NGX_AGAIN;
}

char *check_error(char* str, int sz, const char* sender, ngx_http_request_t** r,
    char** p_mime_type, uint16_t* size_answer, ngx_log_t* p_log)
{
    log_debug1(p_log, 0, "RQST: Debug recv size %d", sz);
    if (sz > NGX_HTTP_RQST_MANAGER_MAX_REQUEST)
    {
        log_error(p_log, 0, "RQST: Error size request = %d", sz);
        sz = NGX_HTTP_RQST_MANAGER_MAX_REQUEST;
    }

    // проверка размера указателя
    if (str[0] != sizeof(ngx_http_request_t *))
    {
        log_error(p_log, 0, "RQST: Error size ngx_http_request_t *r");
        return NULL;
    }
    memcpy(r, (str + 1), str[0]);
    log_debug1(p_log, 0, "RQST: Debug recv pointer %p", *r);

    char *p_str = str + str[0] + 1;

    // блокировка мьютекса
    pthread_mutex_lock(&rqst_manager_mutex_addr);
    // проверка правильности адреса
    rqst_manager_map_address_t::iterator it = rqst_manager_map_address.find(*r);
    if (it == rqst_manager_map_address.end())
    {
        // разблокировка мьютекса
        pthread_mutex_unlock(&rqst_manager_mutex_addr);
        log_error(p_log, 0, "RQST: Error ngx_http_request_t *r not found");
        return NULL;
    }

    // считываем данных из массива
    ngx_http_request_t *tmp_r = it->first;
    map_data_t tmp_d = it->second;

    // удаление адреса
    rqst_manager_map_address.erase(it);
    // разблокировка мьютекса
    pthread_mutex_unlock(&rqst_manager_mutex_addr);

    // проверка на ошибку
    if (p_str[0] == 1)
    {
        // возврат ошибки передачи
        ngx_http_rqst_manager_finalize_request(tmp_r, &tmp_d);
        log_error(p_log, 0, "RQST: unit \"%s\" returned error", sender);
        return NULL;
    }
    p_str++;
    
    // длина типа
    uint8_t size_mime_type = *p_str;
    p_str++;

    // указатель на тип
    *p_mime_type = p_str;
    p_str += size_mime_type;

    size_mime_type -= 1;
    if (size_mime_type != strlen(*p_mime_type))
    {
        ngx_http_rqst_manager_finalize_request(tmp_r, &tmp_d);
        log_error(p_log, 0, "RQST: Error size mime type");
        return NULL;               
    }
    log_debug1(p_log, 0, "RQST: Debug recv size mime type %d", size_mime_type);
    log_debug1(p_log, 0, "RQST: Debug recv mime_type \"%s\"", *p_mime_type);

    // длина ответа
    memcpy(size_answer, p_str, 2);
    p_str += 2;

    *size_answer -= 1;
    if (*size_answer != strlen(p_str))
    {
        ngx_http_rqst_manager_finalize_request(tmp_r, &tmp_d);
        log_error(p_log, 0, "RQST: Error size string (%i != %i)", *size_answer, (int)strlen(p_str));
        return NULL;
    }
    log_debug1(p_log, 0, "RQST: Debug recv size string %d", *size_answer);
    log_debug1(p_log, 0, "RQST: Debug recv string \"%s\"", p_str);
    
    return p_str;
}

char *return_error(char *str, int sz, const char *sender, ngx_log_t *p_log)
{
    ngx_http_request_t *r;
    
    log_debug1(p_log, 0, "RQST: Debug recv size %d", sz);
    if (sz > NGX_HTTP_RQST_MANAGER_MAX_REQUEST)
    {
        log_error(p_log, 0, "RQST: Error size request = %d", sz);
        sz = NGX_HTTP_RQST_MANAGER_MAX_REQUEST;
    }

    // проверка размера указателя
    if (str[0] != sizeof(ngx_http_request_t *))
    {
        log_error(p_log, 0, "RQST: Error size ngx_http_request_t *r");
        return NULL;
    }
    memcpy(&r, (str + 1), str[0]);
    log_debug1(p_log, 0, "RQST: Debug recv pointer %p", r);

    //char *p_str = str + str[0] + 1;

    // блокировка мьютекса
    pthread_mutex_lock(&rqst_manager_mutex_addr);
    // проверка правильности адреса
    rqst_manager_map_address_t::iterator it = rqst_manager_map_address.find(r);
    if (it == rqst_manager_map_address.end())
    {
        // разблокировка мьютекса
        pthread_mutex_unlock(&rqst_manager_mutex_addr);
        log_error(p_log, 0, "RQST: Error ngx_http_request_t *r not found");
        return NULL;
    }

    // считываем данных из массива
    ngx_http_request_t *tmp_r = it->first;
    map_data_t tmp_d = it->second;
    // удаление адреса
    rqst_manager_map_address.erase(it);
    // разблокировка мьютекса
    pthread_mutex_unlock(&rqst_manager_mutex_addr);

    // возврат ошибки передачи
    ngx_http_rqst_manager_finalize_request(tmp_r, &tmp_d);
    log_error(p_log, 0, "RQST: send to \"%s\" failed", sender);

    return NULL;
}

ngx_int_t rqst_send_simple_answer(ngx_http_request_t *r, ngx_uint_t status,
    const char *mime_type, char *some_data, off_t some_data_size, ngx_log_t *p_log)
{
    // установка  HTTP заголовков
    r->headers_out.status = status;
    r->headers_out.content_length_n = some_data_size;
    // Warn: const -> var, Don't use ngx_str_set(), it sets length error.
    // ngx_str_set() uses sizeof() instead strlen()
    r->headers_out.content_type.data = (u_char *)mime_type;
    r->headers_out.content_type.len = strlen(mime_type);
    //ngx_str_set(&r->headers_out.content_type, mime_type);

    ngx_int_t err = ngx_http_send_header(r);  // отправка заголовков
    if (err != NGX_OK)
    {
        log_error(p_log, 0,
            "RQST: Error ngx_http_send_header %s", strerror(errno));
        ngx_http_finalize_request(r, 0);
        return 1;
    }
    
    // выделение буфера под ответ
    ngx_buf_t *b = (ngx_buf_t *)ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
    {
        log_error(p_log, 0, "RQST: Error ngx_pcalloc");
        ngx_http_finalize_request(r, 0);
        return 1;
    }

    b->pos = (u_char *) some_data;                      // позиция первого байта
                                                        // в блоке данных
    b->last = (u_char *) some_data + some_data_size;    // позиция за последним

    b->memory = 1;      // данные храняться в памяти только для чтения (1)
                        // (то есть фильтры должны скопировать эти данные
                        // перед обработкой,вместо того, чтобы изменять их)

    b->last_buf = 1;    // буферов в запросе больше не будет

    ngx_chain_t out;
    out.buf = b;
    out.next = NULL;

    err = ngx_http_output_filter(r, &out);              // отправка ответа
    if (err != NGX_OK)
    {
        log_error(p_log, 0, "RQST: Error ngx_http_output_filter");
        ngx_http_finalize_request(r, 0);
        return 1;
    }
    
    ngx_http_finalize_request(r, 0);
    log_debug0(p_log, 0,
        "RQST: Debug ngx_http_finalize_request OK");
    
    return 0;
}

// чтение ответа от сервера
void *ngx_http_rqst_manager_read(void *lg)
{
    //char str[NGX_HTTP_RQST_MANAGER_MAX_REQUEST];
    int j, count;
    ngx_http_request_t *r;
    ngx_log_t *p_log = (ngx_log_t *)lg;
    char *p_str, *p_mime_type;
    uint16_t size_answer;
    ngx_int_t rc;

    ucs_message_t buff[UCS_INSIDE_RCV_BUFF_SIZE];

    for ( ;; )
    {
        count = rqst_manager_uc->recv(buff);
        for (j = 0; j < count; j++)
        {
            if (buff[j].type == UCS_MESSAGE_TYPE_DATA)
            {
                 switch (buff[j].address)
                 {
                     case MODULE_GEO:
                     case MODULE_MAIN:
                     case MODULE_STORAGE:
                     case MODULE_STATISTICS:
                        
                        p_str = check_error(buff[j].get_data(), buff[j].get_size(), units[buff[j].address], &r, &p_mime_type, &size_answer, p_log);
                        if (p_str == NULL)
                            break;
                        
                        rc = rqst_send_simple_answer(r, NGX_HTTP_OK, p_mime_type, p_str, size_answer, r->connection->log);
                        if (rc != 0)
                           break;
                            
                        break;

                    default:
                        log_error(p_log, 0, "RQST: Wrong source \"%s\"", units[buff[j].address]);
                 }
             }
             else
             {
                // other checks
                log_error(p_log, 0, "RQST: Other data types (%i) from \"%s\"",
                    buff[j].type, units[buff[j].address]);   // ns or nc data                
                
                // if send result to MODULE_GEO failed
                if (buff[j].type == UCS_MESSAGE_TYPE_NS &&
                    buff[j].address == MODULE_GEO)
                        return_error(buff[j].get_data(), buff[j].get_size(), units[buff[j].address], p_log);
             }
         }
    }
    return NULL;
}

// создание конфигурации
static void* ngx_http_rqst_manager_create_serv_conf(ngx_conf_t *cf)
{
    ngx_http_rqst_manager_module_serv_conf_t *conf = (ngx_http_rqst_manager_module_serv_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_rqst_manager_module_serv_conf_t));
    if (conf == NULL)
        return NGX_CONF_ERROR;

    conf->default_prefix.data = NULL;
    conf->default_extension.data = NULL;
    conf->expires_day = NGX_CONF_UNSET;
    conf->path_config.data = NULL;
    conf->start_interval_msec = NGX_CONF_UNSET;
    
    return conf;
}

// создание конфигурации
static void* ngx_http_rqst_manager_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_rqst_manager_module_loc_conf_t *conf = (ngx_http_rqst_manager_module_loc_conf_t *)ngx_pcalloc(cf->pool, sizeof(ngx_http_rqst_manager_module_loc_conf_t));
    if (conf == NULL)
        return NGX_CONF_ERROR;

    conf->work = NGX_CONF_UNSET;

	return conf;
}

// слияние конфигурации
static char* ngx_http_rqst_manager_merge_serv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_rqst_manager_module_serv_conf_t *prev = (ngx_http_rqst_manager_module_serv_conf_t *)parent;
    ngx_http_rqst_manager_module_serv_conf_t *conf = (ngx_http_rqst_manager_module_serv_conf_t *)child;

    ngx_conf_merge_str_value(conf->path_config, prev->path_config, "./nginx.ini");
    ngx_conf_merge_str_value(conf->default_prefix, prev->default_prefix, "default");
    ngx_conf_merge_str_value(conf->default_extension, prev->default_extension, "png");
    ngx_conf_merge_value(conf->expires_day, prev->expires_day, 365);
    ngx_conf_merge_value(conf->start_interval_msec, prev->start_interval_msec, 3000); 

    log_debug0(cf->log, 0, "RQST: merge_serv_conf OK");

    sprintf(ngx_http_rqst_manager_server.path_config, "%s", conf->path_config.data);
    sprintf(ngx_http_rqst_manager_server.default_prefix, "%s", conf->default_prefix.data);
    sprintf(ngx_http_rqst_manager_server.default_extension, "%s", conf->default_extension.data);
    ngx_http_rqst_manager_server.expires_day = conf->expires_day;
    ngx_http_rqst_manager_server.start_interval = conf->start_interval_msec * 1000;
    
    return NGX_CONF_OK;
}

void * f_tr1(void * str)
{
    //return NULL;
    
    ngx_log_t   *p_log = (ngx_log_t *)str;
    rqst_manager_map_address_t::iterator it;
    
    while (rqst_manager_stop_thread != 1)
    {
        // запуск раз в пол секунды
        usleep(ngx_http_rqst_manager_server.start_interval);
        pthread_mutex_lock(&rqst_manager_mutex_addr);
            if (!rqst_manager_map_address.empty())
            {
                // проход по массиву
                for (it = rqst_manager_map_address.begin(); it != rqst_manager_map_address.end(); )
                {
                    // удаление если не было ответа в течении 1 секунды
                    if (it->second.count > 0)
                    {
                        // выдача дефолта
                        log_error(p_log, 0, "RQST: answer not recv: %p", it->first);
                        ngx_http_rqst_manager_finalize_request(it->first, &it->second);
                        // удаление адреса
                        rqst_manager_map_address.erase(it++);
                    }
                    else
                    {
                        it->second.count++;
                        ++it;
                    }
                }
            }
        // снятие блокировки
        pthread_mutex_unlock(&rqst_manager_mutex_addr);
    }
    return NULL;
}

void ngx_http_rqst_manager_finalize_request(ngx_http_request_t *r, map_data_t *map_data)
{
    char str[1024];
    int i;
    // выдача дефолта
    log_error(r->connection->log, 0, "RQST: default (%i x %i, %i)",
        map_data->w, map_data->h, map_data->p);
    
    if (map_data->p == 0)
        i = 0;
    else
    {
        if (map_data->h == 0 || map_data->w == 0)
            i = sprintf(str, "K = document.getElementById(\"poladis_banner_%u\"); K.innerHTML = '<img src=\"%s.%s\">';",
                    map_data->p,
                    ngx_http_rqst_manager_server.default_prefix,
                    ngx_http_rqst_manager_server.default_extension
                    );
        else
            i = sprintf(str, "K = document.getElementById(\"poladis_banner_%u\");  K.innerHTML = '<img src=\"%s_%d_%d.%s\" width=\"%u\" height=\"%u\">';",
                    map_data->p,
                    ngx_http_rqst_manager_server.default_prefix, map_data->w, map_data->h,
                    ngx_http_rqst_manager_server.default_extension, map_data->w, map_data->h
                    );
    }
    
    int rc = rqst_send_simple_answer(r, NGX_HTTP_OK, "text/javascript", str, i, r->connection->log);
    if (rc != 0)
       return;

    return;
}

// копирование данных в буфер (длина + данные)
char *ngx_http_rqst_manager_copy_value(ngx_str_t *data, char *ptr)
{
    if (data->len < 256)
    {
        *ptr = data->len + 1;
        memcpy(++ptr, data->data, data->len);
        ptr += data->len + 1;
    }
    else
    {
        *ptr = 255;
        memcpy(++ptr, data->data, 255);
        ptr += 255;
    }

    *(ptr - 1) = 0;

    return ptr;
}

int ngx_http_rqst_manager_htoi(char *s)
{
	int value;
	int c;

	c = ((unsigned char *)s)[0];
	if (isupper(c))
		c = tolower(c);
	value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

	c = ((unsigned char *)s)[1];
	if (isupper(c))
		c = tolower(c);
	value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

	return (value);
}

// преобразование адреса строки
int ngx_http_rqst_manager_url_decode(char *str, int len)
{
	char *dest = str;
	char *data = str;

	while (len--) 
        {
            if (*data == '+') 
            {
                *dest = ' ';
            }
            else 
            {
                if (*data == '%' && len >= 2 && isxdigit((int) *(data + 1))
                    && isxdigit((int) *(data + 2))) 
                {   
                    *dest = (char) ngx_http_rqst_manager_htoi(data + 1);
                    data += 2;
                    len -= 2;
                }
                else 
                {
                    *dest = *data;
                }
            }
            data++;
            dest++;
	}
	*dest = 0;
	return dest - str;
}

// выделение параметров из строки запроса
// id места, часовой пояс, видимость баннера, адрес страницы - копируются в буфер
// домен и хеш - копируются в соответсвующие строки (domen, hash)
// размеры баннера - map_data
char *ngx_http_rqst_manager_copy_args(ngx_str_t *args, char *ptr, int *id_place, char *domen, char *hash, map_data_t *map_data)
{
    args_data ad;
    char str[NGX_HTTP_RQST_MANAGER_MAX_STRING_ARGS + 1];
    char *p_str, *p_str_2;
    int cnt = 0;
    int tm;

    ad.tm = 4;                                      // часовой пояс Москвы
    ad.pp = 0;                                      // нет id места
    ad.vb = 2;                                      // баннер не виден
    ad.h = 0;                                       // высота экрана
    ad.w = 0;                                       // ширина экрана
    ad.len_page = 0;                                // нет данных о странице
    ad.len_hash = 0;                                // нет данных хеша

    if (args->len > 0)
    {
        if (args->len > NGX_HTTP_RQST_MANAGER_MAX_STRING_ARGS + 1)
        {
            memcpy(str, args->data, NGX_HTTP_RQST_MANAGER_MAX_STRING_ARGS);
            str[NGX_HTTP_RQST_MANAGER_MAX_STRING_ARGS + 1] = 0;
        }
        else
        {
            memcpy(str, args->data, args->len);
            str[args->len] = 0;
        }
        p_str_2 = str;

        while((p_str = strchr(p_str_2, '=')))
        {
            p_str_2 = p_str + 1;
            // проверка наличия первого параметра
            if (p_str < (str + 2))
                continue;

            switch(*(p_str - 1))
            {
                // tm - часовой пояс
                case 'm':
                    if (*(p_str - 2) == 't')
                    {
                        cnt = sscanf((p_str + 1), "%d", &tm);
                        if (cnt > 0 && tm > -25 && tm < 29)
                            ad.tm = tm;
                    }
                    break;

                // pp - id места
                case 'p':
                    if (*(p_str - 2) == 'p')
                    {
                        cnt = sscanf((p_str + 1), "%d", &tm);
                        if (cnt > 0)
                        {
                            ad.pp = tm;
                            map_data->p = tm;
                        }
                        else
                            return NULL;
                    }
                    break;

                // vb - видимость баннера
                case 'b':
                    if (*(p_str - 2) == 'v')
                    {
                        cnt = sscanf((p_str + 1), "%d", &tm);
                        if (cnt > 0 && tm >= 0 && tm < 3)
                            ad.vb = tm;
                    }
                    else
                    {
                        // wb - ширина баннера
                        if (*(p_str - 2) == 'w')
                        {
                            cnt = sscanf((p_str + 1), "%d", &tm);
                            if (cnt > 0)
                                map_data->w = tm;
                        }
                        else
                        {
                            // hb - высота баннера
                            if (*(p_str - 2) == 'h')
                            {
                                cnt = sscanf((p_str + 1), "%d", &tm);
                                if (cnt > 0)
                                    map_data->h = tm;
                            }
                        }
                    }
                    break;

                // pg - адрес страницы
                case 'g':
                    if (*(p_str - 2) == 'p')
                    {
                        ad.ptr_page = p_str + 1;
                        char *p_end = strchr(p_str, '&');
                        if (p_end == NULL)
                        {
                            ad.len_page = strlen(str) - (p_str - str) - 1;
                        }
                        else
                        {
                            ad.len_page = p_end - ad.ptr_page;
                            p_str = p_end;
                        }
                        if (ad.len_page > NGX_HTTP_RQST_MANAGER_MAX_STRING_ADDRESS)
                            ad.len_page = NGX_HTTP_RQST_MANAGER_MAX_STRING_ADDRESS;

                    }
                    else
                    {
                        // hg - высота
                        if (*(p_str - 2) == 'h')
                        {
                            cnt = sscanf((p_str + 1), "%d", &tm);
                            if (cnt > 0)
                                ad.h = tm;
                        }
                    }
                    break;

                // hs - хеш
                case 's':
                    if (*(p_str - 2) == 'h')
                    {
                        ad.ptr_hash = p_str + 1;
                        char *p_end = strchr(p_str, '&');
                        if (p_end == NULL)
                        {
                            ad.len_hash = strlen(str) - (p_str - str) - 1;
                        }
                        else
                        {
                            ad.len_hash = p_end - ad.ptr_hash;
                            p_str = p_end;
                        }
                        if (ad.len_hash > NGX_HTTP_RQST_MANAGER_MAX_STRING_HASH)
                            ad.len_hash = NGX_HTTP_RQST_MANAGER_MAX_STRING_HASH;
                    }
                    break;
                // wd - ширина
                case 'd':
                    if (*(p_str - 2) == 'w')
                    {
                        cnt = sscanf((p_str + 1), "%d", &tm);
                        if (cnt > 0)
                            ad.w = tm;
                    }
                    break;
            }
        }
    }

    // проверка id места, страницы и хеша
    if (ad.pp == 0 || ad.len_page == 0 || ad.len_hash == 0)
        return NULL;

    // id место
    memcpy(ptr, &ad.pp, 4);
    memcpy(id_place, &ad.pp, 4);
    // временная зона
    ptr[4] = ad.tm;
    // видимость баннера
    ptr[5] = ad.vb;
    ptr += 6;
    // длина адреса страницы
    memcpy(ptr, &ad.len_page, 2);
    // адрес страницы
    memcpy((ptr + 2), ad.ptr_page, ad.len_page);
    *(ptr + *ptr + 2) = 0;
    ptr += 2;

    // декодирование адреса страницы
    *(ptr - 2) = ngx_http_rqst_manager_url_decode(ptr, *(ptr - 2));
    *(ptr - 2) = strlen(ptr) + 1;
    ad.len_page = *(ptr - 2) - 1;
    ad.ptr_page = ptr;
    ptr += *(ptr - 2);
    *(ptr - 1) = 0;

    // выделение из адреса страницы домена
    for (cnt = 0; cnt < ad.len_page; ++cnt)
    {
        if (*ad.ptr_page == '/' && *(ad.ptr_page + 1) == '/')
        {
            ad.ptr_page += 2;
            // убираем www. если есть
            if (*ad.ptr_page == 'w' && *(ad.ptr_page + 1) == 'w' 
                && *(ad.ptr_page + 2) == 'w' 
                && *(ad.ptr_page + 3) == '.')
            {
                ad.ptr_page += 4;
            }
            break;
        }
        ++ad.ptr_page;
    }
    if (cnt == ad.len_page)                     // не найдено начало домена
        return NULL;

    while (cnt < ad.len_page && *(ad.ptr_page + cnt) != '?' 
           && *(ad.ptr_page + cnt) != '/' 
           && *(ad.ptr_page + cnt) != '#')
    {
        ++cnt;
    }

    // домен
    if (cnt > NGX_HTTP_RQST_MANAGER_MAX_NAME_DOMEN)
        cnt = NGX_HTTP_RQST_MANAGER_MAX_NAME_DOMEN;
    memcpy(domen, ad.ptr_page, cnt);
    domen[cnt] = 0;

    // хеш
    memcpy(hash, ad.ptr_hash, ad.len_hash);
    hash[ad.len_hash] = 0;

    // высота и ширина экрана пользователя
    memcpy(ptr, &ad.w, 2);
    memcpy((ptr + 2), &ad.h, 2);
    ptr += 4;

    return ptr;
}

// генерация хеша
void gen_md_5(char *buf, int len)
{
    unsigned char res[NGX_HTTP_RQST_MANAGER_MAX_HASH + 1];
    static const char st[] = "0123456789abcdef";
    MD5((unsigned char *) buf, len, res);
    char *p_res = buf;
    int j;

    // преобразование из числа в строку
    for(j = 0; j < MD5_DIGEST_LENGTH; ++j)
    {
        p_res[0] = st[res[j] / 16];
        p_res[1] = st[res[j] % 16];
        p_res += 2;
    }
    *p_res = 0;

    return;
}
