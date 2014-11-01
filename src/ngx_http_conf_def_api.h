#ifndef H_NGX_HTTP_CONF_DEF_API_H
#define H_NGX_HTTP_CONF_DEF_API_H

#include <ngx_config.h>
#include <ngx_core.h>

extern ngx_str_t ngx_http_conf_def_get_string(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key);
extern ngx_str_t ngx_http_conf_def_get_string_with_default(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key, const char *d);

extern ngx_int_t ngx_http_conf_def_get_int(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key);
extern ngx_int_t ngx_http_conf_def_get_int_with_default(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key, ngx_int_t d);

#endif
