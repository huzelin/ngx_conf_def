#ifndef H_NGX_HTTP_CONF_DEF_API_H
#define H_NGX_HTTP_CONF_DEF_API_H

#include <ngx_config.h>
#include <ngx_core.h>

/// config
extern ngx_str_t ngx_http_conf_def_get_string(ngx_str_t section, ngx_str_t key);
extern ngx_str_t ngx_http_conf_def_get_string_with_default(ngx_str_t section, ngx_str_t key, const char *d);
extern ngx_int_t ngx_http_conf_def_get_int(ngx_str_t section, ngx_str_t key);
extern ngx_int_t ngx_http_conf_def_get_int_with_default(ngx_str_t section, ngx_str_t key, ngx_int_t d);

/// binary data file management
extern ngx_array_t* ngx_http_conf_def_get_group_ptr_array(ngx_str_t group_name);
extern ngx_str_t    ngx_http_conf_def_get_data_file_nickname(ngx_array_t* group_ptr_array, size_t idx);
extern u_char*      ngx_http_conf_def_get_data_file_ptr(ngx_array_t* group_ptr_array, size_t idx);
extern size_t       ngx_http_conf_def_get_data_file_size(ngx_array_t* group_ptr_array, size_t idx);
extern void* ngx_http_conf_def_get_data_file_idx(ngx_str_t group_name, ngx_str_t data_file_nick_name, ngx_uint_t* idx);

/// binary-data search algorith

/// 1. trie-data structure
typedef struct ngx_conf_def_trie_node_s{
  int32_t ibase;
  int32_t iprev;
  uint32_t uvalue_pos;
  uint32_t uvalue_len;
}ngx_conf_def_trie_node_t;

typedef struct ngx_conf_def_trie_match_info_s{
  uint32_t umatch_pos;
  uint32_t umatch_len;
  const u_char *uvalue;
  uint32_t uvalue_len;
  int32_t ioparg;
}ngx_conf_def_trie_match_info_t;

/// raw interface
extern ngx_str_t  ngx_http_conf_def_trie_match_longest(u_char *rkey, size_t ksize, u_char *rvalue, ngx_str_t query, size_t* match_len);
extern ngx_uint_t ngx_http_conf_def_trie_match_path(u_char *rkey, size_t ksize, u_char *rvalue, ngx_str_t query, ngx_array_t* hits);
extern ngx_uint_t ngx_http_conf_def_trie_match_all(u_char *rkey, size_t ksize, u_char *rvalue, ngx_str_t query, ngx_array_t* hits);

typedef struct ngx_conf_def_trie_s{
  void* kv_pair_rkey;
  void* kv_pair_rvalue;
  ngx_str_t group_name;
  ngx_str_t nick_name_key;
  ngx_str_t nick_name_value;
}ngx_conf_def_trie_t;

/// good interface
extern ngx_int_t  ngx_http_conf_def_init_trie(ngx_conf_def_trie_t* trie, ngx_str_t grou_name, ngx_str_t nick_name_key, ngx_str_t nick_name_value);
extern ngx_str_t  ngx_http_conf_def_trie_stru_match_longest(ngx_conf_def_trie_t* trie, ngx_str_t query, size_t* match_len);
extern ngx_uint_t ngx_http_conf_def_trie_stru_match_path(ngx_conf_def_trie_t* trie, ngx_str_t query, ngx_array_t* hits);
extern ngx_uint_t ngx_http_conf_def_trie_stru_match_all(ngx_conf_def_trie_t* trie, ngx_str_t query, ngx_array_t* hits);

#endif
