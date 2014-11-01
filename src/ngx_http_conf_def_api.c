#include "ngx_http_conf_def_module.h"
#include "ngx_http_conf_def_api.h"

extern ngx_module_t ngx_http_conf_def_module;

ngx_http_conf_def_cfg_block_kv_pair_t*
ngx_http_conf_def_get_kv_pair(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key)
{
  uint32_t hash;
  ngx_http_conf_def_cfg_block_t* cfg_block = NULL;
  ngx_http_conf_def_cfg_block_kv_pair_t* kv_pair = NULL;
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)ngx_http_conf_get_module_main_conf(cf, ngx_http_conf_def_module);

  hash = ngx_crc32_long(section.data, section.len);
  cfg_block = (ngx_http_conf_def_cfg_block_t*)ngx_str_rbtree_lookup(&cdf->cfg_blocks, &section, hash);
  if(cfg_block != NULL){
    hash = ngx_crc32_long(key.data, key.len);
    kv_pair = (ngx_http_conf_def_cfg_block_kv_pair_t*)ngx_str_rbtree_lookup(&cfg_block->kv_pairs, &key, hash);
  }
  return kv_pair;
}

ngx_str_t 
ngx_http_conf_def_get_string(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key)
{
  return ngx_http_conf_def_get_string_with_default(cf, section, key, NULL);
}

ngx_str_t 
ngx_http_conf_def_get_string_with_default(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key, const char *d)
{
  ngx_str_t ret = ngx_null_string;
  ngx_http_conf_def_cfg_block_kv_pair_t* kv_pair;

  if(d != NULL){
    ret.data = (u_char*)d;
    ret.len  = strlen(d);
  }
 
  kv_pair = ngx_http_conf_def_get_kv_pair(cf, section, key);
  if(kv_pair != NULL && kv_pair->value.nelts > 0){
    ret = *(ngx_str_t*)kv_pair->value.elts;
  }
  
  return ret;
}

ngx_int_t 
ngx_http_conf_def_get_int(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key)
{
  return ngx_http_conf_def_get_int_with_default(cf, section, key, 0);
}

ngx_int_t 
ngx_http_conf_def_get_int_with_default(ngx_conf_t* cf, ngx_str_t section, ngx_str_t key, ngx_int_t d)
{
  ngx_str_t ret = ngx_null_string;
  ngx_http_conf_def_cfg_block_kv_pair_t* kv_pair;
  ngx_int_t ret_int = 0, flag = 1;
  size_t pos = 0;

  kv_pair = ngx_http_conf_def_get_kv_pair(cf, section, key);
  if(kv_pair != NULL && kv_pair->value.nelts > 0){
    ret = *(ngx_str_t*)kv_pair->value.nelts;
  }else
    return d;

  while(pos < ret.len){
    if(pos == 0){
       if(ret.data[pos] == '-' || ret.data[pos] == '+'){
         if(ret.data[pos] == '-')
           flag = -1;
         ++pos;
         continue;
       }
    }
    if(ret.data[pos] >= '0' && ret.data[pos] <= '9'){
      ret_int = ret_int*10 + (ret.data[pos] - '0');
    }else
      return d;
    ++pos;
  }
  return ret_int*flag;  
}
