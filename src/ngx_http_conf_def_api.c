#include "ngx_http_conf_def_module.h"
#include "ngx_http_conf_def_api.h"

extern ngx_module_t ngx_http_conf_def_module;
extern ngx_http_conf_def_t* ngx_global_cdf; 

ngx_http_conf_def_cfg_block_kv_pair_t*
ngx_http_conf_def_get_kv_pair(ngx_str_t section, ngx_str_t key)
{
  uint32_t hash;
  ngx_http_conf_def_cfg_block_t* cfg_block = NULL;
  ngx_http_conf_def_cfg_block_kv_pair_t* kv_pair = NULL;
  ngx_http_conf_def_t* cdf = ngx_global_cdf;
  if(cdf == NULL)
    return NULL;

  hash = ngx_crc32_long(section.data, section.len);
  cfg_block = (ngx_http_conf_def_cfg_block_t*)ngx_str_rbtree_lookup(&cdf->cfg_blocks, &section, hash);
  if(cfg_block != NULL){
    hash = ngx_crc32_long(key.data, key.len);
    kv_pair = (ngx_http_conf_def_cfg_block_kv_pair_t*)ngx_str_rbtree_lookup(&cfg_block->kv_pairs, &key, hash);
  }
  return kv_pair;
}

ngx_str_t 
ngx_http_conf_def_get_string(ngx_str_t section, ngx_str_t key)
{
  return ngx_http_conf_def_get_string_with_default(section, key, NULL);
}

ngx_str_t 
ngx_http_conf_def_get_string_with_default(ngx_str_t section, ngx_str_t key, const char *d)
{
  ngx_str_t ret = ngx_null_string;
  ngx_http_conf_def_cfg_block_kv_pair_t* kv_pair;

  if(d != NULL){
    ret.data = (u_char*)d;
    ret.len  = strlen(d);
  }
 
  kv_pair = ngx_http_conf_def_get_kv_pair(section, key);
  if(kv_pair != NULL && kv_pair->value.nelts > 0){
    ret = *(ngx_str_t*)kv_pair->value.elts;
  }
  
  return ret;
}

ngx_int_t 
ngx_http_conf_def_get_int(ngx_str_t section, ngx_str_t key)
{
  return ngx_http_conf_def_get_int_with_default(section, key, 0);
}

ngx_int_t 
ngx_http_conf_def_get_int_with_default(ngx_str_t section, ngx_str_t key, ngx_int_t d)
{
  ngx_str_t ret = ngx_null_string;
  ngx_http_conf_def_cfg_block_kv_pair_t* kv_pair;
  ngx_int_t ret_int = 0, flag = 1;
  size_t pos = 0;

  kv_pair = ngx_http_conf_def_get_kv_pair(section, key);
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

static ngx_http_conf_def_data_group_t*
ngx_http_conf_def_get_group(ngx_str_t group_name)
{
  ngx_http_conf_def_data_group_t* group;
  uint32_t hash;
  char* rv;

  hash = ngx_crc32_long(group_name.data, group_name.len);
  group = (ngx_http_conf_def_data_group_t*)ngx_str_rbtree_lookup(&ngx_global_cdf->data_groups, &group_name, hash);
  return group;
}

static ngx_http_conf_def_data_file_kv_pair_t*
ngx_http_conf_def_get_group_kv_pair(ngx_http_conf_def_data_group_t* group, ngx_str_t data_file_nick_name)
{
  ngx_http_conf_def_data_file_kv_pair_t* kv_pair;
  uint32_t hash;

  hash    = ngx_crc32_long(data_file_nick_name.data, data_file_nick_name.len);
  kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)
               ngx_str_rbtree_lookup(&group->kv_pairs, &data_file_nick_name, hash);
  return kv_pair;
}

ngx_array_t* 
ngx_http_conf_def_get_group_ptr_array(ngx_str_t group_name)
{
  ngx_http_conf_def_data_group_t* group = ngx_http_conf_def_get_group(group_name);
  if(group != NULL){
     return &(group->addr_ptr_array); 
  }else{
     return NULL;
  }
}

static ngx_http_conf_def_data_file_kv_pair_t*
ngx_http_conf_def_get_data_file_kv_pair(ngx_array_t* group_ptr_array, size_t idx)
{
  char** data_ptrs = (char**)group_ptr_array->elts;
  char*  ptr       = *(data_ptrs + idx);
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair =
       (ngx_http_conf_def_data_file_kv_pair_t*)(ptr - offsetof(ngx_http_conf_def_data_file_kv_pair_t, shm_ptr));
  return kv_pair;
}

ngx_str_t    
ngx_http_conf_def_get_data_file_nickname(ngx_array_t* group_ptr_array, size_t idx)
{
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair = ngx_http_conf_def_get_data_file_kv_pair(group_ptr_array, idx);
  return kv_pair->nick_name;
}

u_char*      
ngx_http_conf_def_get_data_file_ptr(ngx_array_t* group_ptr_array, size_t idx)
{
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair = ngx_http_conf_def_get_data_file_kv_pair(group_ptr_array, idx);
  return (u_char*)kv_pair->shm_ptr; 
}

ngx_http_conf_def_data_file_kv_pair_t* 
ngx_http_conf_def_get_data_file_idx(ngx_str_t group_name, ngx_str_t data_file_nick_name, ngx_uint_t* idx)
{
  ngx_http_conf_def_data_group_t* group = ngx_http_conf_def_get_group(group_name);
  if(group == NULL)
    return NULL;
  
  ngx_http_conf_def_data_file_kv_pair_t* kv_pair = ngx_http_conf_def_get_group_kv_pair(group, data_file_nick_name);
  if(kv_pair != NULL){
    *idx  = kv_pair->addr_ptr_array_pos;
  }
  return kv_pair;
}
