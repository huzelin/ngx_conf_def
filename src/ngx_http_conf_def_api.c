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

size_t       
ngx_http_conf_def_get_data_file_size(ngx_array_t* group_ptr_array, size_t idx)
{
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair = ngx_http_conf_def_get_data_file_kv_pair(group_ptr_array, idx);
  return kv_pair->shm_size;
}

void* 
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

/// binary-data search algorithm
ngx_str_t 
ngx_http_conf_def_trie_match_longest(u_char *rkey, size_t ksize, u_char *rvalue, ngx_str_t query, size_t* match_len)
{
  ngx_str_t ret = ngx_null_string;
  if(rkey == NULL || rvalue == NULL || query.data == NULL || query.len == 0)
  {
    return ret;
  }
  ngx_conf_def_trie_node_t *punits = (ngx_conf_def_trie_node_t*)rkey;
  size_t unit_count = (ksize) / sizeof(ngx_conf_def_trie_node_t);

  if(unit_count == 0)
  {
    return ret;
  }
  ngx_int_t iPos = 1;
  ngx_int_t iMatchPos = iPos;
  *match_len = 0;
  size_t ui;

  for(ui = 0; ui < query.len; ++ui)
  {
    int32_t iRelative = (int32_t)(query.data[ui]);
    int32_t iNext = iPos + punits[iPos].ibase + iRelative;

    if(iNext <= 0 || (uint32_t)(iNext) >= unit_count)
    {
      break;
    }
    if(iNext + punits[iNext].iprev != iPos)
    {
      break;
    }
    iPos = iNext;
    if(punits[iPos].uvalue_len != 0)
    {
       *match_len  = ui + 1;
       iMatchPos   = iPos;
    }
  }
  if(*match_len > 0)
  {
     ret.data = rvalue + punits[iMatchPos].uvalue_pos;
     ret.len  = punits[iMatchPos].uvalue_len;        
     return ret;
  }
  return ret;  
}

ngx_uint_t
ngx_http_conf_def_trie_match_path(u_char *rkey, size_t ksize, u_char *rvalue, ngx_str_t query, ngx_array_t* hits)
{
  if(rkey == NULL || rvalue == NULL || query.data == NULL || query.len == 0 || hits == NULL)
  {
    return 0;
  }
  ngx_conf_def_trie_node_t *punits = (ngx_conf_def_trie_node_t*)rkey;
  size_t unit_count = (ksize) / sizeof(ngx_conf_def_trie_node_t);

  if(unit_count == 0)
  {
    return 0;
  }
  ngx_int_t iPos = 1;
  size_t ui;

  for(ui = 0; ui < query.len; ++ui)
  {
    int32_t iRelative = (int32_t)(query.data[ui]);
    int32_t iNext = iPos + punits[iPos].ibase + iRelative;

    if(iNext <= 0 || (uint32_t)(iNext) >= unit_count)
    {
       break;
    }
    if(iNext + punits[iNext].iprev != iPos)
    {
       break;
    }
    iPos = iNext;
    if(punits[iPos].uvalue_len != 0)
    {
      ngx_str_t* new_str = ngx_array_push(hits);
      new_str->data = rvalue + punits[iPos].uvalue_pos;
      new_str->len  = punits[iPos].uvalue_len;
    }
  }
  return hits->nelts;
}

ngx_uint_t 
ngx_http_conf_def_trie_match_all(u_char *rkey, size_t ksize, u_char *rvalue, ngx_str_t query, ngx_array_t* hits)
{
  if(rkey == NULL || rvalue == NULL || query.data == NULL || query.len == 0 || hits == NULL)
  {
    return 0;
  }
  size_t ui;
  for(ui = 0; ui < query.len; ++ui)
  {
    ngx_str_t sub_str, ret;
    size_t match_len;

    sub_str.data = query.data + ui;
    sub_str.len  = query.len - ui;
    ret = ngx_http_conf_def_trie_match_longest(rkey, ksize, rvalue, sub_str, &match_len);

    if(ret.data != NULL)
    {
       ngx_conf_def_trie_match_info_t *match_info = (ngx_conf_def_trie_match_info_t*)ngx_array_push(hits); 
       match_info->umatch_pos = ui;
       match_info->umatch_len = match_len;
       match_info->uvalue     = (const u_char *)ret.data;
       match_info->uvalue_len = ret.len;
       match_info->ioparg     = -1;
       
       ui += match_len;
    }
    else
    {
       ++ui;
    }
  }
  return hits->nelts;
}

static ngx_str_t suffix_key   = ngx_string(".key");
static ngx_str_t suffix_value = ngx_string(".value");

ngx_int_t  
ngx_http_conf_def_init_trie(ngx_conf_def_trie_t* trie, ngx_str_t group_name, ngx_str_t nick_name_key, ngx_str_t nick_name_value)
{
  trie->group_name = group_name;
  ngx_uint_t idx;

  trie->nick_name_key = nick_name_key;
  trie->kv_pair_rkey = ngx_http_conf_def_get_data_file_idx(group_name, trie->nick_name_key, &idx);

  trie->nick_name_value = nick_name_value;
  trie->kv_pair_rvalue = ngx_http_conf_def_get_data_file_idx(group_name, trie->nick_name_value, &idx); 
  return NGX_OK;
}

ngx_str_t  
ngx_http_conf_def_trie_stru_match_longest(ngx_conf_def_trie_t* trie, ngx_str_t query, size_t* match_len)
{
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair_rkey = trie->kv_pair_rkey;
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair_rvalue = trie->kv_pair_rvalue;

  return ngx_http_conf_def_trie_match_longest(kv_pair_rkey->shm_ptr, kv_pair_rkey->shm_size, kv_pair_rvalue->shm_ptr, query, match_len);  
}

ngx_uint_t 
ngx_http_conf_def_trie_stru_match_path(ngx_conf_def_trie_t* trie, ngx_str_t query, ngx_array_t* hits)
{
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair_rkey = trie->kv_pair_rkey;
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair_rvalue = trie->kv_pair_rvalue;

  return ngx_http_conf_def_trie_match_path(kv_pair_rkey->shm_ptr, kv_pair_rkey->shm_size, kv_pair_rvalue->shm_ptr, query, hits);
}

ngx_uint_t 
ngx_http_conf_def_trie_stru_match_all(ngx_conf_def_trie_t* trie, ngx_str_t query, ngx_array_t* hits)
{
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair_rkey = trie->kv_pair_rkey;
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair_rvalue = trie->kv_pair_rvalue;

  return ngx_http_conf_def_trie_match_all(kv_pair_rkey->shm_ptr, kv_pair_rkey->shm_size, kv_pair_rvalue->shm_ptr, query, hits);
}


