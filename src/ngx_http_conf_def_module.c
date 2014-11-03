#include "ngx_http_conf_def_module.h"
#include "ngx_http_conf_def_api.h"

static char* ngx_http_conf_def_parse(ngx_conf_t* cf, ngx_str_t str, ngx_str_t* func_name, ngx_array_t* func_args);
static ngx_int_t ngx_http_conf_def_get_index(ngx_str_t arg_name, ngx_array_t func_args);
static ngx_http_conf_def_item_t* ngx_http_conf_def_get_item(ngx_http_conf_def_t* cdf, ngx_str_t func_name);
static void ngx_http_conf_def_pack_replace(ngx_conf_t* cf, ngx_array_t contents, ngx_str_t* replace);
static char* ngx_http_conf_def_replace_content(ngx_conf_t* cf, ngx_http_conf_def_t* cdf,ngx_str_t func_content, ngx_array_t func_args, ngx_array_t func_real_args, ngx_str_t* replace);
static char* ngx_http_conf_def_replace(ngx_conf_t* cf, ngx_http_conf_def_t* cdf, ngx_str_t func_name, ngx_array_t func_args, ngx_str_t* replace);
static char* ngx_http_conf_def_cfg_block_item_handler(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

extern ngx_module_t ngx_http_conf_def_module;

static char*
ngx_http_conf_def_parse(ngx_conf_t* cf, ngx_str_t str, ngx_str_t* func_name, ngx_array_t* func_args)
{
  u_char *pos, *cur;
  size_t len;
  ngx_str_t *new_arg;

  pos = str.data;
  len = 0;

  /*** parse def name ****/
  while(len < str.len && *pos != '(' ){
    ++len;
    ++pos;
  }
  if(len == 0) return NGX_CONF_ERROR;
  
  func_name->data = str.data;
  func_name->len  = len;

  /*** parse def arg ***/
  ngx_array_init(func_args, cf->pool, 1, sizeof(ngx_str_t));
  if(*pos == '('){
    ++len;
    ++pos;
    cur = pos;
    while(len < str.len && *cur != ')'){
      if(*cur == ','){
        new_arg       = (ngx_str_t*)ngx_array_push(func_args);
        new_arg->data = pos;
        new_arg->len  = (cur - pos);
        ++len;
        ++cur;
        pos           = cur;
      }else{
        ++len;
        ++cur;
      }
    }
    new_arg           = ngx_array_push(func_args);
    new_arg->data     = pos;
    new_arg->len      = (cur - pos);

    if(*cur != ')')
      return NGX_CONF_ERROR;
  }  
  return NGX_CONF_OK;
}

char*
ngx_http_conf_def(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_conf_def_item_t *new_def_item;
  ngx_str_t func_name, *value;
  ngx_array_t func_args;  
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;

  value = cf->args->elts; 
  ngx_log_debug(NGX_LOG_DEBUG_CORE, cf->log, 0, "def %V %V", value + 1, value + 2); 

  if(NGX_CONF_ERROR == ngx_http_conf_def_parse(cf, value[1], &func_name, &func_args)){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "def %V %V format error", value + 1, value + 2);
    return NGX_CONF_ERROR;
  }

  if((new_def_item = ngx_http_conf_def_get_item(cdf, func_name)) == NULL){
    new_def_item = (ngx_http_conf_def_item_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_item_t));
    new_def_item->node.key = ngx_crc32_long(func_name.data, func_name.len);
    new_def_item->func_name = func_name;
    ngx_rbtree_insert(&cdf->defs, (ngx_rbtree_node_t*)new_def_item);
  }
 
  new_def_item->func_args    = func_args;
  new_def_item->func_content = value[2]; 
  return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_conf_def_get_index(ngx_str_t arg_name, ngx_array_t func_args)
{
   ngx_uint_t c = 0;
   for(; c < func_args.nelts; ++c){
      ngx_str_t *name = (ngx_str_t*)func_args.elts + c;
      if(name->len != arg_name.len)
        continue;
      if(ngx_strncmp(name->data, arg_name.data, arg_name.len) != 0)
        continue;
      return (ngx_int_t)c;
   }
   return -1;
}

static ngx_http_conf_def_item_t*
ngx_http_conf_def_get_item(ngx_http_conf_def_t* cdf, ngx_str_t func_name)
{
  uint32_t hash = ngx_crc32_long(func_name.data, func_name.len);
  return (ngx_http_conf_def_item_t*)ngx_str_rbtree_lookup(&cdf->defs, &func_name, hash);
}

static void 
ngx_http_conf_def_pack_replace(ngx_conf_t* cf, ngx_array_t contents, ngx_str_t* replace)
{
  size_t total_len = 0;
  ngx_uint_t c = 0;
  u_char* pos;
  for(; c < contents.nelts; ++c){
    ngx_str_t *cur = (ngx_str_t*)(contents.elts) + c;
    total_len      += cur->len;
  }
  replace->data = ngx_pcalloc(cf->temp_pool, total_len);
  replace->len  = total_len;
  pos           = replace->data;
  for(c = 0; c < contents.nelts; ++c){
    ngx_str_t *cur = (ngx_str_t*)(contents.elts) + c;
    pos            = ngx_cpymem(pos, cur->data, cur->len);
  }
}

static char*
ngx_http_conf_def_replace_content(ngx_conf_t* cf, ngx_http_conf_def_t* cdf,
                                  ngx_str_t func_content, ngx_array_t func_args, ngx_array_t func_real_args, ngx_str_t* replace)
{
  u_char *pos, *forward;
  ngx_array_t  contents;
  ngx_str_t *new_content, tmp_content;
  size_t len = 0, forward_len;
  ngx_int_t index = -1;

  ngx_array_init(&contents, cf->temp_pool, 1, sizeof(ngx_str_t));
  tmp_content.data = func_content.data;
  tmp_content.len  = 0;

  pos              = func_content.data;

  for(;len < func_content.len;)
  {
    if(*pos == '$') /// replace args
    {
       ngx_int_t ok = 0;
       forward     = pos + 1;
       forward_len = len + 1;

       if(forward_len < func_content.len && *forward == '{')
       {
         while(forward_len < func_content.len)
         {
           if(*forward == '}')
           {
             if(tmp_content.len != 0){
                new_content  = (ngx_str_t*)ngx_array_push(&contents);
                *new_content = tmp_content;
             }
             tmp_content.data = pos + 2;
             tmp_content.len  = forward - pos - 2;
             if(tmp_content.len == 0)
               return NGX_CONF_ERROR;
             index = ngx_http_conf_def_get_index(tmp_content, func_args);
             if(index == -1)
               return NGX_CONF_ERROR;
             new_content      = (ngx_str_t*)ngx_array_push(&contents);
             *new_content     = *((ngx_str_t*)func_real_args.elts + index);

             tmp_content.len  = 0;
             tmp_content.data = forward + 1;

             len              = forward_len + 1;
             pos              = forward + 1;
             ok               = 1;
             break;
           }
           ++forward_len;
           ++forward;
         }
         if(ok == 1)
           continue;
      }
    }
    else if(*pos == '@')  /// replace def
    {
      ngx_int_t ok = 0;
      forward      = pos + 1;
      forward_len  = len + 1;

      if(forward_len < func_content.len && *forward == '{')
      {
         ngx_int_t branch = 0;
         while(forward_len < func_content.len)
         {
           if(*forward == '{')
           {
             ++branch;
           }else if(*forward == '}' && --branch == 0)
           {
             ngx_str_t   sub_func_name;
             ngx_array_t sub_func_args;
             ngx_str_t   sub_replace = ngx_null_string;
             ngx_str_t   sub_sub_replace = ngx_null_string;

             if(tmp_content.len != 0){
               new_content  = (ngx_str_t*)ngx_array_push(&contents);
               *new_content = tmp_content;
             }
             tmp_content.data        = pos + 2;
             tmp_content.len         = forward - pos - 2;

             if( NGX_CONF_ERROR == ngx_http_conf_def_parse(cf, tmp_content, &sub_func_name, &sub_func_args) )
               return NGX_CONF_ERROR;

             if(NGX_CONF_ERROR == ngx_http_conf_def_replace(cf, cdf, sub_func_name, sub_func_args, &sub_replace))
               return NGX_CONF_ERROR;

             if(NGX_CONF_ERROR == ngx_http_conf_def_replace_content(cf, cdf, sub_replace, func_args, func_real_args, &sub_sub_replace))
                return NGX_CONF_ERROR;

             new_content      = (ngx_str_t*)ngx_array_push(&contents);
             *new_content     = sub_sub_replace;

             tmp_content.len  = 0;
             tmp_content.data = forward + 1;

             len              = forward_len + 1;
             pos              = forward + 1;
             ok = 1;
             break;
           }
           ++forward_len;
           ++forward;
         }
      }
      if(ok == 1)
        continue;
    }
    ++len;
    ++pos;
    ++(tmp_content.len);
  }
  if(tmp_content.len != 0){
     new_content  = (ngx_str_t*)ngx_array_push(&contents);
     *new_content = tmp_content;
  }
  ngx_http_conf_def_pack_replace(cf, contents, replace);

  return NGX_CONF_OK;
}

static char*
ngx_http_conf_def_replace(ngx_conf_t* cf, ngx_http_conf_def_t* cdf, ngx_str_t func_name, ngx_array_t func_args, ngx_str_t* replace)
{
  ngx_http_conf_def_item_t* find = NULL;

  if((find = ngx_http_conf_def_get_item(cdf, func_name)) == NULL)
    return NGX_CONF_ERROR;

  ngx_http_conf_def_replace_content(cf, cdf, find->func_content, find->func_args, func_args, replace);

  return NGX_CONF_OK;
}

char*
ngx_http_conf_def_use(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_str_t func_name, *value;
  ngx_array_t func_args;
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;
  ngx_conf_t cf_back;  
  ngx_str_t replace = ngx_null_string;

  value = cf->args->elts;
  ngx_log_debug(NGX_LOG_DEBUG_CORE, cf->log, 0, "def_use %V", value + 1);

  if(NGX_CONF_ERROR == ngx_http_conf_def_parse(cf, value[1], &func_name, &func_args)){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"def_use %V format error", value + 1);
    return NGX_CONF_ERROR;
  }

  if(NGX_CONF_ERROR == ngx_http_conf_def_replace(cf, cdf, func_name, func_args, &replace)){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"def_use %V replace error", value + 1);
    return NGX_CONF_ERROR;
  }

  ngx_log_debug(NGX_LOG_DEBUG_CORE, cf->log, 0, "def_use: %V", &replace);

  if(replace.len > 0)
  {
    ngx_str_t tmp_file = ngx_string(".defs");
    FILE* fp = fopen(".defs", "w");
    if(fp == NULL)
      return NGX_CONF_ERROR;
    fwrite(replace.data, 1, replace.len, fp);
    fclose(fp);

    cf_back = *cf;
    if( NGX_CONF_ERROR == ngx_conf_parse(cf, &tmp_file) )
      return NGX_CONF_ERROR;
    *cf     = cf_back;
  }
 
  return NGX_CONF_OK;
}

char* 
ngx_http_conf_def_cfg_block(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;
  ngx_str_t *block_name = (ngx_str_t*)cf->args->elts + 1;
  ngx_conf_t cf_back;
  char* rv;
  uint32_t hash;
  ngx_http_conf_def_cfg_block_t* new_cfg_block;
  hash = ngx_crc32_long(block_name->data, block_name->len);

  new_cfg_block = (ngx_http_conf_def_cfg_block_t*)ngx_str_rbtree_lookup(&cdf->cfg_blocks, block_name, hash);
  if(new_cfg_block == NULL){
     new_cfg_block = (ngx_http_conf_def_cfg_block_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_cfg_block_t)); 
 
     new_cfg_block->node.key = hash;
     new_cfg_block->block_name = *block_name;
     ngx_rbtree_init(&(new_cfg_block->kv_pairs), &(new_cfg_block->sentinel), ngx_str_rbtree_insert_value);
     ngx_rbtree_insert(&cdf->cfg_blocks, (ngx_rbtree_node_t*)new_cfg_block);  
  }else{
     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V define duplicated", block_name);
     return NGX_CONF_ERROR;
  }

  cf_back          = *cf;
  cf->handler      = ngx_http_conf_def_cfg_block_item_handler; 
  cf->handler_conf = (char*)new_cfg_block;
  rv = ngx_conf_parse(cf, NULL);
  *cf      = cf_back;

  return rv;
}

static char* 
ngx_http_conf_def_cfg_block_item_handler(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_conf_def_cfg_block_t* cur_cfg_block = (ngx_http_conf_def_cfg_block_t*)conf;
  ngx_str_t* value = cf->args->elts; 
  ngx_http_conf_def_cfg_block_kv_pair_t *kv_pair; 
  size_t c;

  if(cf->args->nelts <= 1){
     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%V cfg error", value);
     return NGX_CONF_ERROR;
  }

  kv_pair = (ngx_http_conf_def_cfg_block_kv_pair_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_cfg_block_kv_pair_t));
  kv_pair->node.key = ngx_crc32_long(value[0].data, value[0].len);
  kv_pair->key      = value[0];
  ngx_array_init(&kv_pair->value, cf->pool, 1, sizeof(ngx_str_t));
  for(c = 1; c < cf->args->nelts; ++c){
     ngx_str_t *new_value_item = (ngx_str_t*)ngx_array_push(&kv_pair->value);
     *new_value_item = value[c];
  }
  ngx_rbtree_insert(&cur_cfg_block->kv_pairs, (ngx_rbtree_node_t*)kv_pair); 
 
  return NGX_CONF_OK;
}

char* 
ngx_http_conf_def_echo_def(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_str_t func_name, *value;
  ngx_array_t func_args;
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;
  ngx_str_t replace = ngx_null_string;

  value = cf->args->elts;

  if(NGX_CONF_ERROR == ngx_http_conf_def_parse(cf, value[1], &func_name, &func_args)){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"echo_def %V format error", value + 1);
    return NGX_CONF_ERROR;
  }

  if(NGX_CONF_ERROR == ngx_http_conf_def_replace(cf, cdf, func_name, func_args, &replace)){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"echo_def %V replace error", value + 1);
    return NGX_CONF_ERROR;
  }  

  ngx_log_stderr(0, "-------%V [begin]-------", value + 1);
  ngx_log_stderr(0, "%V", &replace);
  ngx_log_stderr(0, "-------%V [end  ]-------", value + 1);

  return NGX_CONF_OK;  
}

char* 
ngx_http_conf_def_echo_def_cfg(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_str_t *value;
  value = cf->args->elts;

  ngx_str_t ret = ngx_http_conf_def_get_string(value[1], value[2]);
  ngx_log_stderr(0, "-------%V:%V [begin]-------", value + 1, value + 2);
  ngx_log_stderr(0, "%V", &ret);
  ngx_log_stderr(0, "-------%V:%V [end  ]-------", value + 1, value + 2);

  return NGX_CONF_OK;
}

ngx_int_t
ngx_http_conf_def_open_data_file(ngx_http_conf_def_data_file_kv_pair_t* kv_pair)
{
  kv_pair->file.fd = ngx_open_file(kv_pair->file.name.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
  if(kv_pair->file.fd == NGX_INVALID_FILE){
    return NGX_ERROR;
  }
  if(ngx_fd_info(kv_pair->file.fd, &kv_pair->file.info) == NGX_FILE_ERROR){
    return NGX_ERROR;
  }
  return NGX_OK;
}

ngx_int_t
ngx_http_conf_def_close_data_file(ngx_http_conf_def_data_file_kv_pair_t* kv_pair)
{
  if(ngx_close_file(kv_pair->file.fd) == NGX_FILE_ERROR){
    return NGX_ERROR;
  }
  return NGX_OK;
}

char*
ngx_http_conf_def_data_file_group_get_full_name(ngx_rbtree_node_t* root, ngx_rbtree_node_t* sentinel, ngx_str_t* path, ngx_conf_t* cf)
{
  if(root != sentinel){
     ngx_http_conf_def_data_file_kv_pair_t* kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)root;

     if(kv_pair->file_name.len == 0){
       ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,"data_file must not be empty");
       return NGX_CONF_ERROR;
     }

     if(kv_pair->file_name.data[0] == '/'){
        kv_pair->file.name.data = ngx_pcalloc(cf->pool, kv_pair->file_name.len + 1);
        kv_pair->file.name.len  = kv_pair->file_name.len + 1;
        ngx_memcpy(kv_pair->file.name.data, kv_pair->file_name.data, kv_pair->file_name.len);
     }else{
        if(path->len == 0 || path->data[path->len - 1] != '/'){
           ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "data_file_path must not be empty and endwith /");
           return NGX_CONF_ERROR;  
        }
        kv_pair->file.name.data = ngx_pcalloc(cf->pool, kv_pair->file_name.len + path->len + 1);         
        kv_pair->file.name.len  = kv_pair->file_name.len + path->len;

        ngx_memcpy(kv_pair->file.name.data, path->data, path->len);
        ngx_memcpy(kv_pair->file.name.data + path->len, kv_pair->file_name.data, kv_pair->file_name.len);
     }

     if(ngx_http_conf_def_open_data_file(kv_pair) != NGX_OK){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_open_file %s failed", kv_pair->file.name.data);
        return NGX_CONF_ERROR;
     }
    
     if(ngx_http_conf_def_close_data_file(kv_pair) != NGX_OK){
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "ngx_close_file %s failed", kv_pair->file.name.data);
        return NGX_CONF_ERROR;
     } 
    
     ngx_http_conf_def_data_file_group_get_full_name(root->left,  sentinel, path, cf);
     ngx_http_conf_def_data_file_group_get_full_name(root->right, sentinel, path, cf);
  } 
  return NGX_CONF_OK;
}

char*
ngx_http_conf_def_data_file_group(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_str_t* value = cf->args->elts;
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;
  ngx_http_conf_def_data_group_t* new_data_group;
  uint32_t hash;
  char* rv;
  
  hash = ngx_crc32_long(value[1].data, value[1].len);
  new_data_group = (ngx_http_conf_def_data_group_t*)ngx_str_rbtree_lookup(&cdf->data_groups, value + 1, hash);

  if(new_data_group == NULL){
     new_data_group = (ngx_http_conf_def_data_group_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_data_group_t));

     new_data_group->node.key = hash;
     new_data_group->group_name = value[1];
     new_data_group->data_path.data = ".";
     new_data_group->data_path.len = sizeof(".");
     ngx_rbtree_init(&(new_data_group->kv_pairs), &(new_data_group->sentinel), ngx_str_rbtree_insert_value);
     ngx_rbtree_insert(&cdf->data_groups, (ngx_rbtree_node_t*)new_data_group);
  }else{
     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "data group %V define duplicated", value + 1);
     return NGX_CONF_ERROR;
  }
  cdf->curr_data_group = new_data_group;
  ngx_array_init(&new_data_group->addr_ptr_array, cf->pool, 1, sizeof(void*));

  ngx_conf_t cf_back = *cf;
  rv                 = ngx_conf_parse(cf, NULL);
  if( NGX_CONF_ERROR == ngx_http_conf_def_data_file_group_get_full_name(cdf->curr_data_group->kv_pairs.root, 
                                         cdf->curr_data_group->kv_pairs.sentinel, &cdf->curr_data_group->data_path, cf))
    return NGX_CONF_ERROR;
  *cf                = cf_back;  

  return rv;
}

char*
ngx_http_conf_def_data_file_path(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_str_t* value = cf->args->elts;
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;
  ngx_http_conf_def_data_group_t* curr_data_group = cdf->curr_data_group;

  if(curr_data_group == NULL){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "current data file group is null");
    return NGX_CONF_ERROR;
  }  
  curr_data_group->data_path = value[1];
  
  return NGX_CONF_OK;
}

char* 
ngx_http_conf_def_data_file(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_str_t* value = cf->args->elts;
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)conf;
  ngx_http_conf_def_data_group_t* curr_data_group = cdf->curr_data_group;
  uint32_t hash;
  ngx_http_conf_def_data_file_kv_pair_t *kv_pair; 

  if(curr_data_group == NULL){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "current data file group is null");
    return NGX_CONF_ERROR;
  }

  hash = ngx_crc32_long(value[1].data, value[1].len);
  kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)ngx_str_rbtree_lookup(&curr_data_group->kv_pairs, value + 1, hash);
  if(kv_pair == NULL){
     kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_data_file_kv_pair_t));
     kv_pair->node.key    = hash;
     kv_pair->nick_name   = value[1];
     kv_pair->file_name   = value[2];
     ngx_rbtree_insert(&curr_data_group->kv_pairs, (ngx_rbtree_node_t*)kv_pair);

     kv_pair->addr_ptr_array_pos = curr_data_group->addr_ptr_array.nelts;
     void** addr_ptr = (void**)ngx_array_push(&curr_data_group->addr_ptr_array);
     *addr_ptr            = &(kv_pair->shm_ptr);
  }else{ 
     ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "current data file: %V is define in group: %V", value + 1, &curr_data_group->group_name);
     return NGX_CONF_ERROR;
  }
 
  return NGX_CONF_OK;
}

