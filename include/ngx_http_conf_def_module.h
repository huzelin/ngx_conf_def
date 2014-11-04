#ifndef H_NGX_HTTP_CONF_DEF_MODULE_H
#define H_NGX_HTTP_CONF_DEF_MODULE_H

#include "ngx_config.h"
#include "ngx_core.h"
#include "ngx_http.h"

#include <sys/ipc.h>
#include <sys/shm.h>

typedef struct ngx_http_conf_def_item_s{
  ngx_rbtree_node_t  node;
  ngx_str_t          func_name;
  ngx_array_t        func_args;
  ngx_str_t          func_content;
}ngx_http_conf_def_item_t;

typedef struct ngx_http_conf_def_cfg_block_kv_pair_s{
  ngx_rbtree_node_t  node;
  ngx_str_t          key;
  ngx_array_t        value;
}ngx_http_conf_def_cfg_block_kv_pair_t;

typedef struct ngx_http_conf_def_cfg_block_s{
  ngx_rbtree_node_t  node;
  ngx_str_t          block_name;

  ngx_rbtree_t       kv_pairs;
  ngx_rbtree_node_t  sentinel;
}ngx_http_conf_def_cfg_block_t;

typedef struct ngx_http_conf_def_data_file_kv_pair_s{
  ngx_rbtree_node_t  node;
  ngx_str_t          nick_name;
  ngx_str_t          file_name;

  ngx_file_t         file;
  ngx_int_t          shm_header_pos;
  char*              shm_ptr;
  size_t             shm_size;      
  ngx_uint_t         shm_version;   

  ngx_uint_t         addr_ptr_array_pos;
}ngx_http_conf_def_data_file_kv_pair_t;

typedef struct ngx_http_conf_def_data_group_s{
  ngx_rbtree_node_t  node;
  ngx_str_t          group_name;
  ngx_str_t          data_path;

  ngx_rbtree_t       kv_pairs;
  ngx_rbtree_node_t  sentinel;

  ngx_array_t        addr_ptr_array;
}ngx_http_conf_def_data_group_t;

typedef struct ngx_http_conf_def_shm_header_s{
  int                shm_id;
  size_t             shm_size;
  ngx_uint_t         shm_version; 
}ngx_http_conf_def_shm_header_t;

typedef struct ngx_http_conf_def_shm_headers_s{
  ngx_shmtx_t       mutex;
  ngx_shmtx_sh_t    lock;
  size_t            header_shm_size;
  size_t            data_shm_size;
  ngx_uint_t        shm_large_version;
  ngx_http_conf_def_shm_header_t headers[0];
}ngx_http_conf_def_shm_headers_t;

typedef struct ngx_http_conf_def_s{
  ngx_rbtree_t       defs;

  ngx_rbtree_t       cfg_blocks;
  ngx_rbtree_node_t  sentinel;

  ngx_rbtree_t       data_groups;
  ngx_uint_t         shm_large_version;
  ngx_http_conf_def_data_group_t *curr_data_group;  

  ngx_http_conf_def_shm_headers_t *shm_headers;
  ngx_event_t        attach_event;
}ngx_http_conf_def_t;

typedef struct ngx_http_conf_def_loc_s{
  ngx_int_t          index;
}ngx_http_conf_def_loc_t;

extern char* ngx_http_conf_def(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
extern char* ngx_http_conf_def_use(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
extern char* ngx_http_conf_def_cfg_block(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

extern char* ngx_http_conf_def_echo_def(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
extern char* ngx_http_conf_def_echo_def_cfg(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

extern char* ngx_http_conf_def_data_file_group(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
extern char* ngx_http_conf_def_data_file_path(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);
extern char* ngx_http_conf_def_data_file(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

extern ngx_int_t 
ngx_http_conf_def_reload_data_file(ngx_pool_t* pool, ngx_http_conf_def_t* cdf, ngx_str_t group_name, ngx_int_t aio, ngx_http_request_t *r);
extern ngx_int_t ngx_http_conf_def_attach_data_file(ngx_http_conf_def_t* cdf);
extern ngx_int_t ngx_http_conf_def_detach_data_file(ngx_http_conf_def_t* cdf, ngx_int_t detach_flag);

extern char* ngx_http_conf_def_reload_data_file_group(ngx_conf_t* cf, ngx_command_t* cmd, void* conf);

typedef struct ngx_conf_def_aio_pack_s{
  ngx_http_conf_def_data_file_kv_pair_t* kv_pair;
  ngx_http_conf_def_t *cdf;
  ngx_http_conf_def_shm_header_t* shm_header_ptr;

  void* shm_ptr;
  size_t shm_size;
  int shm_id;

  ngx_http_request_t *r;
}ngx_conf_def_aio_pack_t;

#define NGX_HTTP_CONF_DEF_AIO_PACK_DATA(pool,kv_pair,cdf,shm_header_ptr,shm_ptr,shm_size,shm_id, r) \
ngx_conf_def_aio_pack_t* aio_pack = ngx_pcalloc(pool, sizeof(ngx_conf_def_aio_pack_t)); \
aio_pack->kv_pair = kv_pair; \
aio_pack->cdf = cdf; \
aio_pack->shm_header_ptr = shm_header_ptr; \
aio_pack->shm_ptr = shm_ptr; \
aio_pack->shm_size =shm_size; \
aio_pack->shm_id = shm_id; \
aio_pack->r  = r; \
r->main->blocked++;

#define NGX_HTTP_CONF_DEF_AIO_FIN_PACK_DATA(aio_pack) \
if(aio_pack->kv_pair->shm_ptr != NULL) \
shmdt(aio_pack->kv_pair->shm_ptr); \
aio_pack->kv_pair->shm_ptr = aio_pack->shm_ptr; \
aio_pack->kv_pair->shm_size = aio_pack->shm_size; \
ngx_shmtx_lock(&aio_pack->cdf->shm_headers->mutex); \
aio_pack->cdf->shm_headers->data_shm_size = aio_pack->cdf->shm_headers->data_shm_size + aio_pack->shm_size - aio_pack->shm_header_ptr->shm_size; \
aio_pack->shm_header_ptr->shm_size = aio_pack->shm_size; \
aio_pack->shm_header_ptr->shm_id = aio_pack->shm_id; \
aio_pack->shm_header_ptr->shm_version++; \
aio_pack->kv_pair->shm_version = aio_pack->shm_header_ptr->shm_version; \
ngx_shmtx_unlock(&aio_pack->cdf->shm_headers->mutex); \
ngx_http_conf_def_close_data_file(aio_pack->kv_pair); \
aio_pack->r->main->blocked--;

#define NGX_HTTP_CONF_DEF_FIN_PACK_DATA \
if(kv_pair->shm_ptr != NULL) \
shmdt(kv_pair->shm_ptr); \
kv_pair->shm_ptr    = shm_ptr; \
kv_pair->shm_size   = shm_size; \
ngx_shmtx_lock(&cdf->shm_headers->mutex); \
cdf->shm_headers->data_shm_size = cdf->shm_headers->data_shm_size + shm_size - shm_header_ptr->shm_size; \
shm_header_ptr->shm_size        = shm_size; \
shm_header_ptr->shm_id          = shm_id; \
shm_header_ptr->shm_version++; \
kv_pair->shm_version            = shm_header_ptr->shm_version; \
ngx_shmtx_unlock(&cdf->shm_headers->mutex); \
ngx_http_conf_def_close_data_file(kv_pair); 

#endif
