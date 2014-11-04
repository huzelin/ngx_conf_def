#include "ngx_http_conf_def_module.h"
#include "ngx_http_conf_def_api.h"

static void* ngx_http_conf_def_module_create_conf(ngx_conf_t* cf);
static void* ngx_http_conf_def_create_loc_conf(ngx_conf_t* cf);
static ngx_int_t ngx_http_conf_def_module_postconfiguration(ngx_conf_t* cf);
static ngx_int_t ngx_http_conf_def_init_module(ngx_cycle_t* cycle);
static ngx_int_t ngx_http_conf_def_init_process(ngx_cycle_t* cycle);
static void ngx_http_conf_def_exit_process(ngx_cycle_t* cycle);
static void ngx_http_conf_def_exit_master(ngx_cycle_t* cycle);
static ngx_int_t ngx_http_conf_def_init_master(ngx_cycle_t* cycle);

static ngx_command_t ngx_http_conf_def_commands[]={
  { ngx_string("def"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
    ngx_http_conf_def,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("use_def"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_conf_def_use,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("def_cfg_block"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
    ngx_http_conf_def_cfg_block,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("def_data_file_group"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
    ngx_http_conf_def_data_file_group,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("def_data_file_path"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_conf_def_data_file_path,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("def_data_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_http_conf_def_data_file,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("conf_def_reload_data_file_group"),
    NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
    ngx_http_conf_def_reload_data_file_group,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("echo_def"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_http_conf_def_echo_def,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL},
  { ngx_string("echo_def_cfg"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_http_conf_def_echo_def_cfg,
    NGX_HTTP_MAIN_CONF_OFFSET,
    0,
    NULL}, 
  ngx_null_command
};

static ngx_http_module_t ngx_http_conf_def_module_ctx = {
  NULL,
  ngx_http_conf_def_module_postconfiguration,
  ngx_http_conf_def_module_create_conf,
  NULL,  
  NULL,
  NULL,
  ngx_http_conf_def_create_loc_conf,
  NULL
};

ngx_module_t ngx_http_conf_def_module={
  NGX_MODULE_V1,
  &ngx_http_conf_def_module_ctx,
  ngx_http_conf_def_commands,
  NGX_HTTP_MODULE,
  NULL,    /*** init master  ****/
  ngx_http_conf_def_init_module,    /*** init module  ****/
  ngx_http_conf_def_init_process,   /*** init process ****/
  NULL,    
  NULL,
  ngx_http_conf_def_exit_process,   /*** exit process ****/ 
  ngx_http_conf_def_exit_master,    /*** exit master  ****/
  NGX_MODULE_V1_PADDING
};

ngx_http_conf_def_t* ngx_global_cdf              = NULL;
static ngx_int_t ngx_conf_def_master_detach_header_flag = 0;

static void*
ngx_http_conf_def_module_create_conf(ngx_conf_t* cf)
{
  ngx_http_conf_def_t* cdf = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_t));
  if(cdf == NULL)
    return NULL;

  if(ngx_global_cdf != NULL){ /// nginx -s reload
    if(ngx_conf_def_master_detach_header_flag){
      ngx_http_conf_def_detach_data_file(ngx_global_cdf, 0x02);
    }else{
      ngx_http_conf_def_detach_data_file(ngx_global_cdf, 0x03);
    }
    ngx_conf_def_master_detach_header_flag = 0;
  }
  ngx_global_cdf = cdf;

  ngx_rbtree_init(&(cdf->defs),        &(cdf->sentinel), ngx_str_rbtree_insert_value);
  ngx_rbtree_init(&(cdf->cfg_blocks),  &(cdf->sentinel), ngx_str_rbtree_insert_value);
  ngx_rbtree_init(&(cdf->data_groups), &(cdf->sentinel), ngx_str_rbtree_insert_value); 
  return cdf;
}

static void* 
ngx_http_conf_def_create_loc_conf(ngx_conf_t* cf)
{
  ngx_http_conf_def_loc_t *cdlf = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_def_loc_t));
  if(cdlf == NULL)
    return NULL;
  cdlf->index = -1;
  return cdlf;
}

static void
ngx_http_conf_def_get_data_file_cnt(ngx_rbtree_node_t* root, ngx_rbtree_node_t* sentinel, ngx_int_t is_group, size_t* cnt)
{
  if(root != sentinel){
    if(is_group){
       ngx_http_conf_def_data_group_t *group = (ngx_http_conf_def_data_group_t*)root;
       ngx_http_conf_def_get_data_file_cnt(group->kv_pairs.root, group->kv_pairs.sentinel, 0, cnt); 
    }else{
       ngx_http_conf_def_data_file_kv_pair_t *kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)root;
       kv_pair->shm_header_pos = *cnt;
       kv_pair->shm_version    = 1; 
       ++(*cnt);
    }
    ngx_http_conf_def_get_data_file_cnt(root->left,  sentinel, is_group, cnt);
    ngx_http_conf_def_get_data_file_cnt(root->right, sentinel, is_group, cnt);
  }  
}

static ngx_int_t 
ngx_http_conf_def_module_postconfiguration(ngx_conf_t* cf)
{
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)ngx_http_conf_get_module_main_conf(cf, ngx_http_conf_def_module);
  ngx_uint_t cnt  = 0;
  ngx_http_conf_def_get_data_file_cnt(cdf->data_groups.root, cdf->data_groups.sentinel, 1, &cnt);   

  size_t shm_size       = sizeof(ngx_http_conf_def_shm_headers_t) + sizeof(ngx_http_conf_def_shm_header_t) * cnt;

  int id                = shmget(IPC_PRIVATE, shm_size, (SHM_R|SHM_W|IPC_CREAT));
  if(id == -1){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "shmget(%uz) failed", shm_size);
    return NGX_ERROR;
  }  

  cdf->shm_headers     = (ngx_http_conf_def_shm_headers_t*)shmat(id, NULL, 0);
  if((void*)cdf->shm_headers == (void*)-1){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "shmat() failed");
    return NGX_ERROR;
  }

  if(shmctl(id, IPC_RMID, NULL) == -1){
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "shmctl(IPC_RMID) failed");
    return NGX_ERROR;
  }
  
  memset(cdf->shm_headers, 0, shm_size);
  cdf->shm_headers->header_shm_size   = shm_size;

  return NGX_OK;
}

static ngx_int_t 
ngx_http_conf_def_init_module(ngx_cycle_t* cycle)
{
  ngx_http_conf_def_t *cdf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_conf_def_module);
  ngx_str_t group_name = ngx_null_string;
  u_char* file;

#if (NGX_HAVE_ATOMIC_OPS)
  file = NULL;
#else
  file = ngx_pnalloc(cycle->pool, cycle->lock_file.len + sizeof(".conf_def"));
  if(file == NULL){
     return NGX_ERROR;
  }
  (void) ngx_sprintf(file, "%V.conf_def%Z", &cycle->lock_file);
#endif

  if(ngx_shmtx_create(&cdf->shm_headers->mutex, &cdf->shm_headers->lock, file) != NGX_OK)
    return NGX_ERROR;

  ngx_http_conf_def_reload_data_file(cycle->pool, cdf, group_name, 0, NULL); 
  cdf->shm_large_version = cdf->shm_headers->shm_large_version;
  
  return NGX_OK;
}

extern ngx_uint_t    ngx_exiting;

static void
ngx_http_conf_def_attach_data_file_timer(ngx_event_t* ev)
{
  ngx_http_conf_def_t* cdf = (ngx_http_conf_def_t*)ev->data;
  ngx_http_conf_def_attach_data_file(cdf);
  if(ngx_exiting != 1)
    ngx_add_timer(&cdf->attach_event, 1000);
}

static ngx_int_t 
ngx_http_conf_def_init_process(ngx_cycle_t* cycle)
{
  ngx_http_conf_def_t *cdf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_conf_def_module);

  cdf->attach_event.handler = ngx_http_conf_def_attach_data_file_timer;
  cdf->attach_event.log     = cycle->log;
  cdf->attach_event.data    = cdf;

  ngx_str_t group_name = ngx_null_string;
  ngx_http_conf_def_reload_data_file(cycle->pool, cdf, group_name, 0, NULL);
  ngx_add_timer(&cdf->attach_event, 1000);
  return NGX_OK;
}

static void 
ngx_http_conf_def_exit_process(ngx_cycle_t* cycle)
{
  ngx_http_conf_def_t *cdf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_conf_def_module);
  ngx_http_conf_def_detach_data_file(cdf, 0x03);  
}

static void 
ngx_http_conf_def_exit_master(ngx_cycle_t* cycle)
{
  ngx_http_conf_def_t *cdf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_conf_def_module);
  ngx_http_conf_def_detach_data_file(cdf, 0x02);
}

static ngx_int_t 
ngx_http_conf_def_init_master(ngx_cycle_t* cycle)
{
  ngx_http_conf_def_t *cdf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_conf_def_module);
  ngx_http_conf_def_detach_data_file(cdf, 0x01);
  ngx_conf_def_master_detach_header_flag =1;
}
