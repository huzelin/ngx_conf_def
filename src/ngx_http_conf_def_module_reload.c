#include "ngx_http_conf_def_module.h"
#include "ngx_http_conf_def_api.h"

extern ngx_module_t ngx_http_conf_def_module;
static ngx_int_t
ngx_http_conf_def_finalize_req(void* arg, ngx_str_t* response);

static void
ngx_http_conf_def_aio_write_event_handler(ngx_http_request_t *r)
{
   ngx_str_t response = ngx_string("ok");
   ngx_int_t ret = ngx_http_conf_def_finalize_req(r, &response);
   ngx_http_finalize_request(r, ret);
}

static void
ngx_http_conf_def_aio_handler(ngx_event_t *ev)
{
   ngx_event_aio_t     *aio;
   ngx_conf_def_aio_pack_t  *aio_pack;

   aio      = ev->data;
   aio_pack = aio->data;

   NGX_HTTP_CONF_DEF_AIO_FIN_PACK_DATA(aio_pack);
   aio_pack->r->aio = 0;

   if(aio_pack->r->main->blocked == 0){
     aio_pack->cdf->shm_large_version++;

     ngx_shmtx_lock(&aio_pack->cdf->shm_headers->mutex);
     aio_pack->cdf->shm_headers->shm_large_version++;
     ngx_shmtx_unlock(&aio_pack->cdf->shm_headers->mutex);

     ngx_http_conf_def_aio_write_event_handler(aio_pack->r);
   }
}

static ngx_int_t 
ngx_http_conf_def_reload_data_file_impl(ngx_pool_t* pool, 
                                        ngx_http_conf_def_t* cdf,
                                        ngx_rbtree_node_t* root, 
                                        ngx_rbtree_node_t* sentinel, 
                                        ngx_str_t* group_name, 
                                        ngx_int_t is_group, 
                                        ngx_int_t aio, 
                                        ngx_http_request_t *r)
{
  ngx_int_t r1,r2,r3;
  if(root == sentinel)
    return NGX_OK;

  r1 = r2 = r3 = NGX_OK;
  if(is_group){
    ngx_http_conf_def_data_group_t* group = (ngx_http_conf_def_data_group_t*)root;
    if( group_name->data == NULL ||
        (group->group_name.len == group_name->len &&
        ngx_strncmp(group->group_name.data, group_name->data, group_name->len) == 0) )
    {

      r1 = ngx_http_conf_def_reload_data_file_impl(pool, 
                                                   cdf, 
                                                   group->kv_pairs.root, 
                                                   group->kv_pairs.sentinel, 
                                                   group_name, 0, aio, r);        
    }else
      return NGX_OK; 
  }else{
    ngx_http_conf_def_data_file_kv_pair_t* kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)root;
    ngx_http_conf_def_shm_header_t* shm_header_ptr = cdf->shm_headers->headers + kv_pair->shm_header_pos;  

    if(ngx_http_conf_def_open_data_file(kv_pair) == NGX_ERROR) { /*** file corrupt ***/
      r1 = NGX_ERROR;
      goto Next;
    }
    size_t shm_size       = ngx_file_size(&kv_pair->file.info);
    int shm_id            = shmget(kv_pair->node.key, shm_size, (SHM_R|SHM_W|IPC_CREAT));
    void* shm_ptr;
    if(shm_id == -1){
      r1 = NGX_ERROR;
      goto Next;
    }
    shm_ptr               = shmat(shm_id, NULL, 0);
    if((void*)shm_ptr == (void*)-1){
      r1 = NGX_ERROR;
      goto Next;
    }
    if(shmctl(shm_id, IPC_RMID, NULL) == -1){
      r1 = NGX_ERROR;
      goto Next;
    }
    
    if(aio == 0){ /// not use aio operation
      if(ngx_read_file(&kv_pair->file, shm_ptr, shm_size, 0) == NGX_ERROR){
        r1 = NGX_ERROR;
        goto Next;
      }
      /// shmdt shm and change version-related info
      NGX_HTTP_CONF_DEF_FIN_PACK_DATA  
    }else{ /// can use aio operation
      kv_pair->file.log  = pool->log;
      kv_pair->file.aio  = NULL;
      r1 = ngx_file_aio_read(&kv_pair->file, shm_ptr, shm_size, 0, pool);
      switch(r1)
      {
        case NGX_ERROR:
          break;
        case NGX_AGAIN:
          {
            NGX_HTTP_CONF_DEF_AIO_PACK_DATA(pool, kv_pair, cdf, shm_header_ptr, shm_ptr, shm_size, shm_id, r);
#if (NGX_HAVE_FILE_AIO)
            kv_pair->file.aio->handler = ngx_http_conf_def_aio_handler;
            kv_pair->file.aio->data    = aio_pack; 
            r->aio  = 1;
#endif
          }
          break;
        default: //success
          {
            /// shmdt shm and change version-related info
            NGX_HTTP_CONF_DEF_FIN_PACK_DATA
            r1 = NGX_OK;
          }
          break; 
      }
    }
  }

Next:
  r2 = ngx_http_conf_def_reload_data_file_impl(pool, cdf, root->left,  sentinel, group_name, is_group, aio, r);
  r3 = ngx_http_conf_def_reload_data_file_impl(pool, cdf, root->right, sentinel, group_name, is_group, aio, r);

  if(r1 == NGX_AGAIN || r2 == NGX_AGAIN || r3 == NGX_AGAIN)
    return NGX_AGAIN;

  if(r1 == NGX_ERROR || r2 == NGX_ERROR || r3 == NGX_ERROR)
    return NGX_ERROR;

  return NGX_OK; 
}

ngx_int_t 
ngx_http_conf_def_reload_data_file(ngx_pool_t* pool, ngx_http_conf_def_t* cdf, ngx_str_t group_name, ngx_int_t aio, ngx_http_request_t *r)
{
  ngx_int_t rc = ngx_http_conf_def_reload_data_file_impl(pool, cdf, cdf->data_groups.root, 
                             cdf->data_groups.sentinel, &group_name, 1, aio, r);

  if(rc != NGX_AGAIN){
    cdf->shm_large_version++;
    ngx_shmtx_lock(&cdf->shm_headers->mutex);
    cdf->shm_headers->shm_large_version++;
    ngx_shmtx_unlock(&cdf->shm_headers->mutex); 
  }else{
     
  }

  return rc;
}

static ngx_int_t 
ngx_http_conf_def_attach_data_file_impl(ngx_http_conf_def_t* cdf,
ngx_rbtree_node_t* root, ngx_rbtree_node_t* sentinel, ngx_int_t is_group)
{
  ngx_int_t r1,r2,r3;
  if(root == sentinel)
    return NGX_OK;

  r1 = r2 = r3 = NGX_OK;
  if(is_group){
    ngx_http_conf_def_data_group_t* group = (ngx_http_conf_def_data_group_t*)root;
    r1 = ngx_http_conf_def_attach_data_file_impl(cdf, group->kv_pairs.root, group->kv_pairs.sentinel, 0);
  }else{
    ngx_http_conf_def_data_file_kv_pair_t* kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)root;
    ngx_http_conf_def_shm_header_t* shm_header_ptr = cdf->shm_headers->headers + kv_pair->shm_header_pos;  
    void *shm_ptr = NULL;
  
    ngx_shmtx_lock(&cdf->shm_headers->mutex);
    shm_ptr               = shmat(shm_header_ptr->shm_id, NULL, 0);
    if((void*)shm_ptr == (void*)-1){
      r1 = NGX_ERROR;
      ngx_shmtx_unlock(&cdf->shm_headers->mutex);
      goto Next;
    }

    if(kv_pair->shm_ptr != NULL && shmdt(kv_pair->shm_ptr) == -1){
      r1 = NGX_ERROR;
    }

    kv_pair->shm_ptr  = shm_ptr;
    kv_pair->shm_size = shm_header_ptr->shm_size;
    kv_pair->shm_version = shm_header_ptr->shm_version;
    ngx_shmtx_unlock(&cdf->shm_headers->mutex);
  }

Next:
  r2 = ngx_http_conf_def_attach_data_file_impl(cdf, root->left,  sentinel, is_group);
  r3 = ngx_http_conf_def_attach_data_file_impl(cdf, root->right, sentinel, is_group);

  if(r1 != NGX_OK || r2 != NGX_OK || r3 != NGX_OK)
    return NGX_ERROR;
  return NGX_OK; 
}

static ngx_int_t
ngx_http_conf_def_detach_data_file_impl(ngx_http_conf_def_t* cdf,
ngx_rbtree_node_t* root, ngx_rbtree_node_t* sentinel, ngx_int_t is_group)
{
  ngx_int_t r1,r2,r3;
  if(root == sentinel)
    return NGX_OK;

  r1 = r2 = r3 = NGX_OK;
  if(is_group){
    ngx_http_conf_def_data_group_t* group = (ngx_http_conf_def_data_group_t*)root;
    r1 = ngx_http_conf_def_detach_data_file_impl(cdf, group->kv_pairs.root, group->kv_pairs.sentinel, 0);
  }else{
    ngx_http_conf_def_data_file_kv_pair_t* kv_pair = (ngx_http_conf_def_data_file_kv_pair_t*)root;
    //ngx_http_conf_def_shm_header_t* shm_header_ptr = cdf->shm_headers->headers + kv_pair->shm_header_pos;
   
    if(kv_pair->shm_ptr != NULL && shmdt(kv_pair->shm_ptr) == -1){
      r1 = NGX_ERROR;
    }
  }

Next:
  r2 = ngx_http_conf_def_detach_data_file_impl(cdf, root->left,  sentinel, is_group);
  r3 = ngx_http_conf_def_detach_data_file_impl(cdf, root->right, sentinel, is_group);

  if(r1 != NGX_OK || r2 != NGX_OK || r3 != NGX_OK)
    return NGX_ERROR;
  return NGX_OK;
}

ngx_int_t 
ngx_http_conf_def_attach_data_file(ngx_http_conf_def_t* cdf)
{
  ngx_log_stderr(0, "is executing datach: %d %d", cdf->shm_large_version, cdf->shm_headers->shm_large_version);
 
  if(cdf->shm_large_version != cdf->shm_headers->shm_large_version){
    ngx_int_t r1 = ngx_http_conf_def_attach_data_file_impl(cdf, cdf->data_groups.root, cdf->data_groups.sentinel, 1);
    cdf->shm_large_version = cdf->shm_headers->shm_large_version;
    return r1;
  }
  return NGX_OK;
}

ngx_int_t 
ngx_http_conf_def_detach_data_file(ngx_http_conf_def_t* cdf)
{
  ngx_int_t r = ngx_http_conf_def_detach_data_file_impl(cdf, cdf->data_groups.root, cdf->data_groups.sentinel, 1);
  if(cdf->shm_headers != NULL && shmdt(cdf->shm_headers) == -1)
    r = NGX_ERROR; 
  return r;
}

static ngx_int_t
ngx_http_conf_def_reload_data_file_group_handler(ngx_http_request_t* r)
{
  ngx_http_conf_def_t * cdf = ngx_http_get_module_main_conf(r, ngx_http_conf_def_module);
  ngx_http_variable_value_t *vv = ngx_http_get_indexed_variable(r, cdf->index);
  ngx_str_t group_name = ngx_null_string; 
  ngx_str_t ret_ok = ngx_string("ok");
  ngx_str_t ret_fail = ngx_string("fail");
  ngx_int_t rc; 

  if(vv == NULL || vv->not_found || vv->len == 0){
  }else{
     group_name.data = vv->data;
     group_name.len  = vv->len;;
  }

  rc = ngx_http_discard_request_body(r);
  if(rc != NGX_OK)
    return rc;

  switch(ngx_http_conf_def_reload_data_file(r->pool, cdf, group_name, 1, r)){
    case NGX_OK:
      rc = ngx_http_conf_def_finalize_req(r, &ret_ok);
      break;

    case NGX_ERROR:
      rc = ngx_http_conf_def_finalize_req(r, &ret_fail); 
      break;

    case NGX_AGAIN:
      return NGX_AGAIN;
  }
  return rc;
}

static ngx_str_t ngx_http_conf_def_data_file_group_name = ngx_string("reload_data_file_group");
char* 
ngx_http_conf_def_reload_data_file_group(ngx_conf_t* cf, ngx_command_t* cmd, void* conf)
{
  ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_conf_def_reload_data_file_group_handler;
  
  ngx_http_conf_def_t * cdf = (ngx_http_conf_def_t*)conf;
  cdf->index = ngx_http_get_variable_index(cf, &ngx_http_conf_def_data_file_group_name);
  if(cdf->index == NGX_ERROR)
    return NGX_CONF_ERROR;
  return NGX_OK; 
}

static ngx_int_t 
ngx_http_conf_def_finalize_req(void* arg, ngx_str_t* response)
{
   ngx_http_request_t *r = (ngx_http_request_t*)arg;
   int body_len;
   ngx_buf_t *b;
   ngx_chain_t out;
   static ngx_str_t type = ngx_string("text/plain");
   ngx_int_t ret;

   b = ngx_create_temp_buf(r->pool, response->len);
   ngx_snprintf(b->pos, response->len, (char*)"%V", response);
   body_len = response->len;

   r->headers_out.content_length_n = body_len;
   b->last = b->pos + body_len;
   b->last_buf = 1;

   out.buf  = b;
   out.next = NULL;
   r->headers_out.content_type = type;
   r->headers_out.status = NGX_HTTP_OK;
   r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;
   
   ret = ngx_http_send_header(r);
   ret = ngx_http_output_filter(r, &out);

   return ret;
}