
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) nglua.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
	ngx_hash_t                hash;
    ngx_hash_keys_arrays_t    acts;
	ngx_array_t   			  upstreams; 
								/* ngx_http_upstream_srv_conf_t * */
} ngx_http_fly_main_conf_t;


typedef struct {
	ngx_flag_t	  			  enable;
} ngx_http_fly_loc_conf_t;


typedef struct {
    ngx_str_t                  name;
    ngx_uint_t                 index;
    unsigned                   required:1;
} ngx_http_act_param_t;


typedef ngx_buf_t *(*ngx_http_act_pt) (ngx_http_request_t *r, 
	ngx_str_t *params);

typedef struct {
    ngx_str_t                 name;
    ngx_http_act_pt   	  	  handler;
    ngx_http_act_param_t  	 *params;
} ngx_http_act_t;


static ngx_buf_t *ngx_http_act_main(ngx_http_request_t *r);
static ngx_buf_t *ngx_http_act_list(ngx_http_request_t *r, 
	ngx_str_t *params);
static ngx_buf_t *ngx_http_act_show(ngx_http_request_t *r,
	ngx_str_t *params);
static ngx_buf_t *ngx_http_act_add(ngx_http_request_t *r,
	ngx_str_t *params);
static ngx_buf_t *ngx_http_act_update(ngx_http_request_t *r,
	ngx_str_t *params);
static ngx_buf_t *ngx_http_act_delete(ngx_http_request_t *r,
	ngx_str_t *params);


static ngx_http_upstream_srv_conf_t *ngx_http_find_upstream(
	ngx_http_request_t *r, ngx_str_t *backend);
static ngx_http_upstream_rr_peer_t *ngx_http_find_peer(
	ngx_http_upstream_rr_peers_t *peers, ngx_str_t *address, ngx_flag_t *backup);
static void ngx_http_delete_peer(ngx_http_upstream_rr_peers_t *peers,
	ngx_http_upstream_rr_peer_t *selected, ngx_flag_t backup);

static size_t ngx_http_peer_len(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peer_t *peer, ngx_flag_t backup);
static void ngx_http_peer_data(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peer_t *peer, ngx_buf_t *b, ngx_flag_t backup);
static size_t ngx_http_peers_len(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peers_t *peers, ngx_flag_t backup);
static void ngx_http_peers_data(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peers_t *peers, ngx_buf_t *b, ngx_flag_t backup);
static ngx_buf_t *ngx_http_buf_ok(ngx_http_request_t *r);
static ngx_int_t ngx_http_send_act_response(ngx_http_request_t *r, ngx_buf_t *b);

static ngx_int_t ngx_http_parse_act_params(ngx_http_request_t *r, 
	ngx_str_t *params, ngx_http_upstream_srv_conf_t *us, ngx_int_t *weight, 
	ngx_int_t *max_fails, time_t *fail_timeout, ngx_flag_t *backup, 
	ngx_flag_t *down);

static ngx_int_t ngx_http_fly_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_fly_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_fly_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_fly_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_fly_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_fly_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_fly(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_http_fly_commands[] = {

    { ngx_string("fly"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_fly,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_fly_loc_conf_t, enable),
      NULL },

    ngx_null_command
};


static ngx_http_module_t ngx_http_fly_module_ctx = {
    ngx_http_fly_preconfiguration,     /* preconfiguration */
    ngx_http_fly_postconfiguration,    /* postconfiguration */

    ngx_http_fly_create_main_conf,     /* create main configuration */
    ngx_http_fly_init_main_conf,       /* init main configuration */

    NULL,                              /* create server configuration */
    NULL,                              /* merge server configuration */

    ngx_http_fly_create_loc_conf,      /* create location configuration */
    ngx_http_fly_merge_loc_conf        /* merge location configuration */
};


ngx_module_t ngx_http_fly_module = {
    NGX_MODULE_V1,
    &ngx_http_fly_module_ctx,	       /* module context */
    ngx_http_fly_commands,   		   /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


#define  NGX_HTTP_PARAM_UPS  			0
#define  NGX_HTTP_PARAM_ADDR    		1
#define  NGX_HTTP_PARAM_BACKUP     		2
#define  NGX_HTTP_PARAM_STATUS     		3
#define  NGX_HTTP_PARAM_WEIGHT    		4
#define  NGX_HTTP_PARAM_MAX_FAILS    	5
#define  NGX_HTTP_PARAM_FAIL_TIMEOUT    6


static ngx_http_act_param_t  ngx_http_act_list_params[] = {
    { ngx_string("arg_ups"), NGX_HTTP_PARAM_UPS, 1 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_act_param_t  ngx_http_act_add_params[] = {
    { ngx_string("arg_ups"), NGX_HTTP_PARAM_UPS, 1 },
    { ngx_string("arg_addr"), NGX_HTTP_PARAM_ADDR, 1 },
    { ngx_string("arg_backup"), NGX_HTTP_PARAM_BACKUP, 0 },
    { ngx_string("arg_status"), NGX_HTTP_PARAM_STATUS, 0 },
    { ngx_string("arg_weight"), NGX_HTTP_PARAM_WEIGHT, 0 },
    { ngx_string("arg_max_fails"), NGX_HTTP_PARAM_MAX_FAILS, 0 },
    { ngx_string("arg_fail_timeout"), NGX_HTTP_PARAM_FAIL_TIMEOUT, 0 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_act_param_t  ngx_http_act_show_params[] = {
    { ngx_string("arg_ups"), NGX_HTTP_PARAM_UPS, 1 },
    { ngx_string("arg_addr"), NGX_HTTP_PARAM_ADDR, 1 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_act_param_t  ngx_http_act_update_params[] = {
    { ngx_string("arg_ups"), NGX_HTTP_PARAM_UPS, 1 },
    { ngx_string("arg_addr"), NGX_HTTP_PARAM_ADDR, 1 },
    { ngx_string("arg_backup"), NGX_HTTP_PARAM_BACKUP, 0 },
    { ngx_string("arg_status"), NGX_HTTP_PARAM_STATUS, 0 },
    { ngx_string("arg_weight"), NGX_HTTP_PARAM_WEIGHT, 0 },
    { ngx_string("arg_max_fails"), NGX_HTTP_PARAM_MAX_FAILS, 0 },
    { ngx_string("arg_fail_timeout"), NGX_HTTP_PARAM_FAIL_TIMEOUT, 0 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_act_param_t  ngx_http_act_delete_params[] = {
    { ngx_string("arg_ups"), NGX_HTTP_PARAM_UPS, 1 },
    { ngx_string("arg_addr"), NGX_HTTP_PARAM_ADDR, 1 },
    { ngx_null_string, 0, 0 }
};


static ngx_http_act_t  ngx_http_fly_acts[] = {

    { ngx_string("list"), 
	  ngx_http_act_list, 
	  ngx_http_act_list_params },

    { ngx_string("show"), 
	  ngx_http_act_show, 
	  ngx_http_act_show_params },

    { ngx_string("add"), 
	  ngx_http_act_add, 
	  ngx_http_act_add_params },

    { ngx_string("update"), 
	  ngx_http_act_update, 
	  ngx_http_act_update_params },

    { ngx_string("delete"), 
	  ngx_http_act_delete, 
	  ngx_http_act_delete_params },

    { ngx_null_string, NULL, NULL}
};


static u_char ngx_http_act_header[] =
"<html>" CRLF
"<head>" CRLF
"<title>nginx upstream web admin</title>" CRLF
"<link rel=\"stylesheet\" type=\"text/css\" href=\"/assets/fly.css\">" CRLF
"<script src=\"/assets/jquery-1.11.3.min.js\"></script>" CRLF
"<script src=\"/assets/fly.js\"></script>" CRLF
"</head>" CRLF
"<body>" CRLF
;


static u_char ngx_http_act_tail[] =
"</body>" CRLF
"</html>" CRLF
;


static ngx_int_t
ngx_http_fly_handler(ngx_http_request_t *r)
{
	ngx_uint_t							i;
    ngx_buf_t   			   	   	   *b;
	ngx_int_t                   		key;
    ngx_str_t                  		    var;
	ngx_str_t                 		    params[10];
    ngx_http_variable_value_t      	   *vv;
	ngx_http_act_t	   			   	   *act;
	ngx_http_act_param_t	   		   *prm;
	ngx_http_fly_loc_conf_t  		   *flcf;
	ngx_http_fly_main_conf_t 		   *fmcf;

	flcf = ngx_http_get_module_loc_conf(r, ngx_http_fly_module);
	fmcf = ngx_http_get_module_main_conf(r, ngx_http_fly_module);

    if (!flcf->enable) {
        return NGX_DECLINED;
    }

	ngx_str_set(&var, "arg_act");

	key = ngx_hash_key(var.data, var.len);

	vv = ngx_http_get_variable(r, &var, key);

	if (vv == NULL || vv->not_found || vv->len == 0) {
		b = ngx_http_act_main(r);

    } else {
		key = ngx_hash_key(vv->data, vv->len);

		act = ngx_hash_find(&fmcf->hash, key, vv->data, vv->len);
		if (act == NULL) {
			return NGX_HTTP_NOT_FOUND;
		}

		for (prm = act->params, i = 0; prm->name.len; prm++, i++) {
			key = ngx_hash_key(prm->name.data, prm->name.len);

			vv = ngx_http_get_variable(r, &prm->name, key);

			if (vv == NULL || vv->not_found || vv->len == 0) {
				params[i].data = NULL;
				params[i].len = 0;

			} else {
				params[i].data = vv->data;
				params[i].len = vv->len;
			}

			if (prm->required) {
				if (params[i].data == NULL) {
					ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
								  "required \"%V\" param is absent "
								  "in \"%V\" fly act",
								  &prm->name, &act->name);

					return NGX_HTTP_NOT_FOUND;
				}
			}
		}

		b = act->handler(r, params);
	}

    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return ngx_http_send_act_response(r, b);
}


static ngx_buf_t *
ngx_http_act_main(ngx_http_request_t *r)
{
	size_t             		    		size;
    ngx_uint_t    						i, n;
    ngx_buf_t   			   	   	   *b;
	ngx_http_fly_main_conf_t 		   *fmcf;
	ngx_http_upstream_main_conf_t  	   *umcf;
	ngx_http_upstream_srv_conf_t  	  **uscfp, *us;
	ngx_http_upstream_rr_peers_t       *peers;

	fmcf = ngx_http_get_module_main_conf(r, ngx_http_fly_module);
	umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

	uscfp = fmcf->upstreams.elts; 

	n = fmcf->upstreams.nelts;

	size = sizeof("<h3>Nginx upstreams (") - 1 + NGX_ATOMIC_T_LEN;
	size += sizeof(")</h3>" CRLF) - 1;

	for (i = 0; i < fmcf->upstreams.nelts; i++) {
		us = uscfp[i];

		size += sizeof("<div class='item'>" CRLF) - 1;

		size += sizeof("<h4>") - 1;

		size += us->host.len;

		size += sizeof("</h4>" CRLF) - 1;

		size += sizeof("\"<table>" CRLF) - 1;

		peers = us->peer.data;

		size += ngx_http_peers_len(r, peers, 0);

		size += sizeof("</table>" CRLF) - 1;

		size += sizeof("</div>" CRLF) - 1;
    }

	b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NULL;
    }

	b->last = ngx_cpymem(b->last, "<h3>Nginx upstreams (", 
							sizeof("<h3>Nginx upstreams (") - 1);

    b->last = ngx_sprintf(b->last, "%uA", n);

	b->last = ngx_cpymem(b->last, ")</h3>" CRLF, sizeof(")</h3>" CRLF) - 1);

	for (i = 0; i < fmcf->upstreams.nelts; i++) {
		us = uscfp[i];

		b->last = ngx_cpymem(b->last, "<div class='item'>" CRLF, 
								sizeof("<div class='item'>" CRLF) - 1);

		b->last = ngx_cpymem(b->last, "<h4>", sizeof("<h4>") - 1);

		b->last = ngx_cpymem(b->last, us->host.data, us->host.len);

		b->last = ngx_cpymem(b->last, "</h4>" CRLF, sizeof("</h4>" CRLF) - 1);

		b->last = ngx_cpymem(b->last, "<table>" CRLF, sizeof("<table>" CRLF) - 1);

		peers = us->peer.data;

		ngx_http_peers_data(r, peers, b, 0);

		b->last = ngx_cpymem(b->last, "</table>" CRLF, sizeof("</table>" CRLF) - 1);

		b->last = ngx_cpymem(b->last, "</div>" CRLF, sizeof("</div>" CRLF) - 1);
    }

	return b;
}


static ngx_buf_t *
ngx_http_act_list(ngx_http_request_t *r, ngx_str_t *params)
{
	size_t             		    		size;
    ngx_buf_t   			   	   	   *b;
	ngx_http_upstream_srv_conf_t  	   *us;
	ngx_http_upstream_rr_peers_t       *peers;

	ngx_str_t *backend = &params[NGX_HTTP_PARAM_UPS];	

	us = ngx_http_find_upstream(r, backend);
	if (us == NULL) {
		return NULL;
	}

	size = sizeof("[") - 1;

	peers = us->peer.data;

	size += ngx_http_peers_len(r, peers, 0);

	size += sizeof("]") - 1;

	b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NULL;
    }

	b->last = ngx_cpymem(b->last, "[", sizeof("[") - 1);

	peers = us->peer.data;
	ngx_http_peers_data(r, peers, b, 0);

	b->last = ngx_cpymem(b->last, "]", sizeof("]") - 1);

	return b;
}


static ngx_buf_t *
ngx_http_act_show(ngx_http_request_t *r, ngx_str_t *params)
{
	size_t             		    		size;
    ngx_buf_t   			   	   	   *b;
	ngx_str_t 						   *backend;
	ngx_str_t 						   *server;
	ngx_flag_t							backup;
	ngx_http_upstream_srv_conf_t  	   *us;
	ngx_http_upstream_rr_peers_t       *peers;
	ngx_http_upstream_rr_peer_t        *peer;

	backend = &params[NGX_HTTP_PARAM_UPS];	
	server = &params[NGX_HTTP_PARAM_ADDR];	

	us = ngx_http_find_upstream(r, backend);
	if (us == NULL) {
		return NULL;
	}

	peers = us->peer.data;
	
	peer = ngx_http_find_peer(peers, server, &backup);
	if (peer == NULL) {
		return NULL;
	}

	size = ngx_http_peer_len(r, peer, backup);

	b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NULL;
    }

	ngx_http_peer_data(r, peer, b, backup);

	return b;
}


static ngx_buf_t *
ngx_http_act_add(ngx_http_request_t *r, ngx_str_t *params)
{
	time_t                       	   fail_timeout;
	u_short               			   port;
	ngx_int_t						   rc;
    ngx_url_t             			   url;
	ngx_buf_t						  *b;
	ngx_flag_t						   bp, down;
	ngx_flag_t						   prm_backup;
	ngx_int_t                    	   weight, max_fails;
	ngx_str_t 						  *backend;
	ngx_str_t 						  *server;
	ngx_slab_pool_t 				  *shpool;
	ngx_http_upstream_srv_conf_t  	   *us;
	ngx_http_upstream_rr_peers_t       *peers, *backup_peers;
	ngx_http_upstream_rr_peer_t        *peer;
	ngx_http_upstream_resolved_t	   *resolved;

	backend = &params[NGX_HTTP_PARAM_UPS];	
	server = &params[NGX_HTTP_PARAM_ADDR];	

	us = ngx_http_find_upstream(r, backend);
	if (us == NULL) {
		return NULL;
	}

	peers = us->peer.data;

	if (ngx_http_find_peer(peers, server, &bp) != NULL) {
        return NULL;
    }

	rc = ngx_http_parse_act_params(r, params, us, &weight, &max_fails,
    			&fail_timeout, &prm_backup, &down);

	if (rc == NGX_ERROR) {
		return NULL;
	}

	b = ngx_http_buf_ok(r);
    if (b == NULL) {
        return NULL;
    }

	shpool = peers->shpool;

	ngx_memzero(&url, sizeof(ngx_url_t));

	port = 80;

	url.url = *server;
    url.default_port = port;
    url.uri_part = 0;
    url.no_resolve = 1;

	if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in fly add \"%V\"", url.err, &url.url);
        }

        return NULL;
    }

	resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (resolved == NULL) {
        return NULL;
    }

	if (url.addrs && url.addrs[0].sockaddr) {
        resolved->sockaddr = url.addrs[0].sockaddr;
        resolved->socklen = url.addrs[0].socklen;
        resolved->naddrs = 1;
        resolved->host = url.addrs[0].name;

    } else {

		/* domain unsupported */

		return NULL;

        resolved->host = url.host;
        resolved->port = (in_port_t) (url.no_port ? port : url.port);
        resolved->no_port = url.no_port;
    }

	ngx_shmtx_lock(&shpool->mutex);

	peer = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_upstream_rr_peer_t));
	if (peer == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
		return NULL;
	}

	peer->sockaddr = ngx_slab_alloc_locked(shpool, resolved->socklen);
	if (peer->sockaddr == NULL) {
		ngx_slab_free_locked(shpool, peer);
        ngx_shmtx_unlock(&shpool->mutex);
		return NULL;
	}

	ngx_memcpy(peer->sockaddr, resolved->sockaddr, resolved->socklen);
	peer->socklen = resolved->socklen;

	peer->name.data = ngx_slab_alloc_locked(shpool, resolved->host.len);
	if (peer->name.data == NULL) {
		ngx_slab_free_locked(shpool, peer);
		ngx_slab_free_locked(shpool, peer->sockaddr);
        ngx_shmtx_unlock(&shpool->mutex);
		return NULL;
	}

	ngx_memcpy(peer->name.data, resolved->host.data, resolved->host.len);
	peer->name.len = resolved->host.len;

	peer->weight = weight;
	peer->effective_weight = 1;
	peer->current_weight = 0;
	peer->max_fails = max_fails;
	peer->fail_timeout = fail_timeout;
	peer->down = down;

	backup_peers = peers->next;

	if (prm_backup) {
		if (backup_peers == NULL) {
			backup_peers = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_upstream_rr_peers_t));
			if (backup_peers == NULL) {
				ngx_slab_free_locked(shpool, peer);
				ngx_slab_free_locked(shpool, peer->sockaddr);
				ngx_slab_free_locked(shpool, peer->name.data);
				ngx_shmtx_unlock(&shpool->mutex);
				return NULL;
			}

			backup_peers->shpool = shpool;

			peers->next = backup_peers;
		}

		peers = peers->next;
	}

	peer->next = peers->peer;
	peers->peer = peer;

	peers->number++;

    ngx_shmtx_unlock(&shpool->mutex);

	return b;
}


static ngx_buf_t *
ngx_http_act_update(ngx_http_request_t *r, ngx_str_t *params)
{
	time_t                       	   fail_timeout;
	ngx_int_t						   rc;
	ngx_buf_t						  *b;
	ngx_flag_t						   bp, down;
	ngx_flag_t						   prm_backup;
	ngx_int_t                    	   weight, max_fails;
	ngx_str_t 						  *backend;
	ngx_str_t 						  *addr;
	ngx_slab_pool_t 				  *shpool;
	ngx_http_upstream_srv_conf_t  	   *us;
	ngx_http_upstream_rr_peers_t       *peers;
	ngx_http_upstream_rr_peer_t        *peer;

	backend = &params[NGX_HTTP_PARAM_UPS];	
	addr = &params[NGX_HTTP_PARAM_ADDR];	

	us = ngx_http_find_upstream(r, backend);
	if (us == NULL) {
		return NULL;
	}

	peers = us->peer.data;

	peer = ngx_http_find_peer(peers, addr, &bp);
	if (peer == NULL) {
		return NULL;
	}

	rc = ngx_http_parse_act_params(r, params, us, &weight, &max_fails,
    			&fail_timeout, &prm_backup, &down);

	if (rc == NGX_ERROR) {
		return NULL;
	}

	b = ngx_http_buf_ok(r);
    if (b == NULL) {
        return NULL;
    }

	shpool = peers->shpool;

	ngx_shmtx_lock(&shpool->mutex);

	peer->weight = weight;
	peer->effective_weight = 1;
	peer->current_weight = 0;
	peer->max_fails = max_fails;
	peer->fail_timeout = fail_timeout;
	peer->down = down;

    ngx_shmtx_unlock(&shpool->mutex);

	return b;
}


static ngx_buf_t *
ngx_http_act_delete(ngx_http_request_t *r, ngx_str_t *params)
{
	ngx_buf_t						  *b;
	ngx_flag_t						   bp;
	ngx_str_t 						  *backend;
	ngx_str_t 						  *address;
	ngx_slab_pool_t 				  *shpool;
	ngx_http_upstream_srv_conf_t  	   *us;
	ngx_http_upstream_rr_peers_t       *peers;
	ngx_http_upstream_rr_peer_t        *peer;

	backend = &params[NGX_HTTP_PARAM_UPS];	
	address = &params[NGX_HTTP_PARAM_ADDR];	

	us = ngx_http_find_upstream(r, backend);
	if (us == NULL) {
		return NULL;
	}

	peers = us->peer.data;

	peer = ngx_http_find_peer(peers, address, &bp);
	if (peer == NULL) {
        return NULL;
    }

	if (bp == 0 && peers->number == 1) {
		return NULL;
	}

	b = ngx_http_buf_ok(r);
    if (b == NULL) {
        return NULL;
    }

	shpool = peers->shpool;

	ngx_shmtx_lock(&shpool->mutex);

	ngx_http_delete_peer(peers, peer, bp);

	ngx_slab_free_locked(shpool, peer);

	peers->number--;

    ngx_shmtx_unlock(&shpool->mutex);

	return b;
}


static ngx_http_upstream_srv_conf_t *
ngx_http_find_upstream(ngx_http_request_t *r, ngx_str_t *backend)
{
	ngx_uint_t							 i;
	ngx_http_fly_main_conf_t  			*fmcf;
	ngx_http_upstream_srv_conf_t       **uscfp;

	fmcf = ngx_http_get_module_main_conf(r, ngx_http_fly_module);

	uscfp = fmcf->upstreams.elts; 

	for (i = 0; i < fmcf->upstreams.nelts; i++) {

		if (uscfp[i]->host.len == backend->len
            && ngx_strncasecmp(uscfp[i]->host.data, backend->data, backend->len)
               == 0)
        {
			return uscfp[i];
        }
	}

	return NULL;
}


static ngx_http_upstream_rr_peer_t *
ngx_http_find_peer(ngx_http_upstream_rr_peers_t *peers,
	ngx_str_t *addr, ngx_flag_t *bp)
{
	ngx_http_upstream_rr_peer_t	 *peer;

	for (peer = peers->peer; peer; peer = peer->next) {

		if (peer->name.len == addr->len
            && ngx_strncasecmp(peer->name.data, addr->data, addr->len)
               == 0)
        {
			*bp = 0;
			return peer;
        }
	}

	if (peers->next) {
		for (peer = peers->next->peer; peer; peer = peer->next) {

			if (peer->name.len == addr->len
				&& ngx_strncasecmp(peer->name.data, addr->data, addr->len)
				   == 0)
			{
				*bp = 1;
				return peer;
			}
		}
	}

	return NULL;
}


static void
ngx_http_delete_peer(ngx_http_upstream_rr_peers_t *peers,
	ngx_http_upstream_rr_peer_t *curr, ngx_flag_t bp)
{
	ngx_http_upstream_rr_peer_t	 **prev, *peer;

	peers = bp ? peers->next : peers;

	if (peers == NULL) {
		return;
	}

	prev = &peers->peer;

	for (peer = peers->peer; peer; peer = peer->next) {
		if (peer == curr) {
			break;
        }

		prev = &peer->next;
	}

	*prev = peer->next;
}


static size_t
ngx_http_peer_len(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peer_t *peer, ngx_flag_t bp)
{
	size_t 			 			  size;

	size = sizeof("<tr>" CRLF) - 1;

	size += sizeof("<td>") - 1 + peer->name.len + sizeof("</td>" CRLF) - 1;
;

	if (bp) {
		size += sizeof("<td>yes</td>" CRLF) - 1;
	
	} else {
		size += sizeof("<td>no</td>" CRLF) - 1;
	}

	if (peer->down) {
		size += sizeof("<td>down</td>" CRLF) - 1;

	} else {
		size += sizeof("<td>normal</td>" CRLF) - 1;
	}

	size += sizeof("<td>") - 1 + NGX_ATOMIC_T_LEN + sizeof("</td>" CRLF) - 1;

	size += sizeof("<td>") - 1 + NGX_ATOMIC_T_LEN + sizeof("</td>" CRLF) - 1;

	size += sizeof("<td>") - 1 + NGX_ATOMIC_T_LEN + sizeof("</td>" CRLF) - 1;

	size += sizeof("</tr>" CRLF) - 1;

	return size;
}


static void
ngx_http_peer_data(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peer_t *peer, ngx_buf_t *b, ngx_flag_t bp)
{
	b->last = ngx_cpymem(b->last, "<tr>" CRLF, sizeof("<tr>" CRLF) - 1);

	b->last = ngx_cpymem(b->last, "<td>", sizeof("<td>") - 1);
	b->last = ngx_cpymem(b->last, peer->name.data, peer->name.len);
	b->last = ngx_cpymem(b->last, "</td>" CRLF, sizeof("</td>" CRLF) - 1);

	if (bp) {
		b->last = ngx_cpymem(b->last, "<td>yes</td>" CRLF, 
								sizeof("</td>yes</td>" CRLF) - 1);

	} else {
		b->last = ngx_cpymem(b->last, "<td>no</td>" CRLF, 
								sizeof("</td>no</td>" CRLF) - 1);
	}

	if (peer->down) {
		b->last = ngx_cpymem(b->last, "<td>down</td>" CRLF, 
								sizeof("<td>down</td>" CRLF) - 1);

	} else {
		b->last = ngx_cpymem(b->last, "<td>normal</td>" CRLF, 
								sizeof("<td>normal</td>" CRLF) - 1);
	}

	b->last = ngx_cpymem(b->last, "<td>", sizeof("</td>") - 1);
	b->last = ngx_sprintf(b->last, "%uA", peer->weight);
	b->last = ngx_cpymem(b->last, "</td>" CRLF, sizeof("</td>" CRLF) - 1);

	b->last = ngx_cpymem(b->last, "<td>", sizeof("<td>") - 1);
	b->last = ngx_sprintf(b->last, "%uA", peer->max_fails);
	b->last = ngx_cpymem(b->last, "</td>" CRLF, sizeof("</td>" CRLF) - 1);

	b->last = ngx_cpymem(b->last, "<td>", sizeof("<td>") - 1);
	b->last = ngx_sprintf(b->last, "%uA", peer->fail_timeout);
	b->last = ngx_cpymem(b->last, "</td>" CRLF, sizeof("</td>" CRLF) - 1);

	b->last = ngx_cpymem(b->last, "</tr>" CRLF, sizeof("</tr>" CRLF) - 1);
}


static size_t
ngx_http_peers_len(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peers_t *peers, ngx_flag_t bp)
{
	size_t 			 			  size;
	ngx_http_upstream_rr_peer_t	 *peer;

	size = 0;

	if (peers == NULL) {
		return 0;
	}

	for (peer = peers->peer; peer; peer = peer->next) {
		size += ngx_http_peer_len(r, peer, bp);
	}

	if (peers->next) {
		size += ngx_http_peers_len(r, peers->next, 1);
	}

	return size;
}


static void
ngx_http_peers_data(ngx_http_request_t *r, 
	ngx_http_upstream_rr_peers_t *peers, ngx_buf_t *b, ngx_flag_t bp)
{
	ngx_http_upstream_rr_peer_t  	   *peer;

	if (peers == NULL) {
		return;
	}

	for (peer = peers->peer; peer; peer = peer->next) {
		ngx_http_peer_data(r, peer, b, bp);
	}

	if (peers->next) {
		ngx_http_peers_data(r, peers->next, b, 1);
	}
}


static ngx_buf_t *
ngx_http_buf_ok(ngx_http_request_t *r)
{
	size_t							   size;
	ngx_buf_t						  *b;

	size = sizeof("{\"res\":\"ok\"}") - 1;

	b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) {
        return NULL;
    }

	b->last = ngx_cpymem(b->last, "{\"res\":\"ok\"}", 
							sizeof("{\"res\":\"ok\"}") - 1);

	return b;
}


static ngx_int_t
ngx_http_send_act_response(ngx_http_request_t *r, ngx_buf_t *b)
{
	ngx_int_t		rc;
	ngx_buf_t	   *h, *t;
	ngx_chain_t		out[3];

	h = ngx_calloc_buf(r->pool);
    if (h == NULL) {
        return NGX_ERROR;
    }

    h->memory = 1;
    h->pos = ngx_http_act_header;
    h->last = ngx_http_act_header + sizeof(ngx_http_act_header) - 1;

	t = ngx_calloc_buf(r->pool);
    if (t == NULL) {
        return NGX_ERROR;
    }

    t->memory = 1;
    t->last_buf = 1;
    t->pos = ngx_http_act_tail;
    t->last = ngx_http_act_tail + sizeof(ngx_http_act_tail) - 1;

    out[0].buf = h;
    out[0].next = &out[1];

    out[1].buf = b;
	out[1].next = &out[2];

	out[2].buf = t;
	out[2].next = NULL;

    r->headers_out.content_type_len = sizeof("text/html") - 1;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (h->last - h->pos) + 
									  (b->last - b->pos) +
									  (t->last - t->pos);

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
    }

	return ngx_http_output_filter(r, &out[0]);
}


static ngx_int_t
ngx_http_fly_preconfiguration(ngx_conf_t *cf)
{
    ngx_int_t                  rc;
    ngx_http_act_t     		  *act;
    ngx_http_fly_main_conf_t  *fmcf;

	fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_fly_module);

    for (act = ngx_http_fly_acts; act->name.len; act++) {
        rc = ngx_hash_add_key(&fmcf->acts, &act->name, act,
                              NGX_HASH_READONLY_KEY);

        if (rc == NGX_OK) {
            continue;
        }

        if (rc == NGX_BUSY) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "conflicting fly act \"%V\"", &act->name);
        }

		return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_parse_act_params(ngx_http_request_t *r, ngx_str_t *params,
	ngx_http_upstream_srv_conf_t *us, ngx_int_t *weight, ngx_int_t *max_fails,
	time_t *fail_timeout, ngx_flag_t *backup, ngx_flag_t *down)
{
	*weight = 1;

	if (params[NGX_HTTP_PARAM_WEIGHT].data) {
		*weight = ngx_atoi(params[NGX_HTTP_PARAM_WEIGHT].data, 
							params[NGX_HTTP_PARAM_WEIGHT].len);

		if (*weight == NGX_ERROR || *weight == 0) {
			return NGX_ERROR;
		}
	}

	*max_fails = 1;

	if (params[NGX_HTTP_PARAM_MAX_FAILS].data) {
		*max_fails = ngx_atoi(params[NGX_HTTP_PARAM_MAX_FAILS].data, 
							params[NGX_HTTP_PARAM_MAX_FAILS].len);

		if (*max_fails == NGX_ERROR) {
			return NGX_ERROR;
		}
	}

	*fail_timeout = 10;

	if (params[NGX_HTTP_PARAM_FAIL_TIMEOUT].data) {
		if (!(us->flags & NGX_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
			return NGX_ERROR;
        }

		*fail_timeout = ngx_parse_time(&params[NGX_HTTP_PARAM_FAIL_TIMEOUT], 1);

		if (*fail_timeout == (time_t) NGX_ERROR) {
			return NGX_ERROR;
		}
	}

	*backup = 0;

	if (params[NGX_HTTP_PARAM_BACKUP].data) {
		if (!(us->flags & NGX_HTTP_UPSTREAM_BACKUP)) {
			return NGX_ERROR;
        }

		if ((params[NGX_HTTP_PARAM_BACKUP].len == sizeof("yes") - 1)
            && ngx_strncasecmp(params[NGX_HTTP_PARAM_BACKUP].data, (u_char *) "yes", sizeof("yes") - 1)
               == 0)
        {
			*backup = 1;

        } else if ((params[NGX_HTTP_PARAM_BACKUP].len == sizeof("no") - 1)
            && ngx_strncasecmp(params[NGX_HTTP_PARAM_BACKUP].data, (u_char *) "no", sizeof("no") - 1)
               == 0)
        {
			*backup = 0;

        } else {
			return NGX_ERROR;
		}
	}

	*down = 0;

	if (params[NGX_HTTP_PARAM_STATUS].data) {
		if (!(us->flags & NGX_HTTP_UPSTREAM_DOWN)) {
			return NGX_ERROR;
        }

		if ((params[NGX_HTTP_PARAM_STATUS].len == sizeof("down") - 1)
            && ngx_strncasecmp(params[NGX_HTTP_PARAM_STATUS].data, (u_char *) "down", sizeof("down") - 1)
               == 0)
        {
			*down = 1;

        } else if ((params[NGX_HTTP_PARAM_STATUS].len == sizeof("normal") - 1)
            && ngx_strncasecmp(params[NGX_HTTP_PARAM_STATUS].data, (u_char *) "normal", sizeof("normal") - 1)
               == 0)
        {
			*down = 0;

        } else {
			return NGX_ERROR;
		}
	}

	return NGX_OK;
}


static ngx_int_t
ngx_http_fly_postconfiguration(ngx_conf_t *cf)
{
    ngx_uint_t    						i;
	ngx_http_fly_main_conf_t 		   *fmcf;
	ngx_http_upstream_main_conf_t  	   *umcf;
	ngx_http_upstream_srv_conf_t  	  **uscfp, **usp;

	fmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_fly_module);
	umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

	uscfp = umcf->upstreams.elts; 

	for (i = 0; i < umcf->upstreams.nelts; i++) {
		if (uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE) {
			usp = ngx_array_push(&fmcf->upstreams);
			*usp = uscfp[i];
		}
    }

    return NGX_OK;
}


static void *
ngx_http_fly_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_fly_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fly_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	if (ngx_array_init(&conf->upstreams, cf->pool, 4,
                       sizeof(ngx_http_upstream_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

	conf->acts.pool = cf->pool;
    conf->acts.temp_pool = cf->temp_pool;

    if (ngx_hash_keys_array_init(&conf->acts, NGX_HASH_SMALL) != NGX_OK) {
        return NULL;
    }

	return conf;
}


static char *
ngx_http_fly_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_fly_main_conf_t *fmcf = conf;

    ngx_hash_init_t  hash;

    hash.hash = &fmcf->hash;
    hash.key = ngx_hash_key;
    hash.max_size = 1024;
    hash.bucket_size = ngx_cacheline_size;
    hash.name = "fly_act_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

	if (ngx_hash_init(&hash, fmcf->acts.keys.elts,
                      fmcf->acts.keys.nelts)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_fly_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_fly_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_fly_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

	conf->enable = NGX_CONF_UNSET;

	return conf;
}


static char *
ngx_http_fly_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_fly_loc_conf_t *prev = parent;
    ngx_http_fly_loc_conf_t *conf = child;

    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == NGX_CONF_UNSET) {
            conf->enable = 0;

        } else {
			conf->enable = prev->enable;
        }
    }

	return NGX_CONF_OK;
}


static char *
ngx_http_fly(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

	char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_fly_handler;

    return NGX_CONF_OK;
}
