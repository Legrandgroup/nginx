
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_crypt.h>


#define NGX_HTTP_AUTH_BUF_SIZE  2048

#define NGX_HTTP_AUTH_BASIC_STATUS_SUCCESS 1
#define NGX_HTTP_AUTH_BASIC_STATUS_FAILURE 0

#define NGX_HTTP_AUTH_BASIC_CLEANUP_INTERVAL 10 /* How often do we clean up expired evasion data (period in s) */
#define NGX_HTTP_AUTH_BASIC_CLEANUP_BATCH_SIZE 8 /* Size of the ngx_http_auth_basic_cleanup_list (in node count) */

#define NGX_HTTP_AUTH_BASIC_DEFAULT_MAXTRIES 5 /* How many failures do we accept before entering in evasion mode (anti-brute-force) */
#define NGX_HTTP_AUTH_BASIC_DEFAULT_DROP_TIME 300 /* After we create a record for one client IP, how long do we keep it (after this timeout, we will clean up the record, leading to dropping also evasion. This value is seconds. */
#define NGX_HTTP_AUTH_BASIC_DEFAULT_EVASION_TIME 300 /* How long do we send an evasion response (and refuse authentication) from the moment we start the evasion period (in seconds). This is done per-client IP address */

// evasion entries in the rbtree
typedef struct {
    ngx_rbtree_node_t node; // the node's .key is derived from the source address
    time_t drop_time;
    ngx_int_t failcount_times_ten; // The number of failed attempts already accounted for, multiplied by 10, so in 0.1 steps.
                                   // We count by 10% steps because one repeated login/password attempts only counts for 0.1, not for 1 failure.
    struct sockaddr src_addr;
    socklen_t src_addrlen;
    uint32_t last_failed_cred_hash; // The hash of the last attempted credentials that increased the failcount
} ngx_http_auth_basic_ev_node_t;

typedef struct {
    ngx_http_complex_value_t  *realm;
    ngx_http_complex_value_t   user_file;
    time_t drop_time;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest
    time_t evasion_time;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest
    ngx_int_t maxtries;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest
} ngx_http_auth_basic_loc_conf_t;

// the shm segment that houses the used-nonces tree and evasion rbtree
static ngx_uint_t ngx_http_auth_basic_shm_size;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest
static ngx_shm_zone_t *ngx_http_auth_basic_shm_zone;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest
static ngx_rbtree_t *ngx_http_auth_basic_ev_rbtree;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest
static char *ngx_http_auth_basic_set_shm_size(ngx_conf_t *cf,
                                              ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_auth_basic_init_shm_zone(ngx_shm_zone_t *shm_zone,
                                                   void *data);

ngx_event_t *ngx_http_auth_basic_cleanup_timer;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest, required for periodic cleanup of ngx_http_auth_basic_ev_rbtree
static ngx_array_t *ngx_http_auth_basic_cleanup_list;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest, required for periodic cleanup of ngx_http_auth_basic_ev_rbtree
static ngx_atomic_t *ngx_http_auth_basic_cleanup_lock;   // Taken from https://github.com/samizdatco/nginx-http-auth-digest, required for periodic cleanup of ngx_http_auth_basic_ev_rbtree
void ngx_http_auth_basic_cleanup(ngx_event_t *e);   // Taken from https://github.com/samizdatco/nginx-http-auth-digest, required for periodic cleanup of ngx_http_auth_basic_ev_rbtree

// evasive tactics functions
static int ngx_http_auth_basic_srcaddr_key(struct sockaddr *sa, socklen_t len,
                                            ngx_uint_t *key);
static int ngx_http_auth_basic_srcaddr_cmp(struct sockaddr *sa1,
                                            socklen_t len1,
                                            struct sockaddr *sa2,
                                            socklen_t len2);

// rbtree primitives
static void ngx_http_auth_basic_ev_rbtree_insert(ngx_rbtree_node_t *temp,
                                                 ngx_rbtree_node_t *node,
                                                 ngx_rbtree_node_t *sentinel);
static ngx_http_auth_basic_ev_node_t *
ngx_http_auth_basic_ev_rbtree_find(ngx_http_auth_basic_ev_node_t *this,
                                   ngx_rbtree_node_t *node,
                                   ngx_rbtree_node_t *sentinel);
static void
ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                          ngx_rbtree_node_t *sentinel,
                          int (*compare)(const ngx_rbtree_node_t *left,
                                         const ngx_rbtree_node_t *right));

static void ngx_http_auth_basic_evasion_tracking(ngx_http_request_t *r,
    ngx_http_auth_basic_loc_conf_t *alcf, ngx_int_t status, uint32_t cred_hash);
static int ngx_http_auth_basic_evading(ngx_http_request_t *r,
    ngx_http_auth_basic_loc_conf_t *alcf);

static ngx_int_t ngx_http_auth_basic_handler(ngx_http_request_t *r);
static ngx_int_t ngx_hash_http_auth_to_uint32(ngx_http_request_t *r, uint32_t *hash);
static ngx_int_t ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r,
    ngx_str_t *passwd, ngx_str_t *realm);
static ngx_int_t ngx_http_auth_basic_set_realm(ngx_http_request_t *r,
    ngx_str_t *realm);
static void ngx_http_auth_basic_close(ngx_file_t *file);
static void *ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_auth_basic_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_auth_basic_worker_init(ngx_cycle_t *cycle);
static char *ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_auth_basic_commands[] = {

    { ngx_string("auth_basic"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, realm),
      NULL },

    { ngx_string("auth_basic_user_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_auth_basic_user_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_auth_basic_loc_conf_t, user_file),
      NULL },

/* Taken from https://github.com/samizdatco/nginx-http-auth-digest */
    { ngx_string("auth_basic_shm_size"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
      ngx_http_auth_basic_set_shm_size,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_auth_basic_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_auth_basic_init,              /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_auth_basic_create_loc_conf,   /* create location configuration */
    ngx_http_auth_basic_merge_loc_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_auth_basic_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_basic_module_ctx,       /* module context */
    ngx_http_auth_basic_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_auth_basic_worker_init,       /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_auth_basic_handler(ngx_http_request_t *r)
{
    off_t                            offset;
    ssize_t                          n;
    ngx_fd_t                         fd;
    ngx_int_t                        rc;
    ngx_err_t                        err;
    ngx_str_t                        pwd, realm, user_file;
    ngx_uint_t                       i, level, login, left, passwd;
    ngx_file_t                       file;
    ngx_http_auth_basic_loc_conf_t  *alcf;
    u_char                           buf[NGX_HTTP_AUTH_BUF_SIZE];
    uint32_t                         user_cred_hash;
    enum {
        sw_login,
        sw_passwd,
        sw_skip
    } state;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_basic_module);

    if (alcf->realm == NULL || alcf->user_file.value.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, alcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }

    if (realm.len == 3 && ngx_strncmp(realm.data, "off", 3) == 0) {
        return NGX_DECLINED;
    }

    if (ngx_http_auth_basic_evading(r, alcf)) {
        return NGX_HTTP_UNAUTHORIZED;
    }
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "no user/password was provided for basic authentication");

        ngx_http_auth_basic_evasion_tracking(
                      r, alcf, NGX_HTTP_AUTH_BASIC_STATUS_FAILURE, 0);
        return ngx_http_auth_basic_set_realm(r, &realm);
    }

    if (rc == NGX_ERROR) {
        ngx_http_auth_basic_evasion_tracking(
                      r, alcf, NGX_HTTP_AUTH_BASIC_STATUS_FAILURE, 0);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_complex_value(r, &alcf->user_file, &user_file) != NGX_OK) {
        ngx_http_auth_basic_evasion_tracking(
                      r, alcf, NGX_HTTP_AUTH_BASIC_STATUS_FAILURE, 0);
        return NGX_ERROR;
    }

    fd = ngx_open_file(user_file.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);

    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;

        } else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_auth_basic_evasion_tracking(
                      r, alcf, NGX_HTTP_AUTH_BASIC_STATUS_FAILURE, 0);
        ngx_log_error(level, r->connection->log, err,
                      ngx_open_file_n " \"%s\" failed", user_file.data);

        return rc;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = fd;
    file.name = user_file;
    file.log = r->connection->log;

    state = sw_login;
    passwd = 0;
    login = 0;
    left = 0;
    offset = 0;

    for ( ;; ) {
        i = left;

        n = ngx_read_file(&file, buf + left, NGX_HTTP_AUTH_BUF_SIZE - left,
                          offset);

        if (n == NGX_ERROR) {
            ngx_http_auth_basic_close(&file);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (n == 0) {
            break;
        }

        for (i = left; i < left + n; i++) {
            switch (state) {

            case sw_login:
                if (login == 0) {

                    if (buf[i] == '#' || buf[i] == CR) {
                        state = sw_skip;
                        break;
                    }

                    if (buf[i] == LF) {
                        break;
                    }
                }

                if (buf[i] != r->headers_in.user.data[login]) {
                    state = sw_skip;
                    break;
                }

                if (login == r->headers_in.user.len) {
                    state = sw_passwd;
                    passwd = i + 1;
                }

                login++;

                break;

            case sw_passwd:
                if (buf[i] == LF || buf[i] == CR || buf[i] == ':') {
                    buf[i] = '\0';

                    ngx_http_auth_basic_close(&file);

                    pwd.len = i - passwd;
                    pwd.data = &buf[passwd];

                    ngx_int_t auth_status =  ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
                    // User found, password is correct if auth_status==NGX_OK
                    /* For debug: do not use in product, it dumps passwords to the log!
                    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                                  "User login %s for credentials \"%s\" (checked against \"%s\")",
                                  (auth_status == NGX_OK)?"succeeded":"failed",
                                  r->headers_in.user.data, pwd.data);
                    */
                    if (ngx_hash_http_auth_to_uint32(r, &user_cred_hash) != NGX_OK) {
                        user_cred_hash = 0;
                    }
                    ngx_http_auth_basic_evasion_tracking(
                                                         r, alcf,
                                                         (auth_status == NGX_OK)?
                                                             NGX_HTTP_AUTH_BASIC_STATUS_SUCCESS:
                                                             NGX_HTTP_AUTH_BASIC_STATUS_FAILURE,
                                                         user_cred_hash
                                                        );
                    return auth_status;
                }

                break;

            case sw_skip:
                if (buf[i] == LF) {
                    state = sw_login;
                    login = 0;
                }

                break;
            }
        }

        if (state == sw_passwd) {
            left = left + n - passwd;
            ngx_memmove(buf, &buf[passwd], left);
            passwd = 0;

        } else {
            left = 0;
        }

        offset += n;
    }

    ngx_http_auth_basic_close(&file);

    if (state == sw_passwd) {
        pwd.len = i - passwd;
        pwd.data = ngx_pnalloc(r->pool, pwd.len + 1);
        if (pwd.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_cpystrn(pwd.data, &buf[passwd], pwd.len + 1);

        ngx_int_t auth_status = ngx_http_auth_basic_crypt_handler(r, &pwd, &realm);
        if (ngx_hash_http_auth_to_uint32(r, &user_cred_hash) != NGX_OK) {
            user_cred_hash = 0;
        }
        ngx_http_auth_basic_evasion_tracking(
                                             r, alcf,
                                             (auth_status == NGX_OK)?
                                                 NGX_HTTP_AUTH_BASIC_STATUS_SUCCESS:
                                                 NGX_HTTP_AUTH_BASIC_STATUS_FAILURE,
                                             user_cred_hash
                                            );
        return auth_status;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\" was not found in \"%s\"",
                  &r->headers_in.user, user_file.data);

    ngx_http_auth_basic_evasion_tracking(
                                         r, alcf,
                                         NGX_HTTP_AUTH_BASIC_STATUS_FAILURE,
                                         0
                                        );
    return ngx_http_auth_basic_set_realm(r, &realm);
}


/**
 * @brief Hash a user:pwd string into a uint32_t value
 *
 * @param r The incoming request
 * @param[out] hash The resulting uint32_t hash
 *
 * @return NGX_OK in case of success, any other value means a failure
**/
static ngx_int_t
ngx_hash_http_auth_to_uint32(ngx_http_request_t *r, uint32_t *hash)
{
    ngx_int_t  rc;
    u_char     *encrypted;
    
    static u_char sha_no_salt[] = "{SHA}";
    rc = ngx_crypt(r->pool, r->headers_in.passwd.data, sha_no_salt, &encrypted);
    if (rc != NGX_OK || encrypted == NULL) {
         return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    *hash = ngx_crc32_short(encrypted, ngx_strlen(encrypted));
    ngx_pfree(r->pool, encrypted);
    return NGX_OK;
}

static ngx_int_t
ngx_http_auth_basic_crypt_handler(ngx_http_request_t *r, ngx_str_t *passwd,
    ngx_str_t *realm)
{
    ngx_int_t   rc;
    u_char     *encrypted;

    rc = ngx_crypt(r->pool, r->headers_in.passwd.data, passwd->data,
                   &encrypted);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "rc: %i user: \"%V\" salt: \"%s\"",
                   rc, &r->headers_in.user, passwd->data);

    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_strcmp(encrypted, passwd->data) == 0) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "encrypted: \"%s\"", encrypted);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "user \"%V\": password mismatch",
                  &r->headers_in.user);

    return ngx_http_auth_basic_set_realm(r, realm);
}


static ngx_int_t
ngx_http_auth_basic_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    size_t   len;
    u_char  *basic, *p;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;

    basic = ngx_pnalloc(r->pool, len);
    if (basic == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_cpymem(basic, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = basic;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}


/**
 * @brief Set this module's shared memory size
 *
 * @param cf The config for the module
 * @param cmd unused
 * @return conf Unused
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static char *ngx_http_auth_basic_set_shm_size(ngx_conf_t *cf,
                                              ngx_command_t *cmd, void *conf) {
  ssize_t new_shm_size;
  ngx_str_t *value;

  value = cf->args->elts;

  new_shm_size = ngx_parse_size(&value[1]);
  if (new_shm_size == NGX_ERROR) {
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid memory area size `%V'",
                       &value[1]);
    return NGX_CONF_ERROR;
  }

  new_shm_size = ngx_align(new_shm_size, ngx_pagesize);

  if (new_shm_size < 8 * (ssize_t)ngx_pagesize) {
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "The auth_basic_shm_size value must be at least %udKiB",
                       (8 * ngx_pagesize) >> 10);
    new_shm_size = 8 * ngx_pagesize;
  }

  if (ngx_http_auth_basic_shm_size &&
      ngx_http_auth_basic_shm_size != (ngx_uint_t)new_shm_size) {
    ngx_conf_log_error(
        NGX_LOG_WARN, cf, 0,
        "Cannot change memory area size without restart, ignoring change");
  } else {
    ngx_http_auth_basic_shm_size = new_shm_size;
  }
  ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0,
                     "Using %udKiB of shared memory for auth_basic",
                     new_shm_size >> 10);
  return NGX_CONF_OK;
}


/**
 * @brief Initialize this module's shared memory
 *
 * @param[in] shm_zone The shared memory zone to use
 * @param[in] data The length of the sockaddr structure @p sa
 *
 * @return NGX_OK in case of success, any other value means a failure
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static ngx_int_t ngx_http_auth_basic_init_shm_zone(ngx_shm_zone_t *shm_zone,
                                                   void *data) {
  ngx_slab_pool_t *shpool;
  ngx_rbtree_t *tree;
  ngx_rbtree_node_t *sentinel;
  ngx_atomic_t *lock;
  if (data) {
    shm_zone->data = data;
    return NGX_OK;
  }

  shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
  
  /* Note: we removed the ngx_http_auth_*_rbtree-dedicated part here
   * because we only use the evasion rbtree in our code (initialized
   * below).
   */
  tree = ngx_slab_alloc(shpool, sizeof *tree);
  if (tree == NULL) {
    return NGX_ERROR;
  }

  sentinel = ngx_slab_alloc(shpool, sizeof *sentinel);
  if (sentinel == NULL) {
    return NGX_ERROR;
  }

  ngx_rbtree_init(tree, sentinel, ngx_http_auth_basic_ev_rbtree_insert);
  ngx_http_auth_basic_ev_rbtree = tree;

  lock = ngx_slab_alloc(shpool, sizeof(ngx_atomic_t));
  if (lock == NULL) {
    return NGX_ERROR;
  }
  ngx_http_auth_basic_cleanup_lock = lock;

  return NGX_OK;
}


/**
 * @brief Initialize this module's process
 *
 * @return NGX_OK in case of success, any other value means a failure
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static ngx_int_t ngx_http_auth_basic_worker_init(ngx_cycle_t *cycle) {
  if (ngx_process != NGX_PROCESS_WORKER) {
    return NGX_OK;
  }

  // create a cleanup queue big enough for the max number of tree nodes in the
  // shm
  ngx_http_auth_basic_cleanup_list =
      ngx_array_create(cycle->pool, NGX_HTTP_AUTH_BASIC_CLEANUP_BATCH_SIZE,
                       sizeof(ngx_rbtree_node_t *));

  if (ngx_http_auth_basic_cleanup_list == NULL) {
    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "Could not allocate shared memory for auth_basic");
    return NGX_ERROR;
  }

  ngx_connection_t *dummy;
  dummy = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
  if (dummy == NULL)
    return NGX_ERROR;
  dummy->fd = (ngx_socket_t)-1;
  dummy->data = cycle;

  ngx_http_auth_basic_cleanup_timer->log = ngx_cycle->log;
  ngx_http_auth_basic_cleanup_timer->data = dummy;
  ngx_http_auth_basic_cleanup_timer->handler = ngx_http_auth_basic_cleanup;
  ngx_add_timer(ngx_http_auth_basic_cleanup_timer,
                NGX_HTTP_AUTH_BASIC_CLEANUP_INTERVAL * 1000); /* Interval is in s, timer is in ms */
  return NGX_OK;
}


/**
 * @brief Perform a cleanup on obsolete data contained into a ev_rbtree
 *
 * @param[in] node The root of the tree to walk through
 * @param[in] sentinel The sentinel for the rbtree
 * @param[in] now The current time (used to check if nodes have elapsed)
 * @param[in] log Handler to issue logs
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static void
ngx_http_auth_basic_ev_rbtree_prune_walk(ngx_rbtree_node_t *node,
                                          ngx_rbtree_node_t *sentinel,
                                          time_t now, ngx_log_t *log) {
  if (node == sentinel)
    return;

  if (node->left != sentinel) {
    ngx_http_auth_basic_ev_rbtree_prune_walk(node->left, sentinel, now, log);
  }

  if (node->right != sentinel) {
    ngx_http_auth_basic_ev_rbtree_prune_walk(node->right, sentinel, now, log);
  }

  ngx_http_auth_basic_ev_node_t *dnode =
      (ngx_http_auth_basic_ev_node_t *)node;
  if (dnode->drop_time <= ngx_time()) {
    ngx_rbtree_node_t **dropnode =
        ngx_array_push(ngx_http_auth_basic_cleanup_list);
    dropnode[0] = node;
  }
}

/**
 * @brief Perform a cleanup on obsolete data contained into the ngx_http_auth_basic_ev_rbtree
 *
 * @param log Handler to issue logs
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static void ngx_http_auth_basic_ev_rbtree_prune(ngx_log_t *log) {
  ngx_uint_t i;
  time_t now = ngx_time();
  ngx_slab_pool_t *shpool =
      (ngx_slab_pool_t *)ngx_http_auth_basic_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  ngx_http_auth_basic_cleanup_list->nelts = 0;
  ngx_http_auth_basic_ev_rbtree_prune_walk(
      ngx_http_auth_basic_ev_rbtree->root,
      ngx_http_auth_basic_ev_rbtree->sentinel, now, log);

  if (ngx_http_auth_basic_cleanup_list->nelts > 0) {
    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "auth_basic periodic clean up deleting %d evasion record(s)", ngx_http_auth_basic_cleanup_list->nelts);
  }
  ngx_rbtree_node_t **elts =
      (ngx_rbtree_node_t **)ngx_http_auth_basic_cleanup_list->elts;
  for (i = 0; i < ngx_http_auth_basic_cleanup_list->nelts; i++) {
    ngx_rbtree_delete(ngx_http_auth_basic_ev_rbtree, elts[i]);
    ngx_slab_free_locked(shpool, elts[i]);
  }
  ngx_shmtx_unlock(&shpool->mutex);

  // if the cleanup array grew during the run, shrink it back down
  if (ngx_http_auth_basic_cleanup_list->nalloc >
      NGX_HTTP_AUTH_BASIC_CLEANUP_BATCH_SIZE) {
    ngx_array_t *old_list = ngx_http_auth_basic_cleanup_list;
    ngx_array_t *new_list = ngx_array_create(
        old_list->pool, NGX_HTTP_AUTH_BASIC_CLEANUP_BATCH_SIZE,
        sizeof(ngx_rbtree_node_t *));
    if (new_list != NULL) {
      ngx_array_destroy(old_list);
      ngx_http_auth_basic_cleanup_list = new_list;
    } else {
      ngx_log_error(NGX_LOG_ERR, log, 0,
                    "auth_basic ran out of cleanup space");
    }
  }
}


/**
 * @brief Perform a cleanup of obsolete data used for evasion
 *
 * @param ev The event (timer) that triggered a call to this function
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
void ngx_http_auth_basic_cleanup(ngx_event_t *ev) {
  if (ev->timer_set)
    ngx_del_timer(ev);

  if (!(ngx_quit || ngx_terminate || ngx_exiting)) {
    ngx_add_timer(ev, NGX_HTTP_AUTH_BASIC_CLEANUP_INTERVAL * 1000); /* Interval is in s, timer is in ms */
  }

  if (ngx_trylock(ngx_http_auth_basic_cleanup_lock)) {
    ngx_http_auth_basic_ev_rbtree_prune(ev->log);
    ngx_unlock(ngx_http_auth_basic_cleanup_lock);
  }
}


/**
 * @brief Insert a node into a generic rbtree
 *
 * @param[in] temp A node that is guaranteed to be above the node to add (eg: the root of the tree)
 * @param[in] node The node to insert into the tree
 * @param[in] sentinel The sentinel for the rbtree
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static void
ngx_rbtree_generic_insert(ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
                          ngx_rbtree_node_t *sentinel,
                          int (*compare)(const ngx_rbtree_node_t *left,
                                         const ngx_rbtree_node_t *right)) {
  for (;;) {
    if (node->key < temp->key) {

      if (temp->left == sentinel) {
        temp->left = node;
        break;
      }

      temp = temp->left;

    } else if (node->key > temp->key) {

      if (temp->right == sentinel) {
        temp->right = node;
        break;
      }

      temp = temp->right;

    } else { /* node->key == temp->key */
      if (compare(node, temp) < 0) {

        if (temp->left == sentinel) {
          temp->left = node;
          break;
        }

        temp = temp->left;

      } else {

        if (temp->right == sentinel) {
          temp->right = node;
          break;
        }

        temp = temp->right;
      }
    }
  }

  node->parent = temp;
  node->left = sentinel;
  node->right = sentinel;
  ngx_rbt_red(node);
}


/**
 * @brief Compare two nodes in a evasion rbtree
 *
 * @param[in] v_left The left operand for the comparison
 * @param[in] v_right The right operand for the comparison
 *
 * @return -1 if v_left<v_right, 0 if v_left==v_right, 1 if v_left>v_right
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static int
ngx_http_auth_basic_ev_rbtree_cmp(const ngx_rbtree_node_t *v_left,
                                  const ngx_rbtree_node_t *v_right) {
  if (v_left->key == v_right->key) {
    ngx_http_auth_basic_ev_node_t *evleft =
        (ngx_http_auth_basic_ev_node_t *)v_left;
    ngx_http_auth_basic_ev_node_t *evright =
        (ngx_http_auth_basic_ev_node_t *)v_right;
    return ngx_http_auth_basic_srcaddr_cmp(
        &evleft->src_addr, evleft->src_addrlen, &evright->src_addr,
        evright->src_addrlen);
  }
  return (v_left->key < v_right->key) ? -1 : 1;
}


/**
 * @brief Compute a key (hash) based on the sockaddr for a client connection
 *
 * @param[in] sa The sockaddr structure representing the remote client
 * @param len The length of the sockaddr structure @p sa
 * @param[out] key The resulting key (result of a hash)
 *
 * @return 0 in case of failure, any other value means a success
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static int ngx_http_auth_basic_srcaddr_key(struct sockaddr *sa, socklen_t len,
                                           ngx_uint_t *key) {
  struct sockaddr_in *sin;
#if (NGX_HAVE_INET6)
  struct sockaddr_in6 *s6;
#endif

  switch (sa->sa_family) {
  case AF_INET:
    sin = (struct sockaddr_in *)sa;
    *key = ngx_crc32_short((u_char *)&sin->sin_addr, sizeof(sin->sin_addr));
    return 1;
#if (NGX_HAVE_INET6)
  case AF_INET6:
    s6 = (struct sockaddr_in6 *)sa;
    *key = ngx_crc32_short((u_char *)&s6->sin6_addr, sizeof(s6->sin6_addr));
    return 1;
#endif
  default:
    break;
  }
  return 0;
}


/**
 * @brief Compare two source addresses
 *
 * @param[in] sa1 The left operand for the comparison
 * @param[in] len1 The length of the left operand's buffer for the comparison
 * @param[in] sa2 The right operand for the comparison
 * @param[in] len2 The length of the right operand's buffer for the comparison
 *
 * @return -1 if sa1<sa2, 0 if sa1==sa2, 1 if sa1>sa2
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static int ngx_http_auth_basic_srcaddr_cmp(struct sockaddr *sa1,
                                           socklen_t len1,
                                           struct sockaddr *sa2,
                                           socklen_t len2) {
  struct sockaddr_in *sin1, *sin2;
#if (NGX_HAVE_INET6)
  struct sockaddr_in6 *s61, *s62;
#endif
  if (len1 != len2) {
    return (len1 < len2) ? -1 : 1;
  }
  if (sa1->sa_family != sa2->sa_family) {
    return (sa1->sa_family < sa2->sa_family) ? -1 : 1;
  }

  switch (sa1->sa_family) {
  case AF_INET:
    sin1 = (struct sockaddr_in *)sa1;
    sin2 = (struct sockaddr_in *)sa2;
    return ngx_memcmp(&sin1->sin_addr, &sin2->sin_addr, sizeof(sin1->sin_addr));
#if (NGX_HAVE_INET6)
  case AF_INET6:
    s61 = (struct sockaddr_in6 *)sa1;
    s62 = (struct sockaddr_in6 *)sa2;
    return ngx_memcmp(&s61->sin6_addr, &s62->sin6_addr, sizeof(s61->sin6_addr));
#endif
  default:
    break;
  }
  return -999;
}


/**
 * @brief Insert a node in a evasion rbtree
 *
 * @param[in] temp A node that is guaranteed to be above the node to add (eg: the root of the tree)
 * @param[in] node The node to insert into the tree
 * @param[in] sentinel The sentinel for the rbtree
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static void ngx_http_auth_basic_ev_rbtree_insert(ngx_rbtree_node_t *temp,
                                                 ngx_rbtree_node_t *node,
                                                 ngx_rbtree_node_t *sentinel) {

  ngx_rbtree_generic_insert(temp, node, sentinel,
                            ngx_http_auth_basic_ev_rbtree_cmp);
}


/**
 * @brief Find a node in a evasion rbtree
 *
 * @param[in] this The top of the tree to search
 * @param[in] node The node to find into the tree
 * @param[in] sentinel The sentinel for the rbtree
 *
 * @return The node found or NULL
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static ngx_http_auth_basic_ev_node_t *
ngx_http_auth_basic_ev_rbtree_find(ngx_http_auth_basic_ev_node_t *this,
                                   ngx_rbtree_node_t *node,
                                   ngx_rbtree_node_t *sentinel) {
  int cmpval;
  if (node == sentinel)
    return NULL;

  cmpval = ngx_http_auth_basic_ev_rbtree_cmp((ngx_rbtree_node_t *)this, node);
  if (cmpval == 0) {
    return (ngx_http_auth_basic_ev_node_t *)node;
  }
  return ngx_http_auth_basic_ev_rbtree_find(
      this, (cmpval < 0) ? node->left : node->right, sentinel);
}


/**
 * @brief Keep track of evasion statistics based on authentication
 *
 * @param[in] r The HTTP request from the web client
 * @param[in,out] alcf A pointer to the module's local conf structure (context)
 * @param status The current authentication status (success/failure - used to handle statistics accordingly)
 * @param cred_hash The credentials that lead to @p status, hashed as a uint32_t
 *
 * @note Code taken from https://github.com/samizdatco/nginx-http-auth-digest
**/
static void
ngx_http_auth_basic_evasion_tracking(ngx_http_request_t *r,
                                     ngx_http_auth_basic_loc_conf_t *alcf,
                                     ngx_int_t status,
                                     uint32_t cred_hash) {
  ngx_slab_pool_t *shpool;
  ngx_uint_t key;
  ngx_http_auth_basic_ev_node_t testnode, *node;

  if (!ngx_http_auth_basic_srcaddr_key(r->connection->sockaddr,
                                       r->connection->socklen, &key)) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "skipping evasive tactics for this source address");
    return;
  }
  shpool = (ngx_slab_pool_t *)ngx_http_auth_basic_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  ngx_memzero(&testnode, sizeof(testnode));
  testnode.node.key = key;
  ngx_memcpy(&testnode.src_addr, r->connection->sockaddr,
             r->connection->socklen);
  testnode.src_addrlen = r->connection->socklen;
  node = ngx_http_auth_basic_ev_rbtree_find(
      &testnode, ngx_http_auth_basic_ev_rbtree->root,
      ngx_http_auth_basic_ev_rbtree->sentinel);
  if (node == NULL) {
    // Don't bother creating a node if this was a successful auth
    if (status == NGX_HTTP_AUTH_BASIC_STATUS_SUCCESS) {
      ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "sucessful auth, not tracking");
      ngx_shmtx_unlock(&shpool->mutex);
      return;
    }
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0, "adding tracking node");
    node =
        ngx_slab_alloc_locked(shpool, sizeof(ngx_http_auth_basic_ev_node_t));
    if (node == NULL) {
      ngx_shmtx_unlock(&shpool->mutex);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "auth_basic ran out of shm space. Increase the "
                    "auth_basic_shm_size limit.");
      return;
    }
    ngx_memcpy(&node->src_addr, r->connection->sockaddr,
               r->connection->socklen);
    node->src_addrlen = r->connection->socklen;
    ((ngx_rbtree_node_t *)node)->key = key;
    ngx_rbtree_insert(ngx_http_auth_basic_ev_rbtree, &node->node);
  }
  if (status == NGX_HTTP_AUTH_BASIC_STATUS_SUCCESS) {
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "successful auth, clearing evasion counters");
    node->failcount_times_ten = 0;
    node->drop_time = ngx_time();
    node->last_failed_cred_hash = 0; /* Reset the last failed credentials */
  } else {
    // Reset the failure count to 1 if we're outside the evasion window
    if (ngx_time() > node->drop_time) {
      node->failcount_times_ten = 10; /* 10 here means one full failure */
      node->last_failed_cred_hash = cred_hash;
    } else {
      if (node->last_failed_cred_hash == cred_hash) {
        /* If last failure was on the same login/password, consider this is a retry
           and thus, do only count this for 1/4 in the failed count */
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                      "same auth as previous failure, only increasing 1/10");
        node->failcount_times_ten += 1;
      }
      else {
        // Otherwise increase the failed count to progress toward coutnermeasure (evasion)
        node->failcount_times_ten += 10; /* One full failure */
        node->last_failed_cred_hash = cred_hash;
      }
    }
    node->drop_time = ngx_time() + alcf->evasion_time;
    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "failed auth, updating failcount=%d.%d, drop_time=%d",
                  node->failcount_times_ten/10, node->failcount_times_ten%10, node->drop_time);
  }
  ngx_shmtx_unlock(&shpool->mutex);
}


/**
 * @brief Evade an incoming connection that is already categorized as brute-force (quota exceeded)
 *
 * @param r The incoming request
 * @param[in,out] alcf A pointer to the module's local conf structure (context)
**/
static int ngx_http_auth_basic_evading(ngx_http_request_t *r,
                                       ngx_http_auth_basic_loc_conf_t *alcf) {
  ngx_slab_pool_t *shpool;
  ngx_uint_t key;
  ngx_http_auth_basic_ev_node_t testnode, *node;
  int evading = 0;

  if (!ngx_http_auth_basic_srcaddr_key(r->connection->sockaddr,
                                       r->connection->socklen, &key)) {
    return 0;
  }

  ngx_memzero(&testnode, sizeof(testnode));
  testnode.node.key = key;
  ngx_memcpy(&testnode.src_addr, r->connection->sockaddr,
             r->connection->socklen);
  testnode.src_addrlen = r->connection->socklen;

  shpool = (ngx_slab_pool_t *)ngx_http_auth_basic_shm_zone->shm.addr;

  ngx_shmtx_lock(&shpool->mutex);
  node = ngx_http_auth_basic_ev_rbtree_find(
      &testnode, ngx_http_auth_basic_ev_rbtree->root,
      ngx_http_auth_basic_ev_rbtree->sentinel);
  if (node != NULL && node->failcount_times_ten >= alcf->maxtries*10 &&
      ngx_time() < node->drop_time) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ignoring authentication request - in evasion period");
    evading = 1;
  }
  ngx_shmtx_unlock(&shpool->mutex);
  return evading;
}


static void
ngx_http_auth_basic_close(ngx_file_t *file)
{
    if (ngx_close_file(file->fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, file->log, ngx_errno,
                      ngx_close_file_n " \"%s\" failed", file->name.data);
    }
}


static void *
ngx_http_auth_basic_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_basic_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_basic_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->drop_time = NGX_HTTP_AUTH_BASIC_DEFAULT_DROP_TIME;
    conf->evasion_time = NGX_HTTP_AUTH_BASIC_DEFAULT_EVASION_TIME;
    conf->maxtries = NGX_HTTP_AUTH_BASIC_DEFAULT_MAXTRIES;

    return conf;
}


static char *
ngx_http_auth_basic_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_basic_loc_conf_t  *prev = parent;
    ngx_http_auth_basic_loc_conf_t  *conf = child;

    if (conf->realm == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->user_file.value.data == NULL) {
        conf->user_file = prev->user_file;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_basic_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    ngx_str_t                  *shm_name; // Code taken from nginx-http-auth-digest

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_basic_handler;

    /* The following timeout-based cleanup was taken from nginx-http-auth-digest */
    ngx_http_auth_basic_cleanup_timer =
        ngx_pcalloc(cf->pool, sizeof(ngx_event_t));
    if (ngx_http_auth_basic_cleanup_timer == NULL) {
        return NGX_ERROR;
    }

    /* The following shm-related code was taken from nginx-http-auth-digest */
    shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
    shm_name->len = sizeof("auth_basic");
    shm_name->data = (unsigned char *)"auth_basic";

    if (ngx_http_auth_basic_shm_size == 0) {
        ngx_http_auth_basic_shm_size = 256 * ngx_pagesize / 32; // default to 1/32mb
    }

    ngx_http_auth_basic_shm_zone =
        ngx_shared_memory_add(cf, shm_name, ngx_http_auth_basic_shm_size,
                              &ngx_http_auth_basic_module);
    if (ngx_http_auth_basic_shm_zone == NULL) {
        return NGX_ERROR;
    }
    ngx_http_auth_basic_shm_zone->init = ngx_http_auth_basic_init_shm_zone;

    return NGX_OK;
}


static char *
ngx_http_auth_basic_user_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_auth_basic_loc_conf_t *alcf = conf;

    ngx_str_t                         *value;
    ngx_http_compile_complex_value_t   ccv;

    if (alcf->user_file.value.data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &alcf->user_file;
    ccv.zero = 1;
    ccv.conf_prefix = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
