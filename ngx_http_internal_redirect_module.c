/*
 * Copyright (c) 2013, FengGu <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t  postponed;
    unsigned    required:1;
} ngx_http_internal_redirect_main_conf_t;


typedef struct {
    ngx_array_t  *codes;
    ngx_str_t     target;
} ngx_http_internal_redirect_entry_t;


typedef struct {
    ngx_array_t  *redirects;  /* ngx_http_internal_redirect_entry_t */
} ngx_http_internal_redirect_loc_conf_t;


static char *ngx_http_internal_redirect_if(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_internal_redirect_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_internal_redirect_handler(ngx_http_request_t *r);
static char *ngx_http_internal_redirect_if_condition(ngx_conf_t *cf,
    ngx_http_internal_redirect_entry_t *redirect);
static char *ngx_http_internal_redirect_if_condition_value(ngx_conf_t *cf,
    ngx_http_internal_redirect_entry_t *redirect, ngx_str_t *value);
static void *ngx_http_internal_redirect_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_internal_redirect_init_main_conf(ngx_conf_t *cf,
    void *conf);
static void *ngx_http_internal_redirect_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_internal_redirect_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);


static ngx_command_t  ngx_http_internal_redirect_commands[] = {

    { ngx_string("internal_redirect_if"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_internal_redirect_if,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("internal_redirect_if_no_postpone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_internal_redirect_main_conf_t, postponed),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_internal_redirect_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_internal_redirect_init,        /* postconfiguration */

    ngx_http_internal_redirect_create_main_conf,
                                            /* create main configuration */
    ngx_http_internal_redirect_init_main_conf,
                                            /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_internal_redirect_create_loc_conf,
                                            /* create location configuration */
    ngx_http_internal_redirect_merge_loc_conf,
                                            /* merge location configuration */
};


ngx_module_t  ngx_http_internal_redirect_module = {
    NGX_MODULE_V1,
    &ngx_http_internal_redirect_module_ctx,     /* module context */
    ngx_http_internal_redirect_commands,        /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    NULL,                                       /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


static char *
ngx_http_internal_redirect_if(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                               *value;
    ngx_http_internal_redirect_entry_t      *redirect;
    ngx_http_internal_redirect_main_conf_t  *imcf;
    ngx_http_internal_redirect_loc_conf_t   *ilcf = conf;

    if (ilcf->redirects == NULL) {
        ilcf->redirects = ngx_array_create(cf->pool, 4,
                                    sizeof(ngx_http_internal_redirect_entry_t));
        if (ilcf->redirects == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    redirect = ngx_array_push(ilcf->redirects);
    if (redirect == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(redirect, sizeof(ngx_http_internal_redirect_entry_t));

    value = cf->args->elts;
    redirect->target = value[cf->args->nelts - 1];

    if (redirect->target.data[0] != '@' && redirect->target.data[0] != '/') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid redirect target \"%V\"", &redirect->target);
        return NGX_CONF_ERROR;
    }

    cf->args->nelts--;

    if (ngx_http_internal_redirect_if_condition(cf, redirect) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    imcf = ngx_http_conf_get_module_main_conf(cf,
                                             ngx_http_internal_redirect_module);
    imcf->required = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_internal_redirect_if_condition(ngx_conf_t *cf,
    ngx_http_internal_redirect_entry_t *redirect)
{
    u_char                        *p;
    size_t                         len;
    ngx_str_t                     *value;
    ngx_uint_t                     cur, last;
    ngx_regex_compile_t            rc;
    ngx_http_script_code_pt       *code;
    ngx_http_script_file_code_t   *fop;
    ngx_http_script_regex_code_t  *regex;
    u_char                         errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return NGX_CONF_ERROR;
    }

    if (value[last].len == 1) {
        last--;

    } else {
        value[last].len--;
        value[last].data[value[last].len] = '\0';
    }

    len = value[cur].len;
    p = value[cur].data;

    if (len > 1 && p[0] == '$') {

        if (cur != last && cur + 2 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_internal_redirect_if_condition_value(cf, redirect, 
                                                          &value[cur])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (cur == last) {
            return NGX_CONF_OK;
        }

        cur++;

        len = value[cur].len;
        p = value[cur].data;

        if (len == 1 && p[0] == '=') {
            if (ngx_http_internal_redirect_if_condition_value(cf, redirect, 
                                                              &value[last])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            code = ngx_http_script_start_code(cf->pool, &redirect->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NGX_CONF_ERROR;
            }

            *code = ngx_http_script_equal_code;

            return NGX_CONF_OK;
        }

        if (len == 2 && p[0] == '!' && p[1] == '=') {

            if (ngx_http_internal_redirect_if_condition_value(cf, redirect, 
                                                              &value[last])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            code = ngx_http_script_start_code(cf->pool, &redirect->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NGX_CONF_ERROR;
            }

            *code = ngx_http_script_not_equal_code;
            return NGX_CONF_OK;
        }

        if ((len == 1 && p[0] == '~')
            || (len == 2 && p[0] == '~' && p[1] == '*')
            || (len == 2 && p[0] == '!' && p[1] == '~')
            || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
        {
            regex = ngx_http_script_start_code(cf->pool, &redirect->codes,
                                          sizeof(ngx_http_script_regex_code_t));
            if (regex == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));
            
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

            rc.pattern = value[last];
            rc.options = (p[len - 1] == '*') ? NGX_REGEX_CASELESS : 0;
            rc.err.len = NGX_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = ngx_http_regex_compile(cf, &rc);
            if (regex->regex == NULL) {
                return NGX_CONF_ERROR;
            }

            regex->code = ngx_http_script_regex_start_code;
            regex->next = sizeof(ngx_http_script_regex_code_t);
            regex->test = 1;
            if (p[0] == '!') {
                regex->negative_test = 1;
            }
            regex->name = value[last];

            return NGX_CONF_OK;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unexpected \"%V\" in condition", &value[cur]);
        return NGX_CONF_ERROR;

    } else if ((len == 2 && p[0] == '-')
               || (len == 3 && p[0] == '!' && p[1] == '-'))
    {
        if (cur + 1 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        value[last].data[value[last].len] = '\0';
        value[last].len++;

        if (ngx_http_internal_redirect_if_condition_value(cf, redirect,
                                                          &value[last])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        fop = ngx_http_script_start_code(cf->pool, &redirect->codes,
                                         sizeof(ngx_http_script_file_code_t));
        if (fop == NULL) {
            return NGX_CONF_ERROR;
        }

        fop->code = ngx_http_script_file_code;

        if (p[1] == 'f') {
            fop->op = ngx_http_script_file_plain;
            return NGX_CONF_OK;
        }

        if (p[1] == 'd') {
            fop->op = ngx_http_script_file_dir;
            return NGX_CONF_OK;
        }

        if (p[1] == 'e') {
            fop->op = ngx_http_script_file_exists;
            return NGX_CONF_OK;
        }

        if (p[1] == 'x') {
            fop->op = ngx_http_script_file_exec;
            return NGX_CONF_OK;
        }

        if (p[0] == '!') {
            if (p[2] == 'f') {
                fop->op = ngx_http_script_file_not_plain;
                return NGX_CONF_OK;
            }

            if (p[2] == 'd') {
                fop->op = ngx_http_script_file_not_dir;
                return NGX_CONF_OK;
            }

            if (p[2] == 'e') {
                fop->op = ngx_http_script_file_not_exists;
                return NGX_CONF_OK;
            }

            if (p[2] == 'x') {
                fop->op = ngx_http_script_file_not_exec;
                return NGX_CONF_OK;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[cur]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return NGX_CONF_ERROR;
}


static char *
ngx_http_internal_redirect_if_condition_value(ngx_conf_t *cf,
    ngx_http_internal_redirect_entry_t *redirect, ngx_str_t *value)
{
    ngx_int_t                              n;
    ngx_http_script_compile_t              sc;
    ngx_http_script_value_code_t          *val;
    ngx_http_script_complex_value_code_t  *complex;

    n = ngx_http_script_variables_count(value);

    if (n == 0) {
        val = ngx_http_script_start_code(cf->pool, &redirect->codes,
                                         sizeof(ngx_http_script_value_code_t));
        if (val == NULL) {
            return NGX_CONF_ERROR;
        }

        n = ngx_atoi(value->data, value->len);

        if (n == NGX_ERROR) {
            n = 0;
        }

        val->code = ngx_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return NGX_CONF_OK;
    }

    complex = ngx_http_script_start_code(cf->pool, &redirect->codes,
                                  sizeof(ngx_http_script_complex_value_code_t));
    if (complex == NULL) {
        return NGX_CONF_ERROR;
    }

    complex->code = ngx_http_script_complex_value_code;
    complex->lengths = NULL;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &redirect->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_internal_redirect_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt                     *h;
    ngx_http_core_main_conf_t               *cmcf;
    ngx_http_internal_redirect_main_conf_t  *imcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    imcf = ngx_http_conf_get_module_main_conf(cf, 
                                             ngx_http_internal_redirect_module);

    if (imcf->required) {
        h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }
    
        *h = ngx_http_internal_redirect_handler;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_internal_redirect_handler(ngx_http_request_t *r)
{
    ngx_uint_t                               i;
    ngx_http_script_code_pt                  code;
    ngx_http_script_engine_t                 e;
    ngx_http_variable_value_t                stack[10];
    ngx_http_internal_redirect_entry_t      *redirects;
    ngx_http_internal_redirect_main_conf_t  *imcf;
    ngx_http_internal_redirect_loc_conf_t   *ilcf;
    ngx_http_core_main_conf_t               *cmcf;
    ngx_http_phase_handler_t                *ph, *cur_ph, *last_ph, tmp;

    imcf = ngx_http_get_module_main_conf(r, ngx_http_internal_redirect_module);

    if (!imcf->postponed) {

        imcf->postponed = 1;

        cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

        ph = cmcf->phase_engine.handlers;
        cur_ph = &ph[r->phase_handler];
        last_ph = &ph[cur_ph->next - 1];

        if (cur_ph < last_ph) {
            tmp = *cur_ph;

            ngx_memmove(cur_ph, cur_ph + 1,
                        (last_ph - cur_ph) * sizeof(ngx_http_phase_handler_t));

            *last_ph = tmp;
            r->phase_handler--; /* redo the current ph */

            return NGX_DECLINED;
        }
    }

    ilcf = ngx_http_get_module_loc_conf(r, ngx_http_internal_redirect_module);

    if (ilcf->redirects == NULL) {
        return NGX_DECLINED;
    }

    redirects = ilcf->redirects->elts;
    for (i = 0; i < ilcf->redirects->nelts; i++) {
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
        ngx_memzero(&stack, sizeof(stack));

        e.sp = stack;
        e.ip = redirects[i].codes->elts;
        e.request = r;
        e.quote = 1;
        e.log = 1;
        e.status = NGX_DECLINED;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code(&e);
        }

        e.sp--;

        if (e.sp->len && (e.sp->len != 1 || e.sp->data[0] != '0')) {
            break;
        }
    }

    if (i == ilcf->redirects->nelts) {
        return NGX_DECLINED;
    }

    if (redirects[i].target.data[0] == '@') {

        (void) ngx_http_named_location(r, &redirects[i].target);

    } else {
        (void) ngx_http_internal_redirect(r, &redirects[i].target, &r->args);
    }

    ngx_http_finalize_request(r, NGX_DONE);

    return NGX_OK;
}


static void *
ngx_http_internal_redirect_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_internal_redirect_main_conf_t  *imcf;

    imcf = ngx_pcalloc(cf->pool, 
                       sizeof(ngx_http_internal_redirect_main_conf_t));
    if (imcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *     imcf->required = 0;
     */

    imcf->postponed = NGX_CONF_UNSET;

    return imcf;
}


static char *
ngx_http_internal_redirect_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_internal_redirect_main_conf_t  *imcf = conf;

    if (imcf->postponed == NGX_CONF_UNSET) {
        imcf->postponed = 0;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_internal_redirect_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_internal_redirect_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_internal_redirect_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *     conf->redirects = NULL;
     */
    
    return conf;
}


static char *
ngx_http_internal_redirect_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_internal_redirect_loc_conf_t  *prev = parent;
    ngx_http_internal_redirect_loc_conf_t  *conf = child;

    ngx_conf_merge_ptr_value(conf->redirects, prev->redirects, NULL);

    return NGX_CONF_OK;
}
