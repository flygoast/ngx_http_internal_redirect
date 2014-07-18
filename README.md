# NGINX HTTP Internal Redirect Module

## Introduction

The `ngx_http_internal_redirect_module` is used to make an internal redirect to the uri specified according to the condition specified.

## Synopsis

```nginx

    location / {
        internal_redirect_if ($request_method = 'FOO') @foo;
        internal_redirect_if ($request_method = 'BAR') /foo;
        internal_redirect_if ($request_method = 'BAZ') =200;
        internal_redirect_if ($request_method = 'QUZ') "$foo$bar";
        root html;
    }

    location @foo {
        return 200;
    }

    location /bar {
        return 200;
    }
```

## Directives

* **syntax**: *internal_redirect_if (condition) uri*
* **syntax**: *internal_redirect_if (condition) =code*
* **default**: --
* **context**: http, server, location

The specified `condition` is evaluated. If true, an internal redirect would be made to the `uri` specified in this directive. The syntax of condition is the same as it in the `if` directive in `rewrite` module. The syntax of `uri` is the same as it in the `try_files` directive.

* **syntax**: *internal_redirect_if_no_postponed  on|off*
* **default**: off
* **context**: http

Control whether or not to disable postpone the `internal_redirect_if` directives to run at the end of the `REWRITE` request-processing phase. By default, this directive is turned off.

## Installation

```shell
    cd nginx-**version**
    ./configure --add-module=/path/to/this/directory
    make
    make install
```

## Status

This module is compatible with following nginx releases:
- 1.2.6
- 1.2.7

Others are not tested.

## Author

FengGu <flygoast@126.com>
