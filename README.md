# ngx_http_internal_redirect_module

## Introduction

This module complete internal redirect according to conditions. This is what the `rewrite` can not do.

## Synopsis

    location / {
        ...
        internal_redirect_if ($method == 'FOO') @foo;
    }

    location @foo {
        ...
    }

## Directives

* **syntax**: ***internal_redirect_if*** (condition) <target>
* **default**: --
* **context**: http, server, location
    
The `target` is the redirect target. The `condition` is same as the `if`
directive in `rewrite` module.

* **syntax**: ***internal_redirect_if_no_postponed***  on|off
* **default**: off
* **context**: http

On default, this module will adjust the handler to the end of the REWRITE
phase. If tuned to `on`, would suppress this.

## Installation

    cd nginx-*version*
    ./configure --add-module=/path/to/this/directory
    make
    make install

## Status

This module is compatible with following nginx releases:
- 1.2.6
- 1.2.7
Others are not tested.

## Author

FengGu <flygoast@126.com>
