# ping

[![Build Status](https://img.shields.io/travis/kelunik/ping/master.svg?style=flat-square)](https://travis-ci.org/kelunik/ping)
![Unstable](https://img.shields.io/badge/api-unstable-orange.svg?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

`kelunik/ping` is a non-blocking ping utility for use with the [`amp`](https://github.com/amphp/amp)
concurrency framework.

**Required PHP Version**

- PHP 5.5+

**Installation**

```bash
$ composer require kelunik/ping
```

**Permissions**

Your script either needs to be run as root or you have to add the raw socket capability to your PHP interpreter to allow
raw network sockets.

```bash
sudo bin/ping github.com
```

Some Unix based systems allow to set capabilities on interpreted files (`#!`), but most don't, so they require the
permission on the executable. You might want to use a small binary that starts PHP to allow that capability only where
needed. 

```bash
sudo setcap cap_net_raw+ep /path/to/php
```