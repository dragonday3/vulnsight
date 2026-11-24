# Container facts (collected 2026-11-25 from the running containers)

Raw configuration observations, one section per container. Every container
is reachable only on a private Docker network. A scanner connects to its
listed port with plain TCP. Unless a section says otherwise, no TLS
listener was found.

## bench-httpd: Apache httpd 2.4.49 (Unix), official-style image, port 80
- `Listen 80` only; no TLS listener.
- Every enabled `LoadModule` line:
  - MPM: mpm_event
  - auth and access: authn_file, authn_core, authz_host, authz_groupfile,
    authz_user, authz_core, access_compat, auth_basic
  - request and headers: reqtimeout, filter, headers, setenvif
  - content and directories: mime, autoindex, dir, alias
  - logging and other: log_config, env, version, unixd, status
- Not loaded:
  - proxy modules (mod_proxy*), mod_ssl, mod_http2;
  - mod_lua, mod_sed, mod_rewrite;
  - mod_cgi/cgid, mod_auth_digest, mod_deflate.
- Default document root; no extra config beyond the stock httpd.conf
  (`Include conf/extra/proxy-html.conf` is present, but the proxy modules
  it needs are not loaded).

## bench-tomcat: Apache Tomcat 8.5.19, port 8080
- Connectors enabled in server.xml:
  - HTTP/1.1 on 8080;
  - **AJP/1.3 on 8009** (enabled, default address).
  - The 8443 TLS connector is commented out, so there is no TLS.
- No HTTP/2 upgrade protocol configured.
- web.xml: default servlet with default settings (readonly true, no PUT).
  No CORS filter. No rewrite valve.
- Authentication: the default UserDatabaseRealm, wrapped in a
  LockOutRealm; no DIGEST or JASPIC configuration.
- Default webapps present: ROOT, docs, examples, host-manager, manager.
- Runs on Linux.

## bench-tomcat9: Apache Tomcat 9.0.30, port 8080
- Same as bench-tomcat:
  - HTTP/1.1 on 8080;
  - **AJP/1.3 on 8009 enabled**;
  - TLS connector commented out;
  - no HTTP/2, no CORS filter, no rewrite valve;
  - default servlet readonly;
  - default realms only;
  - default webapps.
- Runs on Linux.

## bench-nginx: nginx 1.13.2, port 80
- Built with: http_ssl, http_v2, mp4, gunzip, gzip_static, dav, flv,
  sub, mail, stream.
- The active configuration is the stock one:
  - one http block;
  - `include conf.d/*.conf` (the default server on port 80, plain HTTP);
  - no `ssl`, no `http2`, no `autoindex on`, no `resolver`, no `mp4`;
  - no proxy_pass.

## bench-nginx142: nginx 1.4.2 (built from source), port 80
- Configure arguments: `--with-http_ssl_module` (plus bundled pcre and
  zlib); default modules otherwise.
- nginx.conf: a single server on port 80, plain HTTP, `root html`, with
  index and error_page.
  - No ssl, http2/spdy, autoindex, resolver or proxy_pass.
  - No FastCGI/PHP configuration in this container.

## bench-es: Elasticsearch 1.4.2, HTTP API on port 9200
- elasticsearch-1.4.2.jar, lucene-core 4.10.2.
- **groovy-all-2.3.2.jar is bundled**: Groovy scripting is available.
- Dynamic scripting is left at the version's default.
- No plugins installed; elasticsearch.yml has no non-default settings.
- No security plugin (no Shield/X-Pack, no field/document-level
  security).
- Transport protocol port 9300 runs by default.
- No Hadoop/Spark connector. No ingest node (ingest doesn't exist in
  1.x).

## bench-es11: Elasticsearch 1.1.1, HTTP API on port 9200
- elasticsearch-1.1.1.jar, lucene-core 4.7.2.
- **No Groovy jar**: MVEL is the default scripting language.
- Dynamic scripting is left at the version's default.
- No plugins; no non-default settings; no security plugin.
- Transport port 9300 runs by default. No ingest, no Hadoop/Spark.

## bench-mysql: MySQL 5.5.23 (source build, /usr/local/mysql), port 3306
- `mysqld Ver 5.5.23 for Linux on x86_64`.
- No my.cnf with SSL settings was found, so SSL is not configured.
- Default plugins. Linux. Not a Gentoo or Debian package install.

## bench-php: Apache 2.4.10 (Debian) + PHP 5.4.1 as CGI, port 80
- Apache modules enabled:
  - access, auth and authz: access_compat, auth_basic, authn_core,
    authn_file, authz_core, authz_host, authz_user
  - content and directories: actions, alias, autoindex, dir, mime,
    negotiation
  - CGI and filtering: **cgid**, deflate, filter, env, setenvif
  - other: mpm_event, reqtimeout, status
- Not enabled: mod_ssl, mod_proxy*, mod_http2, mod_rewrite, mod_lua.
- PHP 5.4.1 is served through CGI (php-cgi).
- PHP modules: Core, ctype, curl, date, dom, ereg, fileinfo, filter,
  hash, iconv, json, libxml, mbstring, mysql, mysqlnd, openssl, pcre,
  PDO, pdo_sqlite, Phar, posix, readline, recode, Reflection, session,
  SimpleXML, SPL, sqlite3, standard, tokenizer, xml, xmlreader,
  xmlwriter, zlib.
- Not compiled: gd, intl, exif, soap, xmlrpc, ldap, imap, bz2, zip,
  calendar, sockets, pgsql. No FPM.

## bench-postgres: PostgreSQL 9.6.7, port 5432
- `listen_addresses = '*'`; no `ssl = on`, so SSL is off.
- pg_hba:
  - local connections and 127.0.0.1/::1: trust;
  - all other hosts: md5 password.
- Default extensions only. Linux.

## bench-jetty: Eclipse Jetty 9.4.37.v20210219, port 8080
- Distribution start.ini enables exactly these modules:
  - home-base-warning, ext, server, jsp, resources, deploy, jstl;
  - **websocket**;
  - **http** (HTTP/1.1 on 8080).
- Not enabled: http2, http2c, ssl/https/alpn (so no TLS), gzip
  (GzipHandler), jaspi, rewrite, proxy, and any authentication / login
  service (no DIGEST or BASIC auth configured).
- Default/demo webapps deployment only. Runs on Linux.
