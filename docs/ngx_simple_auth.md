[auth request module]: http://nginx.org/en/docs/http/ngx_http_auth_request_module.html
[auth basic module]: http://nginx.org/en/docs/http/ngx_http_auth_basic_module.html
# ngx\_simple\_auth

**ngx\_simple\_auth** is a module for nginx [auth request module] that authenticates with the account information in the configuration file.  
The purpose of this module is only to check the settings of nginx [auth request module].
For "Basic" authentication, please use nginx's [auth basic module].

Since it does not use external data for authentication, it can be used to check the settings of the nginx [auth request module].

## Error handling

On error, the process terminates with an unsuccessful status. 

## How to start

Run it on the command line like this:

```
ngx_simple_auth <config file>
```

Since it does not provide background execution functions such as daemonization,
start it via a process management system such as systemd.

## Configuration file format

See the [auth request module] documentation for how to configure nginx.

The **ngx\_simple\_auth** configuration file is in TOML format, and the following is a sample configuration file.

```ini
socket_type = "tcp"
socket_path = "127.0.0.1:9200"
#cache_seconds = 0
auth_realm = "TEST Authentication"

[password]
admin1 = "hoge"
user1 = "hogehoge"

#[response.ok]
#code=200
#message="Authorized"

#[response.unauth]
#code=401
#message="Not authenticated"
```

Each parameter of the configuration file is as follows.

### Root part

| Parameter | Description |
| :--- | :--- |
| **socket\_type** | Set this parameter to tcp(TCP socket) or unix(UNIX domain socket). |
| **socket\_path** | Set the IP address and port number for tcp, and UNIX domain socket file path for unix. |
| **cache\_seconds** | Cache duration in seconds passed to nginx upon successful authentication. If the value is 0, cache will not be used. <br>See [Authentication Cache Control](proxy_cache.md) for details. |
| **neg\_cache\_seconds** | Cache duration in seconds passed to nginx upon failed authentication. If the value is 0, cache will not be used. <br>See [Authentication Cache Control](proxy_cache.md) for details. |
| **use\_etag** | Set to `true` if you want to validate the cache using the `ETag` tag. <br>See [Authentication Cache Control](proxy_cache.md) for details. |
| **auth\_realm** | HTTP realm string. |
| **[password]** | User-password mapping data in TOML table format. |

### **\[response.ok\]** part

| Parameter | Description |
| :--- | :--- |
| **code** | The HTTP response status code indicates authorized requests. (Default value: `200`)<br>This value is used by the [auth request module]. Therefore, Malfunctions may be caused by the incorrect setting value. |
| **message** |  The HTTP response message indicates authorized requests. (Default value: `"Authorized"`) |

### **\[response.unauth\]** part

| Parameter | Description |
| :--- | :--- |
| **code** | The HTTP response status code indicates unauthenticated requests. (Default value: `401`)<br>This value is used by the [auth request module]. Therefore, Malfunctions may be caused by the incorrect setting value. |
| **message** | The HTTP response message indicates unauthenticated requests. (Default value: `"Not authenticated"`) |
