ngx_conf_def
============
**ngx_conf_def** is a simple conf definition module for NginX, and brings "**def**", "**use_def**", "**def_data_file_group**", "**def_data_file_path**", "**def_data_file**" and "**conf_def_reload_data_file_group**" to Nginx config file. 

feature
==========================
* def support in Nginx config, facilitate and enjoy configuration.
* binary data file shm-memory management and on-line reload support.

directives
==========================
```nginx
  def LISTEN(num) "listen ${num};";      # LISTEN macro
  def L "@{LISTEN(2080)}";   # listen on 2080 port macro
  use_def L;                 # use listen on 2080 config
```

```nginx
  def_data_file_group seg_group{
    def_data_file kv1  kv1.data;
    def_data_file kv2  kv2.data;
    def_data_file kv3  kv3.data;
    def_data_file kv4  kv4.data;
    def_data_file_path /data/seg_group/;
  }
  
  def data_file_def(nick_name) "def_data_file ${nick_name} ${nick_name}.data; ";
  def_data_file_group another_group{
    use_def data_file_def(my_data1);
    use_def data_file_def(my_data2);
    def_data_file_path /data/another_group/
  }
```

```nginx
  location ~ /reload/(.*) {
    set $reload_data_file_group $1;     ## set reload data file group name
    conf_def_reload_data_file_group;    ## reload
  }
```

on-line reload commands
==========================
use the config above, the following command will reload another_group binary data files.
```sh
  curl "127.0.0.1:2080/realod/another_group"
```



