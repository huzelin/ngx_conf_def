ngx_conf_def
============
ngx_conf_def is a simple conf definition module for NginX

## Directives:
* **def**
```sh
syntax: def macro_func def_config_str
default: none
context: http, server, location
description: define def_config_str as macro_func, take for example: def LS(num) "listen ${num};"; means LS(num) is listen port on num.  
```
* **use_def**
```sh
syntax: use_def macro_func(func_args)
default: none
context: http, server, location
description: use def config. take for example: use_def LS(2004); means use listen on port 2004.
```
*  **def_cfg_block**
```sh
syntax: def_cfg_block cfg_block_name
default: none
context: http, server, location
description: define cfg block, in blocks key-value pair will be configured.
```
*  **def_data_file_group**
```sh
syntax: def_data_file_group group_name
default: none
context: http, server, location
description: define data file group for management.
```
*  **def_data_file_path**
```sh
syntax: def_data_file_path file_path
default: none
context: http, server, location
description: define data file path for management
```
*  **def_data_file**
```sh
syntax: def_data_file file_name
default: none
context: http, server, location
description: define data file name for management
```
