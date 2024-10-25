# VDT
 ```                                                    
VVVVVVVV           VVVVVVVVDDDDDDDDDDDDD       TTTTTTTTTTTTTTTTTTTTTTT
V::::::V           V::::::VD::::::::::::DDD    T:::::::::::::::::::::T
V::::::V           V::::::VD:::::::::::::::DD  T:::::::::::::::::::::T
V::::::V           V::::::VDDD:::::DDDDD:::::D T:::::TT:::::::TT:::::T
 V:::::V           V:::::V   D:::::D    D:::::DTTTTTT  T:::::T  TTTTTT
  V:::::V         V:::::V    D:::::D     D:::::D       T:::::T        
   V:::::V       V:::::V     D:::::D     D:::::D       T:::::T        
    V:::::V     V:::::V      D:::::D     D:::::D       T:::::T        
     V:::::V   V:::::V       D:::::D     D:::::D       T:::::T        
      V:::::V V:::::V        D:::::D     D:::::D       T:::::T        
       V:::::V:::::V         D:::::D     D:::::D       T:::::T        
        V:::::::::V          D:::::D    D:::::D        T:::::T        
         V:::::::V         DDD:::::DDDDD:::::D       TT:::::::TT      
          V:::::V          D:::::::::::::::DD        T:::::::::T      
           V:::V           D::::::::::::DDD          T:::::::::T      
            VVV            DDDDDDDDDDDDD             TTTTTTTTTTT      

                      vSphere Diagnostic Tool
```

__status__ = "Beta"

## Quick Start

### Requirements

VDT requires Python 3.  VDT should exclusively run on/in the product for which you are developing.  No additional libraries should be added to the product, and no log analysis should be performed as part of a check.

### Configure Example Product

First, configure the product entry in vdt.ini.  Provide the path to the main script for the product, the help, a directory to help validate the product, and the config file for the product:
```
[product:example]
name = "example"
main_script = ${paths:root_path}/example/example.py
main_func = "main"
help = "VDT Example Product"
config_file = ${paths:root_path}/example/ex_cfg/example.ini
validation_dir = /some/path/here
```

### Configure Example Main script

Each product config file should contain version, title, paths, categories/subcategories, and checks in the following format

```
[vdt]
version = 1.0
title = "Example Product (v${version})"

[logging]
level = INFO
logdir = /var/log/vmware/vdt
logname = vdt.log

[paths]
root_path = "this should be that same as the main entry script (i.e. example.py)
scripts_path = ${root_path}/ex_scripts

[category:example]
name = "VDT Example - Top Category"

[subcategory:example1]
name = "VDT Example - Sub Category"
parent_cat = "example"

[check:info_function]
product = "example"
parent_cat = "example"
main_script = ${paths:scripts_path}/ex_example.py
main_func = "info_func"
timeout = 10
name = "Information Function"
```

### Write the Entry script

#### Import VDT Utilities
The VDT Formatter class will handle running the checks and formatting them into the report structure.  We will also utilize the logging function get_logger_enh, and the ColorWrap class for formatting the title of our product.  Import utilities used for logging and configuration parsing.

```
import os
import configparser
import logging
from lib.vdt_base import get_logger_enh
from lib.vdt_formatter import Formatter, ColorWrap
```

#### Set Up Config

The entry script should contain a function to set the logging parameters from the config file.  For this, we define our path to the config file and set the config

```
cfgfile = os.path.join(os.path.dirname(__file__), 'ex_cfg', 'example.ini')

logger = logging.getLogger(__name__)

def set_config():
    config = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
    config.read(cfgfile)
    config.set('paths', 'root_path', os.path.dirname(__file__))
    
	with open(cfgfile, 'w') as configfile:
        config.write(configfile)

    logdir = config['logging'].get('logdir')
    logname = config['logging'].get('logname')
    loglevel = config['logging'].get('level')
    get_logger_enh(loglevel, logdir, logname)
    return config
```

#### Write the Main Function
In the main function, we execute our setup, provide our title and header, and generate our report:

```
def main():

    config = set_config()

    title = ColorWrap.title(config['vdt'].get('title'))
    header = f"\n\tThis is the example application showcasing additional products for VDT.\n"

    print(title)
    print(header)

    Runner = Formatter(name=__name__, item_type='check', cfgfile=cfgfile)
    Runner.generate_report()
```

### Write a Check

Any check written should return a dictionary containing at least title and result.  Idealy, details and documentation should be included.  In ex_scripts, create example.py with the following:
```
def info_func():
    title = "INFO function"
    details = "main body of information here"
    result = "INFO"
    documentation = "(Optional) KB or relevant documentation goes here."
    return {'title': title, 'details': details, 'result': result, 'documentation': documentation}
```

### Configure the Check
In the example.ini file, we configure the categories under which the check will execute, as well as directions for VDT to run the check.  For this example, we will provide the top category called 'example'. We then configure the check to specify this category, as well as the path to the script and name of the entry function:
```
[category:example]
name = "VDT Example - Top Category"

[check:info_function]
product = "example"
parent_cat = "example"
main_script = ${paths:scripts_path}/ex_example.py
main_func = "info_func"
timeout = 10
name = "Information Function"
```

### Running the Example
Now run your example.  If everything is configured correctly, your product will now show in the help context of VDT:

```
# python vdt.py -h
usage: vdt.py [-h] [-p {vcenter,example}]

optional arguments:
  -h, --help            show this help message and exit
  -p {vcenter,example}, --product {vcenter,example}

                        Available Products:

                                - vcenter (default) : VDT for vCenter

                                - example: VDT Example Product

```

To run your report:

```
# python vdt.py -p example
______________________________
   "EXAMPLE PRODUCT (V1.0)"


        This is the example application showcasing additional products for VDT.

________________________________
   VDT EXAMPLE - TOP CATEGORY


        [INFO]    INFO function
                        main body of information here
                    Documentation:     (Optional) KB or relevant documentation goes here.
```

## Providing feedback
Please send feedback / feature requests to vcf-gs-sa-vdt.PDL@broadcom.com

## Disclosures
__license__ = "SPDX-License-Identifier: MIT"

__copyright__ = "Copyright (C) 2024 Broadcom Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in the 
Software without restriction, including without limitation the rights to use, 
copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the 
Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all 
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
