#!/usr/bin/env python
"""
__author__ = "Keenan Matheny"
__license__ = "SPDX-License-Identifier: MIT"
__status__ = "Beta"
__copyright__ = "Copyright (C) 2024 Broadcom Inc."

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
"""

import sys, os
import argparse
from lib.vdt_base import Base
from cfg.vdt_defaults import set_vdt_config
set_vdt_config()
cfgfile = os.path.join(os.path.dirname(__file__), 'cfg', 'vdt.ini')

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    ProductRunner = Base(name='vdt_main', item_type='product', cfgfile=cfgfile)
    help_msg = "\nAvailable Products:\n"
    default = ProductRunner.vdt_items[0]
    for item in ProductRunner.vdt_items:
        if default == item:
            item_name = f"{item} (default) "
        else:
            item_name = item
        help_msg += f"\n\t- {item_name}: {ProductRunner.item_config(item).get('help')}\n"
    help_msg += "\n"
    parser.add_argument('-p', "--product", choices=ProductRunner.vdt_items, default=ProductRunner.vdt_items[0], help=help_msg)

    args, unknown = parser.parse_known_args()
    if unknown:
        print("Invalid arguments detected.  Please review the help and try again")
        parser.print_help()
        sys.exit()
    if os.path.exists(ProductRunner.item_config(args.product).get('validation_dir')):
        ProductRunner.run(args.product)
    else:
        print("We have detected that the system on which you are running VDT is not of the product provided.  "
              "Please review the help and select the correct product.\n")
        parser.print_help()
        sys.exit()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)

