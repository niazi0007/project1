import sys, os
import logging
import re
from textwrap import indent
import json
import traceback

try:
    from lib.vdt_base import Base, CheckSkipped
    from cfg.vdt_defaults import DEFAULT_LOGDIR, LOGNAME
except:
    from vdt_base import Base

templogdir = os.getcwd()
logger = logging.getLogger(__name__)

def escape_ansi(line):
    """
    Remove ANSI escape sequences from a line of text.

    Args:
        line (str): The input line of text.

    Returns:
        str: The input line with ANSI escape sequences removed.
    """    
    if line != "":
        try:
            ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
            return ansi_escape.sub('', line)
        except:
            pass
    else:
        return line


def ind(string, times, singdent='  '):
    """
    Indent a string by a specified number of times.

    Args:
        string (str): The string to be indented.
        times (int): The number of times to indent the string.
        singdent (str, optional): The string used as a single level of indentation. Defaults to '  '.

    Returns:
        str: The indented string.

    Raises:
        None
    """    
    singdent = '    '
    return indent(string, times * singdent)

class bcolors:
    """
    A class representing a set of color codes.

    Attributes:
        HEADER (str): The code for the header color.
        OKBLUE (str): The code for the OK blue color.
        INFO (str): The code for the info color.
        OKCYAN (str): The code for the OK cyan color.
        OKGREEN (str): The code for the OK green color.
        WARNING (str): The code for the warning color.
        FAIL (str): The code for the fail color.
        ENDC (str): The code for the end color.
        BOLD (str): The code for the bold style.
        UNDERLINE (str): The code for the underline style.
    """    
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    INFO = '\033[96m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[32m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ColorWrap(object):



    """
    A class representing a color wrapper for console output.

    Methods:
        title(input_string): Returns a formatted title string.
        heading(input_string): Returns a formatted heading string.
        subheading(input_string): Returns a formatted subheading string.
        fail(input_string): Returns a formatted fail string.
        ok(input_string): Returns a formatted ok string.
        warn(input_string): Returns a formatted warning string.
        info(input_string): Returns a formatted info string.
    """

    @staticmethod
    def title(input_string):
        """
        Create a title for a given string.

        Args:
            input_string (str): The input string to be converted into a title.

        Returns:
            str: The titleized version of the input string.
        """        
        length = len(input_string)
        length = length + 6
        topline = '_' * length
        new_string = bcolors.OKCYAN + bcolors.UNDERLINE + topline + "\n   " + input_string.upper() + "   \n" + bcolors.ENDC
        return new_string

    @staticmethod
    def heading(input_string):
        """
        Format a string as a bold, cyan, and underlined heading.

        Args:
            input_string (str): The string to be formatted.

        Returns:
            str: The formatted string.
        """        
        return bcolors.BOLD + bcolors.OKCYAN + bcolors.UNDERLINE + f"{input_string}" + bcolors.ENDC

    @staticmethod
    def subheading(input_string):
        """
        Create a subheading with bold text.

        Args:
            input_string (str): The string to be formatted as a subheading.

        Returns:
            str: The input string formatted as a subheading with bold text.
        """        
        return bcolors.BOLD + f"\u2022 {input_string}" + bcolors.ENDC
    @staticmethod
    def fail(input_string):

        """
        Return the input string formatted with a fail color.

        Args:
            input_string (str): The string to be formatted.

        Returns:
            str: The input string formatted with fail color.
        """        
        return bcolors.FAIL + input_string + bcolors.ENDC

    @staticmethod
    def ok(input_string):
        """
        Converts the input string to a colorized string using the OKGREEN color code.

        Args:
            input_string(str): The string to be colorized.

        Returns:
            str: The colorized string.
        """        
        return bcolors.OKGREEN + input_string + bcolors.ENDC

    @staticmethod
    def warn(input_string):
        """
        Prints an input string in a warning format.

        Args:
            input_string (str): The string to be printed.

        Returns:
            str: The formatted string.
        """        
        return bcolors.WARNING + input_string + bcolors.ENDC

    @staticmethod
    def info(input_string):
        """
        Return a formatted info message.

        Args:
            input_string (str): The message to be formatted.

        Returns:
            str: The formatted info message.
        """        
        return bcolors.INFO + input_string + bcolors.ENDC


class Formatter(Base):


    def __init__(self, name="vdt_formatter", item_type=None, cfgfile=None, username=None, password=None):

        """
        Initialize a new instance of the class.

        Args:
            name (str): The name of the instance. Default is 'vdt_formatter'.
            item_type (str): The type of item. Default is None.
            cfgfile (str): The configuration file. Default is None.
            username (str): The user name. Default is None.
            password (str): The password. Default is None.

        Attributes:
            cats (list): A list of categories extracted from the configuration file.
            subcats (list): A list of subcategories extracted from the configuration file.
            checks (list): A list of checks extracted from the configuration file.
            check_total (int): The total number of checks.
            username (str): The user name passed as an argument.
            password (str): The password passed as an argument.
            cat_map (list): An empty list for mapping categories.
            report_output (str): An empty string to store the report output.
            report_json (list): An empty list to store the report in JSON format.
        """        
        super().__init__(name=name, item_type=item_type, cfgfile=cfgfile)
        self.cats = [section.replace(f"category:", "") for section in self.cfg if
                          section.startswith(f'category:')]
        self.subcats = [section.replace(f"subcategory:", "") for section in self.cfg if
                          section.startswith(f'subcategory:')]

        self.checks = [section.replace(f"check:", "") for section in self.cfg if
                          section.startswith(f'check:')]
        self.check_total = len(self.checks)
        self.username = username
        self.password = password
        self.cat_map = []
        self.report_output = ""
        self.report_json = []
        self.report_metadata = {'timestamp': self.timestamp}
        if self.cfg['vdt']:
            if self.cfg['vdt'].get('version'):
                self.report_metadata.update({'version': self.cfg['vdt'].get('version')})

    def cat_config(self, cat_type, cat_item):
        """
        Get current Task config from config data.
        Entries in the config file which match [product:<name>]
        Are considered products.
        The current product name is stored in self.product.

        Returns:
            dict: The current Task config.

        Raises:
            Exception: If cannot load Task Configuration.
        """
        output = self.cfg.get(f'{cat_type}:' + cat_item)
        if output is None:
            raise Exception(f'No configuration data found for item: {cat_item}.')
        logger.debug(f"CFG for {cat_item} is: {output}")
        return output

    def check_config(self, checkname):
        """
        Check the configuration value for a given check name.

        Args:
            self: The current object instance.
            checkname (str): The name of the check to retrieve the configuration for.

        Returns:
            The configuration value for the specified check.

        Raises:
            None.
        """        
        return self.item_config(checkname)

    def run_check(self, check):
        """
        Run a check and return the result.

        Args:
            self (object): The instance of the class.
            check (str): The name of the check to run.

        Returns:
            list: A list containing the output of the check.

        Raises:
            CheckSkipped: If the check timed out.
            Exception: If there was an error running the check.
        """        
        output = []
        try:

            check_output = self.run(check, self.username, self.password)

            if isinstance(check_output, list):
                new_output = {'title': self.cat_config('check', check).get('name'), 'checks': check_output}
                check_output = new_output

            else:

                if 'title' not in check_output.keys():
                    if 'heading' not in check_output.keys():
                        check_output.update({'title': self.cat_config('check', check).get('name')})

        except CheckSkipped:
            check_output = {'title': self.cat_config('check', check).get('name') + " (timed out)",
                            'result': 'FAIL'}


        except Exception as e:
            check_output = {'title': self.cat_config('check', check).get('name'),
                            'result': 'FAIL',
                            'details': traceback.format_exc()}
            # print(self.run(check, self.username, self.password))

        output.append(check_output)
        self.report_json.append(output)
        return output

    def get_checks(self, subcategory):
        """
        Get a list of checks that belong to a specific subcategory.

        Args:
            self: The object instance.
            subcategory (str): The subcategory name.

        Returns:
            list: A list of checks that belong to the specified subcategory.
        """        
        return [check for check in self.checks if subcategory == self.cat_config('check', check).get('parent_cat')]

    def get_subcats(self, category):
        """
        Get the subcategories and checks for a given category.

        Args:
            category: The parent category for which to retrieve subcategories and checks.

        Returns:
            tuple: A tuple containing two elements:
                - subcats (list): A list of subcategories that belong to the given category.
                - checks (list): A list of checks associated with the given category.

        Note:
            If no subcategories are found, subcats will be set to None.

        Raises:
            Exception: If an error occurs while retrieving subcategories.
        """        
        try:
            subcats = [subcat for subcat in self.subcats if category == self.cat_config('subcategory', subcat).get('parent_cat')]
        except:
            subcats = None
        checks = self.get_checks(category)
        return subcats, checks

    def build_cat(self, category, counter=0):

        """
        Build a category and its subcategories recursively.

        Args:
            category (str): The name of the category to build.
            counter (int, optional): The current recursion level.

        Returns:
            dict: A dictionary representing the built category and its subcategories.

        Raises:
            None.
        """        
        counter += 1
        if category in self.cats and category in self.subcats:
            print(f"ERROR!  {category} exists as both a category and subcategory!")
        elif category in self.cats:
            cat_type = 'category'
        elif category in self.subcats:
            cat_type = 'subcategory'
        else:
            print(f"ERROR!  Category {category} not found")

        cat_name = self.cat_config(cat_type, category).get('name')
        subcats, checks = self.get_subcats(category)
        if subcats:
            subcategories = {}
            for subcat in subcats:
                subcategories.update(self.build_cat(subcat, counter))
                output = {self.cat_config(cat_type, category).get('name'): {'subcategories': self.build_cat(subcat, counter),
                                                                            'checks': self.get_checks(category)}}
            return {cat_name: {'subcategories': subcategories, 'checks': checks}}
        else:
            output = {self.cat_config(cat_type, category).get('name'): {'subcategories': "",
                                                                          'checks': self.get_checks(category)}}
            return output

    def build_output(self):
        """
        Build the output by creating a map of categories.
        """        
        for cat in self.cats:
            self.cat_map.append(self.build_cat(cat))

    def build_json(self):
        """
        Build and print a JSON representation of the output.
        """        
        print(json.dumps(self.build_output(), indent=4))

    def report_and_print(self, data):
        """
        Print the input data and add it to the report output.

        Args:
            self: The instance of the class calling the function.
            data: The data to be printed and added to the report output.

        Returns:
            None

        Raises:
            None
        """        
        print(data)
        if isinstance(data, list):
            for item in data:
                self.report_output += item
        else:
            self.report_output += data

    def display_title(self, heading):
        """
        Display a title with a specified heading.

        Args:
            self: This parameter is not used in the function and is only included for compatibility with class methods.
            heading (str): The heading to be displayed as the title.

        Returns:
            str: The formatted title string.

        Raises:
            None.
        """        
        return "\n" + ColorWrap.title(heading) + "\n"

    def display_heading(self, heading, tab_count=1):
        """
        Display a heading with a specified tab count.

        Args:
            self: The instance of the class.
            heading (str): The heading to be displayed.
            tab_count (int, optional): The number of tabs to be added before and after the heading. Default is 1.

        Returns:
            str: The formatted heading with tabs.
        """        
        return "\n" + ind(ColorWrap.heading(heading), tab_count) + "\n"

    def display_subheading(self, subheading, tab_count=2):
        """
        Display a subheading with a given indentation level.

        Args:
            self: The current object.
            subheading (str): The subheading to be displayed.
            tab_count (int, optional): The number of tabs for indentation. Defaults to 2.

        Returns:
            str: The formatted subheading string.
        """        
        return "\n" + ind(ColorWrap.subheading(subheading), tab_count) + "\n"

    def display_info_check(self, title, **kwargs):
        """
        Displays information with a title and optional details.

        Args:
            self (object): The object calling the function.
            title (str): The title of the information.
            **kwargs: Additional keyword arguments to specify optional details.

        Returns:
            str: The formatted output of the information.

        Note:
            The 'result' keyword argument is ignored.

        Raises:
            None.
        """        
        output = ""
        title_output = f"{ColorWrap.info('[INFO]')}{ind(title,1)}"
        if 'result' in kwargs:
            kwargs.pop('result')

        for x,y in kwargs.items():
            if y:
                if x.lower() == 'details':
                    output += ind(f"\n{y}", 3)
                else:
                    output += ind(f"\n{x.capitalize()}: {ind(y, 1)}", 3)
        return ind(title_output + output, 1)

    def display_passfail_check(self, title, result, **kwargs):
        """
        Display a pass/fail check with additional details.

        Args:
            self: The instance of the class.
            title (str): The title of the check.
            result (str): The result of the check. Can be 'pass', 'fail' or 'warn'.
            **kwargs: Additional keyword arguments for displaying details.
                - details (str): Additional details to display.

        Returns:
            str: The formatted output of the pass/fail check.

        Note:
            The function uses the ColorWrap class for color formatting.

        Raises:
            None.
        """        
        output = ""

        if result.lower() in ['pass', 'ok', 'success']:
            check_result = ColorWrap.ok(f"[{result}]")
        elif result.lower() == "fail":
            check_result = ColorWrap.fail(f"[{result}]")
        elif 'warn' in result.lower():
            check_result = ColorWrap.warn(f"[{result}]")
        output += f"{check_result}{ind(title,1)}"
        for x,y in kwargs.items():
            if y:
                if x.lower() == 'details':
                    output += ind(f"\n{y}", 3)
                else:
                    output += ind(f"\n{x.capitalize()}: {ind(y, 1)}", 3)
                # output += ind(f"\n{x.capitalize()}: {y}", 3)

        return ind(output, 1)

    def format_check(self, check, tab_count=1):

        """
        Check the format of a result and display the corresponding output.

        Args:
            self (object): The current instance of the class.
            check (dict): A dictionary containing information about the check result, including the 'result' type.
            tab_count (int, optional): The number of tabs to use for indentation in the output. Default is 1.

        Returns:
            None

        Raises:
            SystemExit: If the 'result' type is not recognized.
        """        
        if check['result'].lower() in ['pass', 'ok', 'success', 'fail', 'warning', 'warn']:
            output = self.display_passfail_check(**check)

        elif check['result'].lower() == 'info':
            output = self.display_info_check(**check)

        else:
            print(f"Result type not found for result: {check['result']}")
            sys.exit()
        self.report_and_print(ind(output, tab_count + 1) + "\n")

    def display_checks(self, checks, tab_count=1):
        '''
        Args:
            checks (list): A list of checks to run.
            tab_count (int): The number of tabs to indent each check.

        Returns:
            Calls format_check to display the check, or report_and_print
            to display subheadings.
        '''

        for check in checks:
            try:
                if 'subheading' in check:
                    self.report_and_print(ind(self.display_subheading(check['subheading']), tab_count))
                    self.display_checks(check['checks'], tab_count + 1)
                else:
                    if 'checks' in check.keys():
                        self.display_checks(check['checks'], tab_count)
                    else:
                        self.format_check(check, tab_count)
            except Exception as e:
                print(traceback.format_exc())
                print(check)
                print(checks)

    def format(self, item, tab_count=0):
        '''
        Recursively formats the categories and checks within them. Runs each item.

        Args:
            item (dict): A dictionary containing the mapping of categories, subcategories, and checks.
            tab_count (int): The number of tabs. Increases for hierarchy.

        Returns:
            None. Recursively prints titles, headings, and checks.
        '''
        if isinstance(item, dict):
            for x, y in item.items():
                if tab_count == 0:
                    self.report_and_print(self.display_title(x))
                else:
                    self.report_and_print(ind(self.display_heading(x), tab_count))
                if len(y['checks']) > 0:
                    for check in y['checks']:
                        try:
                            self.display_checks(self.run_check(check), tab_count)
                        except Exception as e:
                            print(self.run_check(check))
                            logger.error(f"ERROR running {check}.  Error was {e}")
                            raise e

                if len(y['subcategories']) > 0:
                    tab_count += 1
                    for cat, subcat in y['subcategories'].items():
                        self.format({cat: subcat}, tab_count)
                else:
                    tab_count = tab_count - 1

        else:
            print(f"NOT A DICT: {item}")

    def generate_report(self, tofile: bool = False, header: str = None, interactive: bool = False):
        '''
        This function is called to generate the report and execute the checks.

        Args:
          tofile (bool): True will output to a file as well.
          header (str): If a header is required, we will write it.
          interactive (bool): Flag if you want to pause after every category.

        Returns:
          str: File path of the report.
        '''

        report = ""
        self.build_output()
        for item in self.cat_map:
            self.format(item)
            if interactive:
                input("Press Enter to continue...")
        if tofile:
            report = self.report_filename
            with open(self.report_filename, 'w') as f:
                if header:
                    f.write(escape_ansi(header))
                f.write(escape_ansi(self.report_output))
            self.report_metadata.update({'report': self.report_json})
            with open(f"{report}.json", 'w') as j:
                json.dump(self.report_metadata, j, indent=4)
        return report
