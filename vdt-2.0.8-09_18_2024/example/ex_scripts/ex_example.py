from lib.vdt_formatter import ColorWrap

def info_func():
    title = "INFO function"
    details = "main body of information here"
    result = "INFO"
    documentation = "(Optional) KB or relevant documentation goes here."
    return {'title': title, 'details': details, 'result': result, 'documentation': documentation}

def fail_func():
    title = "FAIL function"
    details = "(Optional) Details about the failure.  Raw findings, suggested commands, etc."
    result = "FAIL"
    documentation = "(Optional) kb for the issue goes here"
    return {'title': title, 'details': details, 'result': result, 'documentation': documentation}

def pass_func():
    title = "PASS function"
    details = f"(Optional) detail goes here.  {ColorWrap.info('Color')} can be {ColorWrap.ok('added')}"
    result = "PASS"
    documentation = "(Optional) kb goes here."
    return {'title': title, 'details': details, 'result': result, 'documentation': documentation}

def nested_func():
    results = []
    nested_funcs = ['func1', 'func2', 'func3']
    for x in nested_funcs:
        checks = [info_func(), fail_func(), pass_func()]
        results.append({'subheading': x, 'checks': checks})
    return results