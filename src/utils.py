from os import path
import re
import javalang

#* Action input related functions

def get_workspace():
    return "/github/workspace"

def get_labels():
    return [
        'Not Vuln',
        '15',
        '36',
        '78',
        '80',
        '89',
        '90',
        '113',
        '129',
        '134',
        '190',
        '191',
        '197',
        '319',
        '369',
        '400',
        '470',
        '476',
        '606',
        '643',
        '690',
        '789'
    ]

def get_CWEs_description():
    return {
        "15": "One or more system settings or configuration elements can be externally controlled by a user.",
        "36": "The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize absolute path sequences such as \"/abs/path\" that can resolve to a location that is outside of that directory.",
        "78": "The product constructs all or part of an OS command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended OS command when it is sent to a downstream component.",
        "80": "The product receives input from an upstream component, but it does not neutralize or incorrectly neutralizes special characters such as \"<\", \">\", and \"&\" that could be interpreted as web-scripting elements when they are sent to a downstream component that processes web pages.",
        "89": "The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.",
        "90": "The product constructs all or part of an LDAP query using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended LDAP query when it is sent to a downstream component.",
        "113": "The product receives data from an HTTP agent/component (e.g., web server, proxy, browser, etc.), but it does not neutralize or incorrectly neutralizes CR and LF characters before the data is included in outgoing HTTP headers.",
        "129": "The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position within the array.",
        "134": "The product uses a function that accepts a format string as an argument, but the format string originates from an external source.",
        "190": "The product performs a calculation that can produce an integer overflow or wraparound, when the logic assumes that the resulting value will always be larger than the original value. This can introduce other weaknesses when the calculation is used for resource management or execution control.",
        "191": "The product subtracts one value from another, such that the result is less than the minimum allowable integer value, which produces a value that is not equal to the correct result.",
        "197": "Truncation errors occur when a primitive is cast to a primitive of a smaller size and data is lost in the conversion.",
        "319": "The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.",
        "369": "The product divides a value by zero.",
        "400": "The product does not properly control the allocation and maintenance of a limited resource, thereby enabling an actor to influence the amount of resources consumed, eventually leading to the exhaustion of available resources.",
        "470": "The application uses external input with reflection to select which classes or code to use, but it does not sufficiently prevent the input from selecting improper classes or code.",
        "476": "A NULL pointer dereference occurs when the application dereferences a pointer that it expects to be valid, but is NULL, typically causing a crash or exit.",
        "606": "The product does not properly check inputs that are used for loop conditions, potentially leading to a denial of service or other consequences because of excessive looping.",
        "643": "The product uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input. This allows an attacker to control the structure of the query.",
        "690": "The product does not check for an error after calling a function that can return with a NULL pointer if the function fails, which leads to a resultant NULL pointer dereference.",
        "789": "The product allocates memory based on an untrusted, large size value, but it does not ensure that the size is within expected limits, allowing arbitrary amounts of memory to be allocated."
    }

def process_input_files(workspace, input):
    if not input:
        return ""
    
    files_temp = input.split()
    files = []

    # Check if the Java file exists in the repository
    for file in files_temp:
        abs_path = workspace + file

        if not file.endswith(".java"):
            print("File '" + file + "' is not a Java file. Ignoring...")

        elif path.isfile(abs_path):
            files.append(abs_path)

        else:
            print("File '" + file + "' not found in the repository")

    return files

def process_input_paths(workspace, input):
    if not input:
        return ""
    
    paths_temp = input.split()
    paths = []

    # Check if the path exists in the repository
    for p in paths_temp:
        abs_path = workspace + p

        if path.isdir(abs_path):
            paths.append(abs_path)
        else:
            print("Path '" + p + "' not found in the repository. Ignoring...")

    return paths


#* Code related functions

def remove_comments(string):
    pattern = r"(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)"
    # first group captures quoted strings (double or single)
    # second group captures comments (//single-line or /* multi-line */)
    regex = re.compile(pattern, re.MULTILINE|re.DOTALL)
    def _replacer(match):
        # if the 2nd group (capturing comments) is not None,
        # it means we have captured a non-quoted (real) comment string.
        if match.group(2) is not None:
            return "" # so we will return empty to remove the comment
        else: # otherwise, we will return the 1st group
            return match.group(1) # captured quoted-string
    return regex.sub(_replacer, string)

def clean_code(code):
    # Remove comments
    code = remove_comments(code)

    # Replace consecutive newlines with a single newline in code, and newlines with spaces in code
    code = code.strip()
    code = re.sub(r'\s+',' ', code)

    return code


#* Java methods related functions
## From: https://github.com/c2nes/javalang/issues/49#issuecomment-915417079

def get_method_start_end(tree, method_node):
    startpos  = None
    endpos    = None
    startline = None
    endline   = None
    for path, node in tree:
        if startpos is not None and method_node not in path:
            endpos = node.position
            endline = node.position.line if node.position is not None else None
            break
        if startpos is None and node == method_node:
            startpos = node.position
            startline = node.position.line if node.position is not None else None
    return startpos, endpos, startline, endline

def get_method_text(codelines, startpos, endpos, startline, endline, last_endline_index):
    if startpos is None:
        return "", None, None, None
    else:
        startline_index = startline - 1 
        endline_index = endline - 1 if endpos is not None else None 

        # 1. check for and fetch annotations
        if last_endline_index is not None:
            for line in codelines[(last_endline_index + 1):(startline_index)]:
                if "@" in line: 
                    startline_index = startline_index - 1
        meth_text = "<ST>".join(codelines[startline_index:endline_index])
        meth_text = meth_text[:meth_text.rfind("}") + 1] 

        # 2. remove trailing rbrace for last methods & any external content/comments
        # if endpos is None and 
        if not abs(meth_text.count("}") - meth_text.count("{")) == 0:
            # imbalanced braces
            brace_diff = abs(meth_text.count("}") - meth_text.count("{"))

            for _ in range(brace_diff):
                meth_text  = meth_text[:meth_text.rfind("}")]    
                meth_text  = meth_text[:meth_text.rfind("}") + 1]     

        meth_lines = meth_text.split("<ST>")  
        meth_text  = "".join(meth_lines)                   
        last_endline_index = startline_index + (len(meth_lines) - 1) 

        return meth_text, (startline_index + 1), (last_endline_index + 1), last_endline_index


def get_file_methods(target_file):
    with open(target_file, 'r') as r:
        codelines = r.readlines()
        code_text = ''.join(codelines)

    lex = None
    tree = javalang.parse.parse(code_text)    
    methods = []
    for _, method_node in tree.filter(javalang.tree.MethodDeclaration):
        startpos, endpos, startline, endline = get_method_start_end(tree, method_node)
        method_text, startline, endline, lex = get_method_text(codelines, startpos, endpos, startline, endline, lex)

        methods.append({"name": method_node.name, "code": method_text, "startline": startline, "endline": endline})
    
    return methods
