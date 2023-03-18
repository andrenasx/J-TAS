from os import path
import re
import javalang

GITHUB_WORKSPACE = "/github/workspace/"

#* Action input related functions

def process_input_files(input):
    if not input:
        return ""
    
    files_temp = input.split()
    files = []

    # Check if the Java file exists in the repository
    for file in files_temp:
        abs_path = GITHUB_WORKSPACE + file

        if file.endswith(".java") and path.isfile(abs_path):
            files.append(abs_path)

    print(str(len(files)) + " input Java files found in the repository")
    return files

def process_input_paths(input):
    if not input:
        return ""
    
    paths_temp = input.split()
    paths = []

    # Check if the path exists in the repository
    for p in paths_temp:
        abs_path = GITHUB_WORKSPACE + p

        if path.isdir(abs_path):
            paths.append(abs_path)

    print(str(len(paths)) + " input paths found in the repository")
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

def flatten_list(zipped):
    return [item for sublist in zipped for item in sublist] # Flatten list

def remove_duplicate_labels(labels):
    d = {}
    for x, y in labels:
        if y not in d:
            d[y] = x
    
    return [(k, v) for k, v in d.items()]


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
