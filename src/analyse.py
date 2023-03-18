from dotenv import load_dotenv
from os import getenv
import sys

import json
import glob

import torch
from transformer import getModel, getTokenizer, getMultilabelBinarizer, process_sequence, get_labels
from utils import clean_code, flatten_list, remove_duplicate_labels, get_file_methods, GITHUB_WORKSPACE, process_input_files, process_input_paths


# Load model, tokenizer and multilabel binarizer
load_dotenv()
model = getModel(getenv("MODEL_PATH"))
tokenizer = getTokenizer()
mlb = getMultilabelBinarizer(getenv("BINARIZER_PATH"))

# CWEs: 15, 23, 36, 78, 80, 89, 90, 113, 129, 134, 190, 191, 197, 319, 369, 400, 470, 606, 643, 690, 789
CWE_DESC = {
    "15": "One or more system settings or configuration elements can be externally controlled by a user.",
    "23": "The product uses external input to construct a pathname that should be within a restricted directory, but it does not properly neutralize sequences such as \"..\" that can resolve to a location that is outside of that directory.",
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
    "606": "The product does not properly check inputs that are used for loop conditions, potentially leading to a denial of service or other consequences because of excessive looping.",
    "643": "The product uses external input to dynamically construct an XPath expression used to retrieve data from an XML database, but it does not neutralize or incorrectly neutralizes that input. This allows an attacker to control the structure of the query.",
    "690": "The product does not check for an error after calling a function that can return with a NULL pointer if the function fails, which leads to a resultant NULL pointer dereference.",
    "789": "The product allocates memory based on an untrusted, large size value, but it does not ensure that the size is within expected limits, allowing arbitrary amounts of memory to be allocated."
}


def file():
    results = []
    files = set()

    # Load the template SARIF file
    with open("./sarif/template.sarif") as f:
        results_sarif = json.load(f)

    print("\n\t===== VDET Analysis =====\n")

    # Process Action inputs
    input_paths = process_input_paths(sys.argv[1])
    input_files = process_input_files(sys.argv[2])

    # DEFAULT: Get all repo files if no input is provided
    if not input_files and not input_paths:
        files.update(glob.glob(GITHUB_WORKSPACE + '/**/*.java', recursive=True))
        print("Analyzing all Java files in this repository.")

    else:
        if input_paths:
            for p in input_paths:
                files.update(glob.glob(p + '/**/*.java', recursive=True))
                print("Analyzing all Java files in " + p)

        if input_files:
            files.update(input_files)
            print("Analyzing specific Java files: " + str(input_files))

    # Iterate through all the files
    for target_file in files:
        methods = get_file_methods(target_file)      
        
        # Iterate through all the methods in the file
        for method in methods:
            code = clean_code(method['code'])
            methodname = method['name']
            startline = method['startline']
            endline = method['endline']

            # Get only first 500 tokens from the code
            code = code[:500]

            encodings = tokenizer.encode_plus(
                code,
                add_special_tokens=False,
                return_tensors='pt')

            input_ids, attn_mask = process_sequence(encodings)

            # Stack lists so that it can be passed to the transformer
            stacked_input_ids = (torch.stack(input_ids, 0)).type(torch.LongTensor)
            stacked_attn_masks = torch.stack(attn_mask, 0)

            # Get predictions
            outputs = model(ids=stacked_input_ids, mask=stacked_attn_masks)
            labels = get_labels(mlb, outputs)

            flatten = flatten_list(labels)
            noDup_labels = remove_duplicate_labels(flatten)

            # Ignore if method is not vulnerable or if no CWE is predicted
            if noDup_labels[0][0] == "False" or noDup_labels[0][0] == "True" or noDup_labels[1][0] == "False":
                continue

            # Add the current method result to the list
            results.append({
                "ruleId": "VDET/CWE-" + noDup_labels[0][0],
                "message": {
                    "text": "CWE-" + noDup_labels[0][0] + " predicted with " + str(round(float(noDup_labels[0][1])*100, 2)) + "% probability. " +  CWE_DESC[noDup_labels[0][0]]
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_file.removeprefix(GITHUB_WORKSPACE),
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": startline,
                                "endLine": endline,
                            }
                        }
                    }
                ]

            })

    # Update the results in the SARIF file
    results_sarif['runs'][0].update({"results": results})

    print("Total number of vulnerabilities found: " + str(len(results)))

    with open("./results.sarif", "w") as f:
        json.dump(results_sarif, f, indent=2)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Please provide the input paths and files as arguments (empty string if none).")
        sys.exit(1)

    file()