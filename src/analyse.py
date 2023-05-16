from dotenv import load_dotenv
from os import getenv
import sys

import json
from glob import glob

import torch
from transformer import getModel, getTokenizer, getMultilabelBinarizer, process_sequence, get_labels
from utils import clean_code, flatten_list, remove_duplicate_labels, get_file_methods, get_workspace, get_CWEs_description, process_input_files, process_input_paths

def analyse():
    # Load model, tokenizer and multilabel binarizer
    load_dotenv()
    model = getModel(getenv("MODEL_PATH"))
    tokenizer = getTokenizer()
    mlb = getMultilabelBinarizer(getenv("BINARIZER_PATH"))

    GITHUB_WORKSPACE = get_workspace()
    CWE_DESC = get_CWEs_description()

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
        files.update(glob(GITHUB_WORKSPACE + '/**/*.java', recursive=True))
        print("Analyzing all Java files in this repository.")

    else:
        if input_paths:
            for p in input_paths:
                files.update(glob(p + '/**/*.java', recursive=True))
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

    analyse()