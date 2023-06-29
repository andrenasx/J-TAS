from dotenv import load_dotenv
import sys

import json
from glob import glob

import torch
from transformer import getModel, getTokenizer, process_sequence, get_prediction
from utils import clean_code, get_file_methods, get_workspace, get_CWEs_description, get_labels, process_input_files, process_input_paths

def analyse(input_paths='', input_files=''):
    GITHUB_WORKSPACE = get_workspace()
    files = set()

    print("\n\t===== J-TAS Analysis =====\n")

    # DEFAULT: Get all repo files if no input is provided
    if not input_files and not input_paths:
        files.update(glob(GITHUB_WORKSPACE + '/**/*.java', recursive=True))

        if not files:
            print("There are no Java files in the repository to analyze. Exiting...")
            sys.exit(0)

        print("Analyzing all Java files in this repository...")

    else:
        # Process Action inputs
        input_paths = process_input_paths(GITHUB_WORKSPACE, input_paths)
        input_files = process_input_files(GITHUB_WORKSPACE, input_files)

        if input_paths:
            for p in input_paths:
                files.update(glob(p + '/**/*.java', recursive=True))
                print("Analyzing all Java files in " + p)

        if input_files:
            files.update(input_files)
            print("Analyzing specific Java files: " + str(input_files))
    
        if not files:
            print("There are no Java files to analyze given the inputs provided. Exiting...")
            sys.exit(0)


    # Load model and tokenizer
    load_dotenv()
    model = getModel('./models/model2-bpf_combined-multiclass-nodups_8.bin')
    tokenizer = getTokenizer()

    # Load CWE descriptions and labels
    CWE_DESC = get_CWEs_description()
    labels = get_labels()

    # Load the template SARIF file for results
    with open("./sarif/template.sarif") as f:
        results_sarif = json.load(f)

    results = []

    # Iterate through all the files
    for target_file in files:
        methods = get_file_methods(target_file)      
        
        # Iterate through all the methods in the file
        for method in methods:
            code = clean_code(method['code'])
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
            prob, pred = get_prediction(outputs)

            # Ignore if the prediction is "Not Vulnerable" (aka 0) or the probability is less than 50%
            if pred == 0 or prob <= 0.5:
                continue

            label = labels[pred]

            # Add the current method result to the list
            results.append({
                "ruleId": "VDET/CWE-" + label,
                "message": {
                    "text": "CWE-" + label + " predicted with " + str(round(float(prob)*100, 2)) + "% probability. " +  CWE_DESC[label]
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

    print("\nTotal number of vulnerabilities found: ", len(results))

    with open("./results.sarif", "w") as f:
        json.dump(results_sarif, f, indent=2)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        analyse()

    elif len(sys.argv) == 3:
        analyse(sys.argv[1], sys.argv[2])

    else:
        print("Please provide the *input paths* and *files* as arguments.")
        sys.exit(1)