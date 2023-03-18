# VDET-Action-test

This action analysis Java files and generates a report in [Static Analysis Results Interchange Format (SARIF) format](https://www.oasis-open.org/standard/sarif-v2-1-0/).

We recommend using the [actions/checkout](https://github.com/marketplace/actions/checkout) action to check out your repository, and [github/codeql-action/upload-sarif](https://github.com/github/codeql-action/tree/main/upload-sarif) to upload the SARIF file. For more information on their usage, check the respective READMEs.

# Usage

<!-- start usage -->
```yaml
- uses: andrenasx/VDET-Action-test@main
  with:
    # Paths to the directories containing the Java source files to analyze.
    # These paths are relative to the root of the repository, and separated by spaces when multiple paths are provided.
    # Example: 'src/main/java src/test/java'
    # Default: ''
    paths: ''

    # Paths of the the Java source files to analyze.
    # These paths are relative to the root of the repository, and separated by spaces when multiple paths are provided.
    # Example: 'src/main/java/example/HelloWorld.java src/test/java/example/HelloWorldTest.java'
    # Default: ''
    files: ''
```
<!-- end usage -->

When no `paths` or `files` are provided, the action will analyze all Java files in the repository.

# Workflow examples

- [Analyse the whole repository](#Analyse-the-repository-on-every-push)
- [Analyse specific files](#Analyse-specific-files)
- [Analyse specific directories](#Analyse-specific-directories)
- [Analyse only the changed files](#Analyse-only-the-changed-files)

## Analyse the repository on every push

```yaml
on: [push]
name: VDET Action Test

jobs:
  vdet-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout this repo code
        uses: actions/checkout@v3

      - name: Run VDET
        uses: andrenasx/VDET-Action-test@main

      - name: Upload VDET report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```

## Analyse specific files

```yaml
on: [push]
name: VDET Action Test

jobs:
  vdet-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout this repo code
        uses: actions/checkout@v3

      - name: Run VDET
        uses: andrenasx/VDET-Action-test@main
        with:
          files: 'src/main/java/com/example/HelloWorld.java src/test/java/com/example/HelloWorldTest.java'

      - name: Upload VDET report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```

## Analyse specific directories

```yaml
on: [push]
name: VDET Action Test

jobs:
  vdet-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout this repo code
        uses: actions/checkout@v3

      - name: Run VDET
        uses: andrenasx/VDET-Action-test@main
        with:
          paths: 'src/main/java/com/example/HelloWorld.java src/test/java/com/example/HelloWorldTest.java'

      - name: Upload VDET report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```

## Analyse only the changed files

```yaml
on: [push]
name: VDET Action Test

jobs:
  vdet-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository code
        uses: actions/checkout@v3
        with:
          fetch-depth: 2

      - name: Process files changed in the current commit
        id: diff
        run: |
          changedFiles=$(git diff --name-only HEAD^)
          echo "files=${changedFiles//$'\n'/ }" >> "$GITHUB_OUTPUT"

      - name: Run VDET
        uses: andrenasx/VDET-Action-test@main
        with:
          files: ${{ steps.diff.outputs.files }}

      - name: Upload VDET report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```
