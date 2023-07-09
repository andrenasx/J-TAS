# J-TAS (Java Transformer-based Automated Scanner)

This action analysis Java files using a Deep Learning model and generates a report in [Static Analysis Results Interchange Format (SARIF)](https://www.oasis-open.org/standard/sarif-v2-1-0/). The results can be seen in the *Security tab* of your repository.

We recommend using the [actions/checkout](https://github.com/marketplace/actions/checkout) action to check out your repository, and [github/codeql-action/upload-sarif](https://github.com/github/codeql-action/tree/main/upload-sarif) to upload the SARIF file. For more information on their usage, check the respective READMEs.

## Usage

<!-- start usage -->
```yaml
- uses: andrenasx/J-TAS@main
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

When no `paths` nor `files` are provided, the action will analyze all Java files in the repository.

## Workflow examples

- [Analyse the whole repository](#Analyse-the-repository-on-every-push)
- [Analyse specific files](#Analyse-specific-files)
- [Analyse specific directories](#Analyse-specific-directories)
- [Analyse only the changed files in current commit](#Analyse-only-the-changed-files)

### Analyse the repository on every push

```yaml
on: [push]
name: J-TAS analysis

jobs:
  jtas-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout this repo code
        uses: actions/checkout@v3

      - name: Run J-TAS
        uses: andrenasx/J-TAS@main

      - name: Upload J-TAS report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```

### Analyse specific files

```yaml
on: [push]
name: J-TAS analysis

jobs:
  jtas-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout this repo code
        uses: actions/checkout@v3

      - name: Run J-TAS
        uses: andrenasx/J-TAS@main
        with:
          files: 'src/main/java/com/example/HelloWorld.java src/test/java/com/example/HelloWorldTest.java'

      - name: Upload J-TAS report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```

### Analyse specific directories

```yaml
on: [push]
name: J-TAS analysis

jobs:
  jtas-analysis:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout this repo code
        uses: actions/checkout@v3

      - name: Run J-TAS
        uses: andrenasx/J-TAS@main
        with:
          paths: 'src/main/java/com/controller src/main/java/com/service'

      - name: Upload J-TAS report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```

### Analyse only the changed files

```yaml
on: [push]
name: J-TAS analysis

jobs:
  jtas-analysis:
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

      - name: Run J-TAS
        uses: andrenasx/J-TAS@main
        with:
          files: ${{ steps.diff.outputs.files }}

      - name: Upload J-TAS report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
          category: my-analysis-tool
```
