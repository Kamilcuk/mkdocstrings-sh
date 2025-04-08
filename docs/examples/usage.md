# Usage

In your mkdocs.yaml file include the following configuration:

```
plugins:
- mkdocstrings:
    default_handler: sh
    handlers:
      sh:
        options:

          # If includeregex is specified, this will include _ALL_ symbols matching this regex, also without any documentation.
          # I am using this to show all public symbols exported from a library, even those not explicitly documented.
          includeregex: "^L_.*$"

          # If excluderegex is specified, this will exclude all symbols that match this regex.
          excluderegex: "^_.*$"

          # If this is specified, an addititional item is displayed for every documentation element
          # that links to the source documentation.
          # This string is formatted wiht .format() python function.
          # Following variables are available:
          #  - {name} - the HTTP escaped name of the function or variable
          #  - {file} - the full path to the file
          #  - {line} - the line number of the function or variable
          source_url: "https://github.com/Kamilcuk/mkdocstrings-sh/blob/main/{file}#L{line}"
```
