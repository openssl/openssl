# markdownlint style rules for OpenSSL

all

rule 'MD046', :style => :indented

exclude_rule 'MD004' # Unordered list style TODO(fix?)
exclude_rule 'MD005' # Inconsistent indentation for list items at the same level
exclude_rule 'MD006' # Consider starting bulleted lists at the beginning of the line
exclude_rule 'MD012' # Multiple consecutive blank lines
exclude_rule 'MD014' # Dollar signs used before commands without showing output
exclude_rule 'MD024' # Multiple headers with the same content
exclude_rule 'MD025' # Multiple top level headers in the same document
exclude_rule 'MD036'  # Emphasis used instead of a header
