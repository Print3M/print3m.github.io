---
title: Perl one-liners notes
---

## Manual

```bash
# Basic flags
-e <code>               # Execute one-liner
-E                      # Execute with additional features
-n                      # while(<>) {...} loop around program
-p                      # Like "-n" but print every line
-l                      # Print with \n at the end
-a                      # Split input line by whitespaces
-F <separator>          # Fields separator (char)

# Special vars
$_                      # Current line content
$.                      # Current line number
$$                      # Perl process ID
$&                      # String matched by the last pattern match
@F                      # Array of fields

# These make the same print
perl -e 'print "Hello world!\n"'
perl -le 'print "Hello world!"'
perl -E 'say "Hello world!"'

# BEGIN and END are called only once
perl -ne 'BEGIN { ... }; <code-code>; END { ... }'
perl -nE '$c++; END { say "lines = $c" }'

# Print "<line_number>: <line_content>"
perl -lne 'print "$.: $_"'

# `print` without argument assumes $_ var.
# These make the same print
perl -lne 'print'
perl -lne 'print $_'

# If statement
perl -lne 'print if $. == 7'
perl -lne 'print if $. == 7 || $. == 6'

# If-else statement
perl -lne '$. == 7 ? print "yes" : print "no"'

# Skip rest of the line: `next` keyword
# Exit the program: `exit` keyword
perl -lne 'next if $. == 4; print'  # Skip 4th line
perl -lne '$. == 4 ? exit : print'  # Exit after 4th line

# String substitution. First match:
echo "1:2:3" | perl -pe 's/:/-/'
# Globally
echo "1:2:3" | perl -pe 's/:/-/g'

# With special functions like "m" and "s" you can define
# your own delimiters (to avoid leaning toothpick syndrome)
m{test} == m~test~
s/test1/test2/ == s#test#test2#

# Field processing. Get second field (array of fields):
perl -F: -lnE 'say $F[1]'

# Execute external commands (backticks)
perl -E '$words = `wc -w text.txt`; say $words'
```

## Regex

```bash
# /REGEXP/FLAGS is a shortcut for $_ =~ m/REGEXP/FLAGS
# !/REGEXP/FLAGS is a shortcut for $_ !~ m/REGEXP/FLAGS
# Regex without argument assumes current line

# Print all lines not containing 'e'
perl -lne 'print if !/e/'
perl -lne 'print if $_ !~ m/e/'

# Select group (dolar-sign)
perl -lne '/(\d+):(\w+)/; print $1, $2'
```

## Examples

```bash
# List all users with corresponding groups
perl -F: -ne 'print("$. $F[0] | ", `groups $F[0]`)' /etc/passwd

# List files not owned by root
ls -al | perl -lane 'print if $F[2] !~ /root/ && $. > 1'

# Count lines of selected files
find . -type f -name "*.asm" | perl -lne '$c += `wc -l $_`; END { print "Lines: $c" }'
```
