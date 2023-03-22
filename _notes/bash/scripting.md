---
title: Bash scripting notes
---

## Differences between Bash and sh features
- https://www.gnu.org/software/bash/manual/html_node/Major-Differences-From-The-Bourne-Shell.html

Bash is superset of sh. Sh is POSIX compliant, bash is not. Bash has many extra features which improve readability and speed of programming. Almost everything what does work on sh would be working on Bash as well, but not the other way.

#### Major differences (Bash vs sh)
```bash
if [[ ... ]] vs if [ ... ]
```

## Bash references
[Official Bash documentation (manual)](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html)

### Debugging (line by line)
```bash
# At the beginning of the script
set -x
trap read debug
```

### Special variables
```bash
$?          # Exit code of last command
$#          # Number of arguments supplied
$0          # Current filename (first argument)
$1-$9       # Command line arguments (one by one)
$@          # Array of arguments
$$          # Current PID
```

### Prologue
```bash
#!/usr/bin/env bash                     # Shebang: run with Bash shell

# TL;DR
set -ueo pipefail

# Exit if undefined variable has been found
set -u                                      

# Exit if any exit code of executed functions is not equal zero
set -e

# Break pipeline if our script failed
set -o pipefail                               
```

### Defining variables
> **NOTE**: No spaces around equal sign!
```bash
var1=100                                # Number
var2="Number: $var1"                    # Double quotes == interpolation
var3='Number is stored in $var1'        # Single quotes == no interpolation
var4=$(cat test.txt)                    # Result of command
var5=("str1" "str2" "str3")             # Array of strings
var6=(1 5 9 43 23 43)                   # Array of numbers
read var7                               # Read variable from stdin
```

### If statement
```bash
# If statements (spaces around expression matter)
if [ "$var" = "Test value" ]; then
    command
elif [ "var" = "abcd" ]; then
    command
else
    command
fi

# Negation
if ! [[ -f $var1 ]]                     # If file doesn't exist

# Number comparision
if [[ $var1 -lt $var2 ]]                # If less than
if [[ $var1 -gt $var2 ]]                # If greater than
if [[ $var1 -eq $var2 ]]                # If equal
if [[ $var1 -ne $var2 ]]                # If not equal

# String comparision
if [[ $var1 = $var2 ]]                  # If string equal
if [[ $var1 != $var2 ]]                 # If string not equal

# Others
if [[ -z $var1 ]]                       # If null or zero length
if [[ -n $var1 ]]                       # If not null and not zero length
if [[ -d $var1 ]]                       # If directory exist
if [[ -f $var1 ]]                       # If file exist

# Compund expressions
if [[ $v1 = $v2  || $v1 != $v3 ]]       # Or
if [[ $v1 = $v2  && $v1 != $v3 ]]       # And
```

### Loops
```bash
# For loops
for number in {1..12}; do
    echo "Current number: $number"
    break
    continue
done

for file in /bin/*                      # Iterate over files
for num in {1..12..2}                   # {start..end..step}
for num in 1 9 4 3 3                    # Interate over list of items
for (( i=0; i<5; i++ ))                 # C-like for loop
for name in $(cat names.txt)            # Line by line output of a command

# Iterate over array elements
for item in "${arr[@]}"; do
    echo "$item"
done

# Iterate over lines of variable
while read -r line; do
    echo $line
done <<< "$content"

# Iterate over lines of file
while read -r line; do
    echo $line
done < file.txt
```

### Functions
Arguments are not named. They are only positional. Same convention as for the
script parameters.
```bash
function func1() {
    echo $1                             # Echo 1st argument
    echo $2                             # Echo 2nd argument
}

func1 "test-argument" 234               # Call a function
```

### Strings
```bash
var='super'
echo ${var:0:1} OR ${var::1}  => 's'    # Get substring of a string
echo ${var:2:2}               => 'pe'   # ${var:start:n}        
echo ${var:2}                 => 'per'  # From :2 to end
echo ${var:(-2)}              => 'e'    # Index from end
echo ${#var}                  => 5      # Get length

# Case manipulation
echo ${str^}            => 'Super'      # Upper first letter
echo ${str^^}           => 'SUPER'      # Uppercase
var='SUPER'
echo ${str,}            => 'sUPER'      # Lower first letter
echo ${str,,}           => 'super'      # Lowercase

# Split into variables
str='1:2'
IFS=: read -r var1 var2 <<< "$str"  =>  var1 == 1, var2 == 2 
```

### Math / arithmetic
```bash
$((1 + 1))                              # Math expression        
$((x + y))                              # Variables math
```

### Arrays
```bash
arr=("1" "2" "3")                       # Define array
arr[3]="4"                              # Define item
arr+=("5")                              # Add item
echo ${arr[3]}                          # Get item
echo ${arr[@]}                          # Get all items
```

### Regex
```bash
# Check matching and group extraction
exp='123(.*)456'
if [[ $var1 =~ $exp ]]; then
    echo $BASH_REMATCH[0]               # Entire regex match
    echo $BASH_REMATCH[1]               # First group
fi
```