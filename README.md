# IDAPyFuncFinder
bit of a messy python script for IDA to find potential function names by following imported function call xrefs

# Usage
Note: put in your IDA Pro/plugins folder, this script was designed for IDA Pro 7.5 with Python 3.9, bugs may exist


Launch the script either via the plugin drop down or using Ctrl-Alt-L, it will prompt you for 2 inputs, first one is asking for a module
enter the module name without extension (eg: kernel32) then it will prompt you for a function.

This function should contain a string such as "Person::Work".

Once the script ran, you should be given a list where you can click on functions to go to them.

Next to the functions there's a suggested name.

Simply right-click the function in the list if the name seems appropriate and hit Apply Name Change.
