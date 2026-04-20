import yara
import getopt, sys, os

args = sys.argv[1:]
options = "hf:o:"
long_options = ["help", "target-binary", "output"]
targetBinary = ""
outFile = ""

def helpCmd():
    print("\nAnalyzes binaries using YARA to check if Pyinstaller was used to package it.\n")
    print("-h, --help           |   help")
    print("-f, --target-binary  |   Target binary to analyze")
    print("-o, --output         |   Output file")
    print("")


def handleCLI():

    global targetBinary
    global outFile

    try:
        arguments, values = getopt.getopt(args, options, long_options)
        for currentArg, currentVal in arguments:
            if currentArg in ("-h", "--help"):
                helpCmd()
            elif currentArg in ("-f", "--target-binary"):
                print("Target binary is " + currentVal + ", analyzing...\n")
                targetBinary = currentVal
            elif currentArg in ("-o", "--output"):
                outFile = currentVal

    except getopt.error as err:
        print(str(err))

def signaturePyinstaller():

    yaraRuleFile = "./rules/pyinstaller.yar"

    if not os.path.exists(targetBinary):
        print("Target binary does not exist!")
        sys.exit(1)
        
    if not os.path.exists(yaraRuleFile):
        print("Can't find YARA rule file!")
        sys.exit(1)
        
    rules = yara.compile(filepath=yaraRuleFile)
    matches = rules.match(targetBinary)

    if not matches:
        print("No YARA matches found.")
        return
    
    for match in matches:
        print(f"Rule: {match.rule}")
        for key, val in match.meta.items():
            print(f"  {key}: {val}")
        for s in match.strings:
            for instance in s.instances:
                print(f"  {s.identifier}: {instance.matched_data}")

handleCLI()
signaturePyinstaller()
