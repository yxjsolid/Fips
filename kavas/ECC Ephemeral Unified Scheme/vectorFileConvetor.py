fileName = "KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.fax"
outFileName = "KASValidityTest_ECCEphemeralUnified_NOKC_ZZOnly_init.conv"

fileName = "KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.fax"
outFileName = "KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.conv"
fd = open(fileName, "r")
outFd = open(outFileName, "w")
paramList = [

"deCAVS",
"QeCAVSx",
"QeCAVSy",
"deIUT",
"QeIUTx",
"QeIUTy",
"Z",
"CAVSHashZZ",
"Nonce",
"OI",
"CAVSTag",
"MacData",
"DKM",

]


for line in fd:
    if "=" in line:
        params = line.split()
        param, val = params[0], params[2]
        if param in paramList:
            newLine = "char *%s = \"%s\";\n"%(param ,val)
            outFd.write(newLine)
        else:
            outFd.write(line)

    else:
        outFd.write(line)