import subprocess

exe_path = "IntegerGameKeyGensVS.exe"
arg1 = "PrivateAccounts/51"
arg2 = "PublicAccounts/51"

rangeStart=-2000000000
account_to_create=16384

rangeEnd = rangeStart + account_to_create
key_range = range(rangeStart, rangeEnd)
for key in key_range:
    arg1 = "PrivateAccounts/" + str(key)
    arg2 = "PublicAccounts/" + str(key)
    subprocess.run([exe_path, arg1, arg2,"NoValidation"])

    