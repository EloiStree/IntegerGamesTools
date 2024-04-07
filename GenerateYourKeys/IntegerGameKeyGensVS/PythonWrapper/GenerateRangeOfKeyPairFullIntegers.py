import subprocess

exe_path = "IntegerGameKeyGensVS.exe"
arg1 = "PrivateAccounts/51"
arg2 = "PublicAccounts/51"




square_size=4
while True:
    start=0
    end=square_size*square_size
    folder_name=f"{square_size}x{square_size}"
    key_range = range(start, end)
    for key in key_range:
        print(f"{key} {square_size}x{square_size}")
        arg1 = folder_name+"/PrivateAccounts/" + str(key)
        arg2 = folder_name+"/PublicAccounts/" + str(key)
        subprocess.run([exe_path, arg1, arg2, "NoValidation"], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    
    square_size*=2
