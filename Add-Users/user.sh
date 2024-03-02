#!/bin/bash
#set -x
MY_INPUT='/path/to/user.csv'
declare -a NAME
declare -a SURNAME
declare -a USERNAME
declare -a GROUP
declare -a PASSWORD
while IFS=, read -r COL1 COL2 COL3 COL4 COL5 TRASH;
do
        NAME+=("$COL1")
        SURNAME+=("$COL2")
        USERNAME+=("$COL3")
        GROUP+=("$COL4")
        PASSWORD+=("$COL5")
done <"$MY_INPUT"
for index in "${!USERNAME[@]}"; do
        groupadd "${GROUP[$index]}";
        useradd -G "${GROUP[$index]}" -d "/home/${USERNAME[$index]}" -s /bin/bash -p "$(echo "${PASSWORD[$index]}" | openssl passwd -1 -stdin)" "${USERNAME[$index]}"
done