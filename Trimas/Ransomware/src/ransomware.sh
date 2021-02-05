#!/bin/bash

make all
# make run

export LD_PRELOAD=./logger.so 

if [ "$#" -ne 2 ]; then
    echo "You must enter exactly 2 command line argument."
    exit 1
fi

if ! [[ "$1" =~ ^[0-9]+$ ]]; then
    echo "The first argument must be an integer(volume of files)."
    exit 1
fi

if ! [[ -d "$2" ]]
then
    mkdir "$2"
fi

rm -rf "$2"/* 

if ! [[ -d "decrypted" ]]
then
    mkdir "decrypted"
fi

rm -rf decrypted/*
./file $1
for file in Userfiles/*
do 
	end=".encrypt"
	crypto_folder=""$2"/"
    output=$crypto_folder${file##*/}$end
    openssl enc -aes-256-ecb -e  -pbkdf2  -salt -in $file -out $output -k 1234
    rm -rf $file 
    decr_folder="decrypted/"
    output_2=$decr_folder${file##*/}
    openssl aes-256-ecb -pbkdf2 -in $output -out $output_2 -d -k 1234
done
