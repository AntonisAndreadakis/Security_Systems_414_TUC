#include "rsa.h"
#include "utils.h"
#include <math.h>


/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *sieve_of_eratosthenes(int limit, int *primes_sz){
	size_t *primes;
	/* TODO */
	size_t array[limit+1];
	int i,j,m,var2,var3;
	//eliminate first 2:
	for(i=0; i<=limit; i++){
		array[i] = 1;
		if(i<2)
			array[i] = 0;
	}
	m = round(sqrt(limit));	
	//create our array to store values:	
	//search all array and eliminate multiples-non prime:
	for(i=2; i<=m; i++){
		if(array[i]==1){
			//set multiples to false:
			for(j=i*i; j<=limit; j+=i){
				array[j] = 0;
			}
		}
	}
	var2 = 0;
	//length:
	for (i = 2; i<=limit; i++){
		if (array[i]==1){
			var2++;
		}
	}
	// allocate array for all numbers in limit:	
	primes = (size_t*)malloc(var2*sizeof(size_t));
	var3 = 0;
	for (i = 2; i<=limit; i++){
		if (array[i]==1){
			*(primes+var3) = i;			
			var3++;
		}
	}
	*primes_sz = var2;
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int gcd(int a, int b){

	/* TODO */
	int result;
	while(b>0){
		result = a%b;    // store mod of a%b
		if (result == 0) // if perfect division
			return b;// b is our desired
		a = b;           
		b = result;
	}
	return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n, size_t* primes, int prime_length){
	size_t e = 0;
	int i;
	/* TODO */
	for(i=0; i<prime_length; i++){
		e = primes[i];
		if((e % fi_n) != 0 && gcd(e,fi_n) == 1)
			return e;
		}
	return -1;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t mod_inverse(size_t a, size_t b){
	/* TODO */
	size_t inverse;
	size_t q, r, s, t, u1, u3, v1, v3;
	// initialise:
	u1 = 1;
	u3 = a;
	v1 = 0;
	v3 = b;
	t = 1; //remember odd/even iterations
	// while "b" not null:
	while(v3!=0){
		q = u3/v3;
		s = u3%v3;
		r = q*v1 + u1;
		//swap:
		u1 = v1;
		v1 = r;
		u3 = v3;
		v3 = s;
		t = -t;
	}
	// make sure a = gcd(a,b) == 1
	if(u3!=1)
		//no inverse:
		return 0;
	// positive result:
	if(t<0)
		inverse = b-u1;
	else
		inverse = u1;
	return inverse;
}

void pool(size_t* p1, int p_size, size_t *var1, size_t *var2){
int i,j;
srand(time(NULL));
i = (rand() % (p_size-1));
j = (rand() % (p_size-1));
while(i==j){
	j = (rand() % (p_size-1));
	}
*var1 = p1[i];
*var2 = p1[j];
}

void write_key(size_t var1, size_t var2, char* key){
FILE *fp = fopen(key,"w");
if(fp==NULL)
	return ;
fwrite(&var1,1,sizeof(var1),fp);
fwrite(&var2,1,sizeof(var2),fp);
fclose(fp);
}
/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void){
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	int p_size;
	size_t *prime_pool;
	/* TODO */
	prime_pool = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &p_size);
	pool(prime_pool, p_size, &p, &q);
	n = p*q;
	fi_n = (p-1)*(q-1);
	e = choose_e(fi_n, prime_pool, p_size);
	d = mod_inverse(fi_n,e);
	while(d<0)
		d = d + fi_n;
	write_key(d,n, "public.txt");
	write_key(e,n, "private.txt");
}

//function for modular exponantiation
size_t mod_expon(size_t a, size_t b, size_t c){
if(a==0)
	return 0;
if(b==0)
	return 1;
size_t x;

//b is even:
if(b%2==0){
	x = mod_expon(a,b/2,c);
	x = (x*x)%c;
	}
//b is odd:
else{
	x = a%c;
	x = (x*(mod_expon(a,b-1,c))%c);
	}
x = (size_t)((x+c)%c);
return x;
}

//function for reading file:
unsigned char* read_file(char* filename, int *filesize){
FILE* fp = fopen(filename,"r");
if(fp==NULL)
	return 0;
char* var1 = (char*)malloc((BUFFER_SIZE+1)*sizeof(char));
size_t text = fread(var1,sizeof(char),BUFFER_SIZE,fp);
fclose(fp);
char* buf = (char*)malloc((text)*sizeof(char));
memcpy(buf,var1,text);
free(var1);
*filesize = (int)text;
return (unsigned char*)buf;
}

//function for writing to file:
void writeFile(int size, char* filename, size_t* text){
FILE *fp = fopen(filename,"w");
if(fp==NULL)
	return ;
int i;
for(i=0; i<=size; i++){
	fwrite(&text[i],1,sizeof(text[i]),fp);
	}
fclose(fp);
}

//function for writing text:
void writeText(int size, char* filename, unsigned char* text){
FILE* fp = fopen(filename,"w");
if(fp==NULL)
	return ;
int i;
for(i=0; i<=size; i++){
	fwrite(&text[i],1,sizeof(text[i]),fp);
	}
fclose(fp);
}

//function for encoding:
size_t* encode(int size, size_t n, size_t d, unsigned char *plaintext){
size_t* ciphertext;
int i;

ciphertext = (size_t*)malloc(size*sizeof(size_t));

for(i=0; i<=size; i++){
	ciphertext[i] = mod_expon((size_t)plaintext[i],n,d);
	}
return ciphertext;
}

//function for decoding:
unsigned char* decode(int size, size_t n, size_t e, size_t *ciphertext){
int i;
//size_t var;
unsigned char* plaintext;

plaintext = (unsigned char*)malloc(size*sizeof(unsigned char));

for(i=0; i<=size; i++){
	//var = mod_expon(ciphertext[i], n, e);
	plaintext[i] = (unsigned char)mod_expon(ciphertext[i], n, e);
	}
return plaintext;
}
/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *input_file, char *output_file, char *key_file){
	/* TODO */
	int filesize, keysize;
	size_t n, d;
	unsigned char *plaintext, *key;
	size_t *ciphertext;
	
	//read file:
	plaintext = read_file(input_file, &filesize);
	if(plaintext==NULL)
		exit(0);
	//read key:
	key = read_file(key_file, &keysize);
	if(key==NULL)
		exit(0);
	//separate key to "n" and "d":
	memcpy(&n,key,sizeof(size_t));
	memcpy(&d,key+sizeof(size_t),sizeof(size_t));
	
	//encrypt file:
	ciphertext = (size_t*)malloc(filesize*sizeof(size_t));
	ciphertext = encode(filesize,n,d,plaintext);

	//write to output file:
	writeFile(filesize,output_file,ciphertext);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *input_file, char *output_file, char *key_file){

	/* TODO */
		
	int filesize, keysize;
	size_t n, e;
	unsigned char *plaintext, *key, *file;
	size_t *ciphertext;
	
	//read file:
	file = read_file(input_file, &filesize);
	if(file==NULL)
		exit(0);
	//change:
	ciphertext = (size_t*)malloc(filesize);
	memcpy(ciphertext,file,(filesize/sizeof(size_t)));

	//read key:
	key = read_file(key_file, &keysize);
	if(key==NULL)
		exit(0);
	//separate key to "n" and "e":
	memcpy(&n,key,sizeof(size_t));
	memcpy(&e,key+sizeof(size_t),sizeof(size_t));
	
	//decrypt file:
	plaintext = (unsigned char*)malloc((filesize/sizeof(size_t))*sizeof(unsigned char));
	plaintext = decode(filesize/sizeof(size_t), n, e, ciphertext);

	//write to output file:
	writeText((filesize/sizeof(size_t)),output_file,plaintext);
}
