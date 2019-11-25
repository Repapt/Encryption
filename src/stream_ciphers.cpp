//============================================================================
// Name        : stream_ciphers.cpp
// Author      : Samuel Liu
// Copyright   : Your copyright notice
// Description : Project 2 - Stream Ciphers
//============================================================================

#include <iostream>

void printArray(unsigned char arr[]){
	for(int i=0;i<256;i++){
		std::cout << static_cast<unsigned int>(arr[i]) << " ";
	}
	//std::cout << std::endl;
}

char *encode(char *plaintext, unsigned long key);
char *encode(char *plaintext, unsigned long key){

	//to find length;
	unsigned int n = 0;

	unsigned int null_num = 0;

	for( char *i = plaintext; *i; i++){
		n++;
	}

	int m = 0;
	if(n%4 != 0){
		null_num = 4 - n%4;
		m++;
	}
	m += 5*n/4 + 1;

	//initialize arrays

	unsigned char *cipher = new unsigned char[n + null_num];
	char *ascii_cipher = new char[m];


	unsigned char s[256];
	for(std::size_t i=0; i<256;i++){
		s[i] = i;
	}

	unsigned int i = 0, j = 0;
	for(std::size_t x=0;x<256;x++){
		unsigned int k = i%64;
		unsigned long bit = (key)&(1L<<k);

		if(bit > 1){
			bit = 1;
		}

		//std::cout << bit;
		j = (j + s[i] + bit)%256;

		char temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		i = (i+1)%256;
	}

	//printArray(s);


	for(std::size_t b=0;b<n + null_num;b++){
		unsigned char c;
		if(b >= n){
			c = '\0';
		} else {
			c = plaintext[b];
		}
		//std::cout << (c) << " " << static_cast<unsigned int>(c) << std::endl;
		i = (i+1)%256;
		j = (j+s[i])%256;
		char temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		int r = (s[i] + s[j])%256;
		c = c^(s[r]);

		cipher[b] = c;
		//std::cout << static_cast<unsigned int>(c) << std::endl;
	}
	//std::cout << std::endl;



	//ascii armour
	std::size_t limit = n/4;
	if(n%4 != 0){
		limit ++;
	}
	for(std::size_t a=0;a<limit;a++){

		//code for exceptions needed
		unsigned int val1 = static_cast<unsigned int>(cipher[a*4]);
		unsigned int val2, val3, val4;
		val4 = static_cast<unsigned int>(cipher[a*4 + 3]);

		val3 = static_cast<unsigned int>(cipher[a*4 + 2]);

		val2 = static_cast<unsigned int>(cipher[a*4 + 1]);


		//std::cout << val1 << " " << val2 << " " << val3 << " " << val4 << std::endl;


		val1 = val1 << 24;
		val2 = val2 << 16;
		val3 = val3 << 8;


		unsigned int num = val1 + val2 + val3 + val4;
		//std::cout << num << std::endl;

		unsigned int values[5];
		for(int b=0;b<5;b++){
			values[b] = num%85;
			//std::cout << values[b] << " ";
			num/=85;
		}
		//std::cout << std::endl;
		for(std::size_t b=0;b<5;b++){
			ascii_cipher[5*a + 4 - b] = values[b] + 33;
		}



	}

	return ascii_cipher;


}

char *decode(char *ciphertext, unsigned long key);
char *decode(char *ciphertext, unsigned long key){

	//determining size
	int m =0;

	for(char *i = ciphertext; *i; i++){
		m++;
	}



	char *plain = new char[4*m/5 + 1];

	int null_count = 0;


	for(std::size_t a=0;a<m/5;a++){
		unsigned int num = 0;
		for(std::size_t b = 0; b<5;b++){
			int inc = ciphertext[a*5 + b] - 33;
			for(std::size_t c=0;c<4-b;c++){
				inc *= 85;
			}
			num += inc;
		}

		//std::cout << num << std::endl;

		plain[a*4] = num >> 24;
		plain[a*4 + 1] = (num >> 16)&255;
		plain[a*4 + 2] = (num >> 8)&255;
		plain[a*4 + 3] = num&255;

		if(plain[a*4 +1] == 0){
			null_count = 3;
		} else if(plain[a*4 +2] == 0){
			null_count = 2;
		} else if(plain[a*4 +3] == 0){
			null_count = 1;
		}



	}



	unsigned char s[256];
	for(std::size_t i=0; i<256;i++){
		s[i] = i;
	}

	unsigned int i = 0, j = 0;
	for(std::size_t x=0;x<256;x++){
			unsigned int k = i%64;
			unsigned long bit = (key)&(1L<<k);

			if(bit > 1){
				bit = 1;
			}

			//std::cout << bit;
			j = (j + s[i] + bit)%256;

			char temp = s[i];
			s[i] = s[j];
			s[j] = temp;

			i = (i+1)%256;
		}


	for(std::size_t b=0;b<4*m/5 + 1;b++){
		unsigned char c = plain[b];
		//std::cout << static_cast<unsigned int>(c) << " ";
		i = (i+1)%256;
		j = (j+s[i])%256;
		char temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		int r = (s[i] + s[j])%256;
		c = c^(s[r]);

		plain[b] = c;
		//std::cout << static_cast<unsigned int>(c) << std::endl;
	}

		plain[4*m/5] = '\0';



	return plain;



}

#ifndef MARMOSET_TESTING
int main();
#endif

#ifndef MARMOSET_TESTING
int main() {



	char text[] = {"A Elbereth Gilthoniel\nsilivren penna miriel\n""o menel aglar elenath!\nNa-chaered palan-diriel\n""o galadhremmin ennorath,\nFanuilos, le linnathon\n""nef aear, si nef aearon!"};

	char text2[] = {"Hello world!"};
	char *cipher = encode(text2, 51323);

	char text3[] = {";nVU/]gK[/N_AL8-15?n5YEuBRj;^r])-Pn\\j/i0"
"N4aa+i8<nsF^,2Kql\\\\#ONC@5F5.<$SZJ=JYfr6"
"9dqtAX].?DP(H0gDg9_VgD3,2K<</^F^W*j+Q/A'b"
"r$)TD.!R4rK,/4S,C)6Iq:0;W"};

	std::cout << text2 << std::endl;
	std::cout << cipher << std::endl;

	std::cout << decode(text3, 89963221);

	//char *plain = decode(cipher, 51323);
	//std::cout << plain;
	/*
	int i=0;
	while(cipher[i] != '\0'){
		i++;
	}
	std::cout << i;
	*/
}
#endif
