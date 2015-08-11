/* 
Custom Crypter XOR / NOT / XOR / INC / Swapping
Author: Guillaume Kaddouch
SLAE-681
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Write "Egg Mark" and exit
unsigned char shellcode[] = \
"\x31\xdb\xf7\xe3\xb0\x04\x6a\x0a\x68\x4d\x61\x72\x6b\x68\x45"
"\x67\x67\x20\xb3\x01\x89\xe1\xb2\x09\xcd\x80\xb0\x01\xcd\x80"
"\x90"; // shellcode end mark;

int shellcode_len=31;

void display(unsigned char* buffer, int buffer_len){
    int counter;
    unsigned char data_byte;

    for (counter=0; counter< buffer_len; counter++)
    {
        data_byte = buffer[counter];
        printf("\\x%02x", data_byte);
    }

}

int main()
{
	int counter;
	int xor_key;
	unsigned char temp;
        unsigned char encrypted[shellcode_len];
        unsigned char decrypted[shellcode_len];

	printf("Shellcode:\n");
	display((unsigned char*)shellcode, shellcode_len);


	/* ---------------- Encryption code ---------------- */
        for (counter=0; counter < shellcode_len; counter++){
		if (shellcode[counter] == 0xaa || (~(shellcode[counter] ^ 0xaa)) == 0xbb){ // XOR = NULL
			printf("Forbidden character in plain or encrypted shellcode found \\x%02x, exiting.", shellcode[counter]);
			exit(0);
		}
		// Encryption of 'A' => A XOR 0xaa | NOT | XOR 0xbb | INC
                encrypted[counter] = (~(shellcode[counter] ^ 0xaa)) ^ 0xbb;
		if (encrypted[counter] < 0xff){
			encrypted[counter] = encrypted[counter] + 0x1;
		}
        }

	// Swapping pair of bytes, e.g: \xda\xef \x31\x56 -> \xef\xda \x56\x31
	for (counter=1; counter < (shellcode_len-1); counter=counter+2){
		// swap two bytes
                temp = encrypted[counter];
        	encrypted[counter] = encrypted[counter-1];
                encrypted[counter-1] = temp;

	}

	printf("\n\nEncrypted shellcode:\n");
	display((unsigned char*)encrypted, shellcode_len);

	printf("\n\n");
    	return 0;
}
