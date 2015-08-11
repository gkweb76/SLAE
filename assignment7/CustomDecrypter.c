/* 
Custom Decrypter XOR / NOT / XOR / INC / Swapping
Author: Guillaume Kaddouch
SLAE-681
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Write "Egg Mark" and exit
unsigned char encrypted[] = \
"\x36\xe0\x0e\x1a\xeb\x5f\xe5\x85\xa4\x87\x9d\x90\x87\x86\x8a\xac\xcf\x8a\xf0\x5e\x10\x68\xe8\x5d\x6f\x24\xf0\x5f\x6f\x24\x7f";

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
        //unsigned char encrypted[];
        unsigned char decrypted[shellcode_len];

	printf("\n[*] Encrypted Shellcode: ");
	display((unsigned char*)encrypted, shellcode_len);

	/* ---------------- Decryption code ---------------- */

	printf("\n[*] Brute forcing XOR key... ");
	for (xor_key = 1; xor_key < 255; xor_key++)
        {
                if ( (unsigned char)((~((encrypted[shellcode_len-1] - 0x01) ^ xor_key)) ^ 0xaa)  == 0x90 ){
			printf("XOR key found \\x%02x\n", xor_key);
			break; // XOR key found
                }
        }


	// Swapping pair of bytes, e.g: \xda\xef \x31\x56 -> \xef\xda \x56\x31
	for (counter=1; counter < (shellcode_len-1); counter=counter+2){
                // swap two bytes
                temp = encrypted[counter];
                encrypted[counter] = encrypted[counter-1];
                encrypted[counter-1] = temp;

        }

        for (counter=0; counter < shellcode_len; counter++)
        {
		if (encrypted[counter] > 0x00){
                        encrypted[counter] = encrypted[counter] - 0x1;
                }
                decrypted[counter] = (~(encrypted[counter] ^ xor_key)) ^ 0xaa;

        }

 	printf("[*] Decrypted shellcode: ");
        display((unsigned char*)decrypted, shellcode_len);

	printf("\n\n[*] Jumping to Shellcode...\n");
	int (*ret)() = (int(*)())decrypted;
        ret();

}
