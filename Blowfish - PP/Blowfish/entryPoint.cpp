// ConsoleApplication6.cpp : Defines the entry point for the console application.

//blowfish.h
//This code is in the public domain.
//Created by Taylor Hornby 
//May 8, 2010.
//Ported from my C# blowfish code which was ported from the JavaScript crypto library found here:
//  http://etherhack.co.uk/symmetric/blowfish/blowfish.html
//Complies with the test vectors:  http://www.schneier.com/code/vectors.txt
//Description:
//  Blowfish is a keyed, symmetric block cipher, designed in 1993 by Bruce Schneier and
//  included in a large number of cipher suites and encryption products. Blowfish provides
//  a good encryption rate in software and no effective cryptanalysis of it has been found to date.
//Key Size: 32 to 448 bits
//Block Size: 64 bits
//Rounds: 16 (up to 256 rounds can be used with this class, change the '#define ROUNDS' line)
//More Information: http://www.schneier.com/paper-blowfish-fse.html and http://en.wikipedia.org/wiki/Blowfish_cipher

/*  Cryptography 101 - How to implement properly

This class provides two modes of encryption, CBC and ECB. With ECB, the same data encrypted with the same key will
produce the same result. Patterns will also be visible in the ciphertext. ECB mode should not be used unless it is
specifically needed. CBC mode ensures that no patterns are present in the ciphertext, and that the same data
encrypted with the same key, yeilds a different ciphertext.

Whenever encrypting data, ALWAYS verify the authenticity of the data BEFORE decrypting. To do this, use a HMAC:
token = HMAC(ciphertext, key)
Include this token with the data, and verify it by computing the HMAC again. This ensures that without the key,
an attacker cannot modify the ciphertext. This is especially important with CBC mode, without verification, the
attacker can control the value of the first block of plaintext by modifying the IV.

-   When using CBC mode, always use a random and unique IV. SetRandomIV() will do this for you.
-   Blowfish is only as secure as the encryption key you provide. To create a key from a password,
run it through a hash algorithm such as SHA-256
*/

//the source code was taken from https://defuse.ca/blowfish.htm

#include "stdafx.h"
#include <fstream>
#include <string>


using namespace std;
typedef unsigned char byte;



int encryptAndHash(string  fileName, string destinationFileName, string secret)
{
	ifstream myFile;
	myFile.open(fileName.c_str(), ios::binary | ios::ate);
	char *memblock = NULL;
	int size;

	if (myFile.is_open())
	{
		size = myFile.tellg();
		memblock = new char[size];
		myFile.seekg(0, ios::beg);
		myFile.read(memblock, size);
		myFile.close();
	}


	if (memblock == NULL)
	{
		return 0;
	}

	int newlen = 0;
	BLOWFISH bf(secret.c_str());
	byte* result = bf.Encrypt_ECB((byte*)memblock, size, &newlen);
	delete[]memblock;

	HMac hmac1(secret.c_str());
	string hash = hmac1.ComputeHash((char*)result);


	ofstream outputFile;
	outputFile.open(destinationFileName.c_str(), ios::out | ios::binary);
	if (outputFile.is_open())
	{
		outputFile.write((char*)result, newlen);
		outputFile.write((char*)hash.c_str(), hash.length());
		outputFile.close();
	}

}

int decryptAndCheckHash(string fileName, string destinationFileName, string secret)
{
	ifstream myFile;
	myFile.open(fileName.c_str(), ios::binary | ios::ate);
	char *memblock = NULL;
	char *hash = NULL;
	int size;

	if (myFile.is_open())
	{
		size = myFile.tellg();
		hash = new char[SHA1::HASH_HEX_LENGTH];
		memblock = new char[size - SHA1::HASH_HEX_LENGTH];
		myFile.seekg(0, ios::beg);
		myFile.read(memblock, size - SHA1::HASH_HEX_LENGTH); // read the maincontent
		myFile.read(hash, SHA1::HASH_HEX_LENGTH); // read the hash
		myFile.close();
	}
	else
	{
		throw std::exception("Cannot open source file");
	}

	HMac hmac1(secret);
	string computedHashVal = hmac1.ComputeHash(memblock);
	string fileDigest = std::string(hash);
	bool areEqual = true;

	for (int index = 0; index < computedHashVal.length(); index++)
	{
		if (computedHashVal[index] != fileDigest[index])
		{
			areEqual = false;
		}
	}

	if (!areEqual)
	{
		throw std::exception("Invalid hash");
		return 0;
	}


	BLOWFISH bf(secret.c_str());

	int decriptedLength = 0;
	byte* decript = bf.Decrypt_ECB((byte*)memblock, size - SHA1::HASH_HEX_LENGTH, &decriptedLength);
	delete[] memblock;


	ofstream outputFile;
	outputFile.open(destinationFileName.c_str(), ios::out | ios::binary);
	if (outputFile.is_open())
	{
		outputFile.write((char*)decript, decriptedLength);
		outputFile.close();
	}
	else
	{
		throw std::exception("Cannot open destination file");
		return -1;
	}

	delete[] decript;

	return 1;
}

//blowfishalgorithm.exe -e "input.JPG" "outputImage.dat" "FEDCBA9876543210"
//blowfishalgorithm.exe -d "outputImage.dat" "inputToCheck.JPG" "FEDCBA9876543210"

//blowfishalgorithm.exe -e "c:\\preloadedData.csv" "c:\\outputData.dat" "FEDCBA9876543210"
//blowfishalgorithm.exe -d "c:\\outputData.dat" "c:\\preloadedDataToCheck.csv" "FEDCBA9876543210"

int main(int argc, char** argv)
{
	bool decrypt = false;
	string sourceFileName;
	string destinationFileName;
	string key;

	//-e "c:\\IMGP3835.JPG" "C:\\OutputIMGP.JPG" "FEDCBA9876543210"

	/*sourceFileName = "c:\\IMGP3835.JPG";
	destinationFileName = "C:\\outputTest.dat";*/

	sourceFileName = "c:\\preloadedData.csv";
	destinationFileName = "C:\\preloadedDataCriptat.dat";
	key = "FEDCBA9876543210";


	destinationFileName = "c:\\outputImage.JPG";
	bool perftest = false;

	argv++;
	if (!perftest)
	{

		if (argc < 5)
		{
			printf("%s", "Invalid Parameters. Please enter: -e/d (encrypt/decrypt) sourcefilename destinationfilename");
			return 0;
		}
		else
		{
			for (int index = 1; index < 4; index++)
			{
				string currentArg = string(*argv);

				if (index == 1)
				{
					if (currentArg == "-e" || currentArg == "-E")
					{
						decrypt = false;
					}
					else if (currentArg == "-d" || currentArg == "-D")
					{
						decrypt = true;
					}
					else
					{
						printf("%s", "Invalid Parameters. Please enter - e/d (encrypt/decrypt) sourcefilename destinationfilename");
						return 0;
					}
				}
				else if (index == 2)
				{
					sourceFileName = string(*argv);
				}
				else if (index == 3)
				{
					destinationFileName = string(*argv);
				}
				else if (index == 4)
				{
					key = string(*argv);
				}
				argv++;
			}
		}
	}

	if (!decrypt)
	{
		encryptAndHash(sourceFileName, destinationFileName, key);
	}
	else
	{
		decryptAndCheckHash(sourceFileName, destinationFileName, key);
	}

	return 0;
}









