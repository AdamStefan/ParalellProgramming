#include "stdafx.h"
#include <vector>

HMac::HMac(std::string key)
{

	int length = key.length();
	this->i_key_pad = (char*)malloc(sizeof(char) * 64);
	int blokSize = 64;

	// if key is longer than blocksize
	if (length > blokSize)
	{
		SHA1 sha1;
		sha1.update(key);
		char* oldKey = i_key_pad;
		std::string keyHash = sha1.final();
		i_key_pad = (char*)malloc(sizeof(char) * keyHash.length());
		strncpy(i_key_pad, keyHash.c_str(), blokSize);
		length = keyHash.length();
		free(oldKey);
	}
	else if (length <= blokSize)
	{
		for (int i = 0; i < blokSize; i++)
		{
			if (i < length)
			{
				*i_key_pad = key[i];				
			}
			else
			{
				*i_key_pad = 0x0;
			}
			i_key_pad++;
		}

		i_key_pad = i_key_pad - blokSize;
	}

	this->o_key_pad = (char*)malloc(sizeof(char) * 64);


	for (int i = 0; i < blokSize; i++)
	{
		*o_key_pad = 0x5c ^ *i_key_pad;
		*i_key_pad = 0x36 ^ *i_key_pad;
		o_key_pad++;
		i_key_pad++;
	}

	i_key_pad = i_key_pad - blokSize;
	o_key_pad = o_key_pad - blokSize;

}


std::string HMac::ComputeHash(char* M, int length)
{
	SHA1 sha1, sha2;
	std::string message = std::string(M, length);
	char* keyPadAndM = new char[message.length() + 64];

	memcpy(keyPadAndM, i_key_pad, sizeof(char) * 64);
	keyPadAndM += 64;
	memcpy(keyPadAndM, M, sizeof(char) * message.length());
	keyPadAndM -= 64;


	sha1.update(std::string(keyPadAndM, message.length() + 64));
	std::string hashed = sha1.final();
	
	char* keyAndHashed = new char[hashed.length() + 64];

	memcpy(keyAndHashed, o_key_pad, sizeof(char) * 64);
	keyAndHashed += 64;
	memcpy(keyAndHashed, hashed.c_str(), sizeof(char)* hashed.length());
	keyAndHashed -= 64;

	sha2.update(std::string(keyAndHashed, 64 + hashed.length()));

	delete[] keyAndHashed;
	delete[] keyPadAndM;	

	return sha2.final();
}

std::string HMac::ComputeHash(std::istream&is)
{
	SHA1 sha1, sha2;
	sha1.update(is, std::string(this->i_key_pad, 64));
	std::string hashed = sha1.final();

	// concatenate o_key and hash	
	char* keyAndHashed = new char[hashed.length() + 64];
	memcpy(keyAndHashed, this->o_key_pad, sizeof(char) * 64);
	keyAndHashed += 64;
	memcpy(keyAndHashed, hashed.c_str(), sizeof(char) * hashed.length());
	keyAndHashed -= 64;

	sha2.update(std::string(keyAndHashed, 64 + hashed.length()));

	std::string hash = sha2.final();
	return hash;
}
