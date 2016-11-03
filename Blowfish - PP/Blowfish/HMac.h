#include"stdafx.h"
#include <string>


class HMac {
public:
	HMac(std::string);
	std::string ComputeHash(char* M, int length);
	std::string ComputeHash(std::istream&is);	
private:
	char* o_key_pad;
	char* i_key_pad;
};