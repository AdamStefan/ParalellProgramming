#include"stdafx.h"
#include <string>


class HMac {
public:
	HMac(std::string);
	std::string HMac::ComputeHash(char* M);
	std::string HMac::ComputeHash(std::istream&is);	
private:
	char* o_key_pad;
	char* i_key_pad;
};