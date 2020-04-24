#include "cpp-sha256-hmac.hpp"

using namespace YukiWorkshop::Crypto;

int main() {
	SHA256 s;
	s.update("0123456789");

	std::vector<uint8_t> r0 = s.finalize();

	for (auto &it : r0) {
		printf("%02x", it);
	}

	puts("");

	SHA256 s2;
	s2 << "abcdefghij";

	std::vector<uint8_t> r1;
	s2 >> r1;

	for (auto &it : r1) {
		printf("%02x", it);
	}

	puts("");

	uint8_t k[] = "some secret key, don't use human readable password";
	SHA256_HMAC sh(k, sizeof(k));
	s.update("0123456789");
	std::vector<uint8_t> r2 = sh.finalize();

	for (auto &it : r2) {
		printf("%02x", it);
	}

	puts("");

}