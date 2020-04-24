# cpp-sha256-hmac
C++ library for SHA256 & SHA256-HMAC calculation.

## Usage
```cpp
#include "cpp-sha256-hmac.hpp"

using namespace YukiWorkshop::Crypto;
```

```cpp
SHA256 s;
s.update("0123456789");

std::vector<uint8_t> r0 = s.finalize();

for (auto &it : r0) {
    printf("%02x", it);
}
```

```cpp
SHA256 s2;
s2 << "abcdefghij";

std::vector<uint8_t> r1;
s2 >> r1;

for (auto &it : r1) {
    printf("%02x", it);
}
```

```cpp
uint8_t k[] = "some secret key, don't use human readable password";
SHA256_HMAC sh(k, sizeof(k));
s.update("0123456789");
std::vector<uint8_t> r2 = sh.finalize();

for (auto &it : r2) {
    printf("%02x", it);
}
```

## License
MIT

## Acknowledgements
This library makes use of [jb55/sha256.c](https://github.com/jb55/sha256.c) and [aperezdc/hmac-sha256](https://github.com/aperezdc/hmac-sha256).