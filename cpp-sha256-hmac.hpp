/*
    This file is part of cpp-sha256-hmac.
    Copyright (C) 2020 ReimuNotMoe

    This program is free software: you can redistribute it and/or modify
    it under the terms of the MIT License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

    Algorithm credits: https://github.com/jb55/sha256.c
                       https://github.com/aperezdc/hmac-sha256

*/

#include <vector>
#include <string>

#include <cstdlib>
#include <cinttypes>
#include <cstring>


namespace YukiWorkshop::Crypto {

	class SHA256 {
	protected:
		uint32_t state[8];
		uint64_t count;
		unsigned char buffer[64];

		void sha256_write_byte_block();

		static void __update(SHA256 *p, const void *__data, size_t __len) noexcept;
		static void __finalize(SHA256 *p, void *__digest) noexcept;
	public:
		SHA256() {
			reset();
		}

		void reset() noexcept;

		void update(const void *__data, size_t __len) noexcept;

		void update(const char *__data) noexcept {
			update(__data, strlen(__data));
		}

		template <typename T, typename A>
		void update(const std::vector<T, A>& __input) {
			update(__input.data(), __input.size() * sizeof(T));
		}

		template <typename T>
		void update(const T& __input) {
			update(__input.data(), __input.size());
		}

		auto finalize() {
			struct {
				SHA256 *p;

				operator std::vector<uint8_t>() {
					std::vector<uint8_t> ret(32);
					__finalize(p, ret.data());
					return ret;
				}

				operator std::string() {
					std::string ret;
					ret.resize(32);
					__finalize(p, ret.data());
					return ret;
				}

			} ret{this};

			return ret;
		}

		void finalize(void *__digest) noexcept;

		template <typename T, typename A>
		friend SHA256& operator<<(SHA256& e, const std::vector<T, A>& s) {
			__update(&e, s.data(), s.size() * sizeof(T));
			return e;
		}

		template <typename T>
		friend SHA256& operator<<(SHA256& e, const T& s) {
			__update(&e, s.data(), s.size());
			return e;
		}

		friend SHA256& operator<<(SHA256& e, const char *s) {
			__update(&e, s, strlen(s));
			return e;
		}

		template <typename T, typename A>
		friend void operator>>(SHA256& e, std::vector<T, A>& s) {
			s.resize(32 / sizeof(T));
			__finalize(&e, s.data());
		}

		friend void operator>>(SHA256& e, void *s) {
			__finalize(&e, s);
		}
	};

	class SHA256_HMAC : SHA256 {
	private:
		uint8_t kx[64];

		std::vector<uint8_t> key_buf;

		static void __hmac_finalize(SHA256_HMAC *p, void *__digest) noexcept;
	public:
		SHA256_HMAC() {
			reset();
		};

		SHA256_HMAC(const void *__data, size_t __len) {
			reset();
			set_key(__data, __len);
		}

		template <typename T, typename A>
		SHA256_HMAC(const std::vector<T, A>& __input) {
			reset();
			set_key(__input.data(), __input.size() * sizeof(T));
		}

		template <typename T>
		SHA256_HMAC(const T& __input) {
			reset();
			set_key(__input.data(), __input.size());
		}

		void set_key(const void *__data, size_t __len);

		template <typename T, typename A>
		void set_key(const std::vector<T, A>& __input) {
			set_key(__input.data(), __input.size() * sizeof(T));
		}

		template <typename T>
		void set_key(const T& __input) {
			set_key(__input.data(), __input.size());
		}

		using SHA256::update;

		void finalize(void *__digest) noexcept {
			__hmac_finalize(this, __digest);
		}

		auto finalize() {
			struct {
				SHA256_HMAC *p;

				operator std::vector<uint8_t>() {
					std::vector<uint8_t> ret(32);
					__hmac_finalize(p, ret.data());
					return ret;
				}

				operator std::string() {
					std::string ret;
					ret.resize(32);
					__hmac_finalize(p, ret.data());
					return ret;
				}

			} ret{this};

			return ret;
		}

		template <typename T, typename A>
		friend SHA256_HMAC& operator<<(SHA256_HMAC& e, const std::vector<T, A>& s) {
			__update(&e, s.data(), s.size() * sizeof(T));
			return e;
		}

		template <typename T>
		friend SHA256_HMAC& operator<<(SHA256_HMAC& e, const T& s) {
			__update(&e, s.data(), s.size());
			return e;
		}

		friend SHA256_HMAC& operator<<(SHA256_HMAC& e, const char *s) {
			__update(&e, s, strlen(s));
			return e;
		}

		template <typename T, typename A>
		friend void operator>>(SHA256_HMAC& e, std::vector<T, A>& s) {
			s.resize(32 / sizeof(T));
			__hmac_finalize(&e, s.data());
		}

		friend void operator>>(SHA256_HMAC& e, void *s) {
			__hmac_finalize(&e, s);
		}


	};
}