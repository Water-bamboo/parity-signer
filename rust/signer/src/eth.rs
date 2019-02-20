// Copyright 2015-2019 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! Ethereum key utils

use ethsign::{SecretKey, PublicKey, Error};
use crate::util::Keccak256;

pub struct KeyPair {
	secret: SecretKey,
	public: PublicKey,
}

impl KeyPair {
	pub fn from_secret(secret: SecretKey) -> KeyPair {
		let public = secret.public();

		KeyPair {
			secret,
			public,
		}
	}

	pub fn from_parity_phrase(phrase: &str) -> KeyPair {
		let mut secret = phrase.as_bytes().keccak256();
		let mut i = 0;

		loop {
			secret = secret.keccak256();

			match i > 16384 {
				false => i += 1,
				true => {
					if let Ok(pair) = SecretKey::from_raw(&secret).map(KeyPair::from_secret) {
						if pair.public().address()[0] == 0 {
							return pair
						}
					}
				},
			}
		}
	}

	pub fn secret(&self) -> &SecretKey {
		&self.secret
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}

	pub fn address(&self) -> &[u8; 20] {
		self.public().address()
	}

	pub fn sign(&self, message: &[u8]) -> Result<[u8; 65], Error> {
		let signature = self.secret().sign(message)?;

		let mut data: [u8; 65] = [0; 65];

		data[0..32].copy_from_slice(&signature.r);
		data[32..64].copy_from_slice(&signature.s);
		data[64] = signature.v;

		Ok(data)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_parity_phrase() {
		let words = "this is sparta";
		let expected_address = b"\x00\x6E\x27\xB6\xA7\x2E\x1f\x34\xC6\x26\x76\x2F\x3C\x47\x61\x54\x7A\xff\x14\x21";

		let keypair = KeyPair::from_parity_phrase(words);

		assert_eq!(keypair.address(), expected_address);

	}

	#[test]
	fn test_parity_empty_phrase() {
		let words = "";
		let expected_address = b"\x00\xa3\x29\xc0\x64\x87\x69\xA7\x3a\xfA\xc7\xF9\x38\x1E\x08\xFB\x43\xdB\xEA\x72";

		let keypair = KeyPair::from_parity_phrase(words);

		assert_eq!(keypair.address(), expected_address);
	}
}
