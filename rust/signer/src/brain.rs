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

//! This is a Parity Phrase brain wallet implementation.
//!
//! **Parity Phrases are NOT BIP39.**

use parity_wordlist as wordlist;
use tiny_keccak::Keccak;
use ethsign::{SecretKey, PublicKey};

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

	pub fn secret(&self) -> &SecretKey {
		&self.secret
	}

	pub fn public(&self) -> &PublicKey {
		&self.public
	}
}

/// Simple brainwallet.
pub struct Brain(String);

impl Brain {
	pub fn new<S>(s: S) -> Self
	where
		S: Into<String>,
	{
		Brain(s.into())
	}

	pub fn validate_phrase(phrase: &str, expected_words: usize) -> Result<(), wordlist::Error> {
		wordlist::validate_phrase(phrase, expected_words)
	}

	pub fn keypair(&mut self) -> Result<KeyPair, ()> {
		let mut secret = self.0.as_bytes().keccak256();
		let mut i = 0;

		loop {
			secret = secret.keccak256();

			match i > 16384 {
				false => i += 1,
				true => {
					if let Ok(pair) = SecretKey::from_raw(&secret)
						.map(KeyPair::from_secret)
					{
						if pair.public().address()[0] == 0 {
							return Ok(pair)
						}
					}
				},
			}
		}
	}
}

pub trait Keccak256<T> {
	fn keccak256(&self) -> T where T: Sized;
}

impl Keccak256<[u8; 32]> for [u8] {
	fn keccak256(&self) -> [u8; 32] {
		let mut keccak = Keccak::new_keccak256();
		let mut result = [0u8; 32];
		keccak.update(self);
		keccak.finalize(&mut result);
		result
	}
}

#[cfg(test)]
mod tests {
	use super::Brain;

	#[test]
	fn test_brain() {
		let words = "this is sparta";
		let expected_address = b"\x00\x6E\x27\xB6\xA7\x2E\x1f\x34\xC6\x26\x76\x2F\x3C\x47\x61\x54\x7A\xff\x14\x21";

		let keypair = Brain::new(words).keypair().unwrap();

		assert_eq!(keypair.public().address(), expected_address);

	}

	fn test_empty_phrase() {
		let words = "";
		let expected_address = b"\x00\xa3\x29\xc0\x64\x87\x69\xA7\x3a\xfA\xc7\xF9\x38\x1E\x08\xFB\x43\xdB\xEA\x72";

		let keypair = Brain::new(words).keypair().unwrap();

		assert_eq!(keypair.public().address(), expected_address);
	}
}
