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
