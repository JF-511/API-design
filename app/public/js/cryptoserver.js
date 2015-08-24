'use strict';

if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle) {
	window.crypto.subtle = window.crypto.webkitSubtle;
}
if (!window.crypto || !window.crypto.subtle) {
	alert("Your browser does not support the Web Cryptography API! This page will not work.");
}

// Sends catched error to the server
window.onerror = function(message, url, lineNumber) {
	throw new Error(message);
	let data = JSON.stringify({
		message: message,
		url: url,
		lineNumber: lineNumber
	});
	// Try to send it to the server
	$.ajax({
			type: 'POST',
			url: '/client_errors',
			data: data
	});
};

// Used to generate jti
function uuid() {
	return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
		let r = Math.random()*16|0, v = c == 'x' ? r : (r&0x3|0x8);
		return v.toString(16);
	});
}

let Woodland_jwk = {
	kty: "RSA",
	n: "3_PxevqxtVBsqRJeLvroRXjkSndDKA6_aX6lSW5WqeJeimr89OIlHh8mz-S3HRHsdNGdG-mkhBPsYGdui2vimC21ter-GAIXWQi2lgjZtbSfRFeBuYa-2EL5685s15MEUwUj9QbK8E10oKPGrAZpO3xhH3FnpliW7nLFiCQBxQtmrpNieUiFFoLPsqB3tQbfbU7dxz33tyRYWyd_C3hHqbwL7J80fDiANukTnvftuffgjpqKQk4LN7wEaGwzj87fgUYak6JkdPSL9qRept2Nse8rvfKF1EW08Gh8fbh_MJ4uV4EK6vIW7mklp75qEzCT124InOgTHllJQwhtelcC1w",
	e: "AQAB"
}

// Init Jose cryptographer
let cryptographer = new Jose.WebCryptographer();

$( document ).ready(function() {
	
// --------------------------- Signing Key ---------------------------
/*
	Function generates a CryptoKey object for JWT signing
	Private key will be used to JWT sign the requests
	Public key will be sent to the Signing Services so they could store it and use to verify the clients requests
*/
function generateSigningKey() {
		
	const signing_key = crypto.subtle.generateKey(
		{
			name: "RSASSA-PKCS1-v1_5",
			modulusLength: 2048, //can be 1024, 2048, or 4096
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
		},
		true, //whether the key is extractable (i.e. can be used in exportKey)
		["sign", "verify"] //can be any combination of "sign" and "verify"
	);
		
	return signing_key;
}
/* 
	Submit key generation form
*/
$('#genSigningkey').submit(function(e){
	e.preventDefault(); // Do not submit naturally
		// Generate CryptoKey
	generateSigningKey().then(function(signing_key){
		// Store CryptoKey object in session
		window.signing_key = signing_key;

		$('#genSigningkey').html('New key generated and stored in session.');

	}).catch(function(err){
		console.error('Generate key promise error: ', err);
	});
});

// --------------------------- Encryption Key ---------------------------
/*
	Function generates a CryptoKey object for JWE encryption of signed tokens
	Public key will be sent to the Signing Services so they could store it and use to encrypt responses to the client
	Private key will be used to decrypt those responses
*/
function generateEncryptionKey() {
		
	const encryption_key = crypto.subtle.generateKey(
		{
			name: "RSA-OAEP",
			modulusLength: 2048, //can be 1024, 2048, or 4096
			publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
			hash: {name: "SHA-256"}, //can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
		},
		true, //whether the key is extractable (i.e. can be used in exportKey)
		["encrypt", "decrypt", "wrapKey", "unwrapKey"] //must contain both "encrypt" and "decrypt"
	);
		
	return encryption_key;
}
/* 
	Submit key generation form
*/
$('#genEncryptionkey').submit(function(e){
	e.preventDefault(); // Do not submit naturally

	// Generate CryptoKey
	generateEncryptionKey().then(function(encryption_key){

		// Store CryptoKey object in session
		window.encryption_key = encryption_key;

		$('#genEncryptionkey').html('New key generated and stored in session.');

	}).catch(function(err){
		console.error('Generate key promise error: ', err);
	});
});

// --------------------------------------------------------
/*
	Submit a key generation form
	Client is going to generate a new asymmetric key with the help of the Signing Oracle.
	Signing oracle should send a public part of generated key back.
	Also it is going to hold a private part for the future uses by the client.
*/
// Submit form
$('#generateKey').submit(function (e) {
	e.preventDefault(); // Do not submit naturally
	
	cryptographer.setContentSignAlgorithm("RS256");
	
	let signer = new JoseJWS.Signer(cryptographer);

	co(function* () {

		let s_public_key_jwk;
		let e_public_key_jwk;
		try {
			s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);
			e_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.encryption_key.publicKey);

		} catch (e) {
			console.error('Export signing_key error: ', e);
		}

		const sPayload = {
			//iss: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}, // Issuer public key
			iat: Date.now(), // Issued at
			jti: uuid(),
			usages: ["sign", "verify"],
			exportable: false,
			owner: {
				sign: {
					jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
				},
				encrypt: {
					jwk: {n: e_public_key_jwk.n, e: e_public_key_jwk.e, kty: e_public_key_jwk.kty, alg: e_public_key_jwk.alg}
				} 	
			},
			async: document.querySelector('#generateKey input[id="async"]').checked // Indicates that operation should be performed in async mode
		};

		// Set key generation algorithm
		if (document.querySelector('#generateKey input[id="ECDSA"]').checked) {
			// Client want to generate ECDSA key
			sPayload.algorithm = {
				name: "ECDSA",
				namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
			};
		} else {
			// RSA key
			sPayload.algorithm = {
				name: "RSASSA-PKCS1-v1_5",
				modulusLength: 2048,
				publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
				hash: {name: "SHA-256"}
			};
		}
		// Show parameters on the page
		$('#generateKeyParams').html('Request (JWT signed K1 in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

		let sResult;
		try {
			yield signer.addSigner(window.signing_key.privateKey, '1');

			sResult = yield signer.sign(sPayload, null, {});
		} catch (e) {
			console.log('Jose sign error: ', e);
		}

		// Signed result
		const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

		// Import Woodland K0 public key
		const public_rsa_key = Jose.Utils.importRsaPublicKey(Woodland_jwk);
		
		let encrypted_result;
		try {
			//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
			let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

			// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
			encrypted_result = yield encrypter.encrypt(signed_result);
		} catch (e) {
			console.log('Jose encryption error: ', e);
		}
		
		// Prepare request data
		const data = JSON.stringify({
			token: encrypted_result
		});

		// Make async POST request containing all of the data in the body
		$.ajax({
			type: 'POST',
			url: '/api/keys',
			processData: false,
			contentType: 'application/json',
			data: data,
			success: function(data)
			{ 
				// Parse JWT
				let parsed_sig;
				try {
					const jws = new KJUR.jws.JWS();
					jws.parseJWS(data.token);

					// Parse response claims
					parsed_sig = JSON.parse(jws.parsedJWS.payloadS);

					// If operation was asynchronous
					if (sPayload.async === true) {
						// Result should contain a location
						// Save it to the session
						window.async_loc = parsed_sig.data.location;
					} else {
						console.log('parsed_sig: ' , parsed_sig);
						// Save received key and generated key id
						window.public_key = parsed_sig.data.public_key.jwk;
						window.key_id = parsed_sig.data.id;  
					}
				} catch (e) {
					console.log('Parse JWS error: ', e);
				}
							
				// Update key field with response
				$('#generateKeyResponse').html('Response signed K2: <pre>' + JSON.stringify(data, null, 4) + '</pre>Parsed: <pre>'+JSON.stringify(parsed_sig, null, 4)+'</pre>Received K2 public key and ID stored in session.');
			},
			error: function (data) {
				$('#generateKeyResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
			},
		});
	});

});

	// --------------------------------------------------------
	// Get key by id

	// Submit form
	$('#getKey').submit(function (e) {

		e.preventDefault(); // Do not submit naturally
	
		cryptographer.setContentSignAlgorithm("RS256");
		
		let signer = new JoseJWS.Signer(cryptographer);

		co(function* () {

			let s_public_key_jwk;
			try {
				s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);

			} catch (e) {
				console.error('Export signing_key error: ', e);
			}

			const sPayload = {
				iat: Date.now(), // Issued at
				jti: uuid(),
				owner: {
					sign: {
						jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
					}
				}
			};

			// Show parameters on the page
			$('#getKeyParams').html('Request (JWT signed K1 in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

			let sResult;
			try {
				yield signer.addSigner(window.signing_key.privateKey, '1');

				sResult = yield signer.sign(sPayload, null, {});
			} catch (e) {
				console.log('Jose sign error: ', e);
			}

			// Signed result
			const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

			// Import Woodland K0 public key
			const public_rsa_key = Jose.Utils.importRsaPublicKey(window.public_key);
			
			let encrypted_result;
			try {
				//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
				let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

				// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
				encrypted_result = yield encrypter.encrypt(signed_result);
			} catch (e) {
				console.log('Jose encryption error: ', e);
			}
			
			// Prepare request data
			const data = 'token=' + encrypted_result;

			console.log('window.key_id: ', window.key_id);

			// Make async POST request containing all of the data in the body
			$.ajax({
				type: 'GET',
				url: '/api/keys/'+window.key_id,
				processData: false,
				contentType: 'application/json',
				data: data,
				success: function(data)
				{ 
					// Parse JWT
					let parsed_sig;
					try {
						const jws = new KJUR.jws.JWS();
						jws.parseJWS(data.token);

						// Parse response claims
						parsed_sig = JSON.parse(jws.parsedJWS.payloadS);

						$('#getKeyResponse').html('Response signed K2: <pre>' + JSON.stringify(data, null, 4) + '</pre>Verified K2 and parsed: <pre>' + JSON.stringify(parsed_sig, null, 4) + '</pre>');

					} catch (e) {
						console.log('Parse JWS error: ', e);
					}
				},
				error: function (data) {
					$('#getKeyResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
				},
			});
		});
	});

	// --------------------------------------------------------
	// Delete key by id

	// Submit form
	$('#deleteKey').submit(function (e) {

		e.preventDefault(); // Do not submit naturally
	
		cryptographer.setContentSignAlgorithm("RS256");
		
		let signer = new JoseJWS.Signer(cryptographer);

		co(function* () {

			let s_public_key_jwk;
			try {
				s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);

			} catch (e) {
				console.error('Export signing_key error: ', e);
			}

			const sPayload = {
				iat: Date.now(), // Issued at
				jti: uuid(),
				owner: {
					sign: {
						jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
					}
				},
				async: document.querySelector('#deleteKey input[type="checkbox"]').checked
			};

			// Show parameters on the page
			$('#getKeyParams').html('Request (JWT signed K1 in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

			let sResult;
			try {
				yield signer.addSigner(window.signing_key.privateKey, '1');

				sResult = yield signer.sign(sPayload, null, {});
			} catch (e) {
				console.log('Jose sign error: ', e);
			}

			// Signed result
			const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

			// Import Woodland K0 public key
			const public_rsa_key = Jose.Utils.importRsaPublicKey(window.public_key);
			
			let encrypted_result;
			try {
				//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
				let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

				// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
				encrypted_result = yield encrypter.encrypt(signed_result);
			} catch (e) {
				console.log('Jose encryption error: ', e);
			}
			
			// Prepare request data
			// Prepare request data
			const data = JSON.stringify({
				token: encrypted_result
			});

			// Make async POST request containing all of the data in the body
			$.ajax({
				type: 'DELETE',
				url: '/api/keys/'+window.key_id,
				processData: false,
				contentType: 'application/json',
				data: data,
				success: function(data)
				{ 
					// Parse JWT
					let parsed_sig;
					try {
						const jws = new KJUR.jws.JWS();
						jws.parseJWS(data.token);

						// Parse response claims
						parsed_sig = JSON.parse(jws.parsedJWS.payloadS);

						// If operation was asynchronous
						if (sPayload.async === true) {
							// Result should contain a location
							// Save it to the session
							window.async_loc = parsed_sig.data.location;
						}

						$('#deleteKeyResponse').html('Response signed K0: <pre>' + JSON.stringify(data, null, 4) + '</pre>Parsed: <pre>' + JSON.stringify(parsed_sig, null, 4) + '</pre>');

					} catch (e) {
						console.log('Parse JWS error: ', e);
					}
				},
				error: function (data) {
					$('#deleteKeyResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
				},
			});
		});
	});

	// --------------------------------------------------------
	/*
	Submit sign data form
	
	Prepares a JWT with the payload containing a set of claims:
	iss: String issuer
	exp: Number expiration period in milliseconds
	iat: Date issued at
	algorithm: Object containing algorithm to sign data with in a WebCrypto-friendly format
		name:
		modulusLength:
		publicExponent:
		hash:
	data_string: String data to sign
	*/

	$('#signData').submit(function (e) {

		e.preventDefault(); // Do not submit naturally
	
		cryptographer.setContentSignAlgorithm("RS256");
		
		let signer = new JoseJWS.Signer(cryptographer);

		co(function* () {

			let s_public_key_jwk;
			try {
				s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);

			} catch (e) {
				console.error('Export signing_key error: ', e);
			}

			const sPayload = {
				iat: Date.now(), // Issued at
				jti: uuid(),
				owner: {
					sign: {
						jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
					}
				},
				algorithm: {
					name: "RSASSA-PKCS1-v1_5"
				},
				data_string: 'some data',
				async: document.querySelector('#signData input[type="checkbox"]').checked
			};

			// Show parameters on the page
			$('#signDataParams').html('Request (JWT signed K1 in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

			let sResult;
			try {
				yield signer.addSigner(window.signing_key.privateKey, '1');

				sResult = yield signer.sign(sPayload, null, {});
			} catch (e) {
				console.log('Jose sign error: ', e);
			}

			// Signed result
			const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

			// Import Woodland K0 public key
			const public_rsa_key = Jose.Utils.importRsaPublicKey(window.public_key);
			
			let encrypted_result;
			try {
				//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
				let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

				// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
				encrypted_result = yield encrypter.encrypt(signed_result);
			} catch (e) {
				console.log('Jose encryption error: ', e);
			}
			
			// Prepare request data
			// Prepare request data
			const data = JSON.stringify({
				token: encrypted_result
			});

			// Make async POST request containing all of the data in the body
			$.ajax({
				type: 'POST',
				url: '/api/keys/'+window.key_id+'/sign',
				processData: false,
				contentType: 'application/json',
				data: data,
				success: function(data)
				{ 
					// Verify incoming JWS with the public key K2
							const toVerify = {
								header: {},
								protected: data.token.split('.')[0],
								payload: data.token.split('.')[1],
								signature: data.token.split('.')[2]
							};

							const verifier = new JoseJWS.Verifier(cryptographer, toVerify);
							
							const jwk = window.public_key;

							verifier.addRecipient(jwk, '1').then(function() {

								verifier.verify().then(function(verified) {

									// Parse JWS to show its contents
									let parsed_sig;
									try {
										const jws = new KJUR.jws.JWS();
										jws.parseJWS(data.token);
										parsed_sig = JSON.parse(jws.parsedJWS.payloadS);

										// If operation was asynchronous
										if (sPayload.async === true) {
											// Result should contain a location
											// Save it to the session
											window.async_loc = parsed_sig.data.location;
												
											$('#signDataResponse').html('Response signed K2: <pre>' + JSON.stringify(data, null, 4) + '</pre>Verified K2 and parsed response contains Base64 encoded signature: <pre>' + JSON.stringify(parsed_sig, null, 4) + '</pre>');
										}
									} catch (e) {
										console.log('JWS parse error');
									}

									// Update field with response
									if (verified[0].verified) {
										$('#signDataResponse').html('Response signed K2: <pre>' + JSON.stringify(data, null, 4) + '</pre>Verified K2 and parsed response contains Base64 encoded signature: <pre>' + JSON.stringify(parsed_sig, null, 4) + '</pre>');
									} else {
										$('#signDataResponse').html('Failed to verify response with public K2');
									}

								}).catch(function(e) {
									console.log("verification failed: " + e);
								});
							
							}); 
				},
				error: function (data) {
					$('#signDataResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
				},
			});
		});
	});

	// --------------------------------------------------------
	/*
	Submit List all user keys form
	*/
	$('#listAllKeys').submit(function (e) {

		e.preventDefault(); // Do not submit naturally
	
		cryptographer.setContentSignAlgorithm("RS256");
		
		let signer = new JoseJWS.Signer(cryptographer);

		co(function* () {

			let s_public_key_jwk;
			try {
				s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);

			} catch (e) {
				console.error('Export signing_key error: ', e);
			}

			const sPayload = {
				iat: Date.now(), // Issued at
				jti: uuid(),
				owner: {
					sign: {
						jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
					}
				}
			};

			// Show parameters on the page
			$('#listAllKeysParams').html('Request (JWT signed in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

			let sResult;
			try {
				yield signer.addSigner(window.signing_key.privateKey, '1');

				sResult = yield signer.sign(sPayload, null, {});
			} catch (e) {
				console.log('Jose sign error: ', e);
			}

			// Signed result
			const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

			// Import Woodland K0 public key
			const public_rsa_key = Jose.Utils.importRsaPublicKey(Woodland_jwk);
			
			let encrypted_result;
			try {
				//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
				let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

				// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
				encrypted_result = yield encrypter.encrypt(signed_result);
			} catch (e) {
				console.log('Jose encryption error: ', e);
			}
			
			// Prepare request data
			const data = 'token=' + encrypted_result + '&page=1&limit=25';

			// Make async POST request containing all of the data in the body
			$.ajax({
				type: 'GET',
				url: '/api/keys/',
				processData: false,
				contentType: 'application/json',
				data: data,
				success: function(data)
				{ 
					// Parse JWT
					let parsed_sig;
					try {
						const jws = new KJUR.jws.JWS();
						jws.parseJWS(data.token);

						// Parse response claims
						parsed_sig = JSON.parse(jws.parsedJWS.payloadS);

						// If operation was asynchronous
						if (sPayload.async === true) {
							// Result should contain a location
							// Save it to the session
							window.async_loc = parsed_sig.data.location;
						}

						$('#listAllKeysResponse').html('Response signed K0: <pre>' + JSON.stringify(data, null, 4) + '</pre>Parsed: <pre>' + JSON.stringify(parsed_sig, null, 4) + '</pre>');

					} catch (e) {
						console.log('Parse JWS error: ', e);
					}
				},
				error: function (data) {
					$('#listAllKeysResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
				},
			});
		});
	});

	// --------------------------------------------------------
	// Delete all user keys

	// Submit form
	$('#deleteAllKeys').submit(function (e) {
		e.preventDefault(); // Do not submit naturally
	
		cryptographer.setContentSignAlgorithm("RS256");
		
		let signer = new JoseJWS.Signer(cryptographer);

		co(function* () {

			let s_public_key_jwk;
			try {
				s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);

			} catch (e) {
				console.error('Export signing_key error: ', e);
			}

			const sPayload = {
				iat: Date.now(), // Issued at
				jti: uuid(),
				owner: {
					sign: {
						jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
					}
				},
				async: document.querySelector('#deleteAllKeys input[type="checkbox"]').checked
			};

			// Show parameters on the page
			$('#deleteAllKeysParams').html('Request (JWT signed K1 in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

			let sResult;
			try {
				yield signer.addSigner(window.signing_key.privateKey, '1');

				sResult = yield signer.sign(sPayload, null, {});
			} catch (e) {
				console.log('Jose sign error: ', e);
			}

			// Signed result
			const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

			// Import Woodland K0 public key
			const public_rsa_key = Jose.Utils.importRsaPublicKey(Woodland_jwk);
			
			let encrypted_result;
			try {
				//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
				let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

				// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
				encrypted_result = yield encrypter.encrypt(signed_result);
			} catch (e) {
				console.log('Jose encryption error: ', e);
			}
			
			// Prepare request data
			const data = JSON.stringify({
				token: encrypted_result
			});

			// Make async POST request containing all of the data in the body
			$.ajax({
				type: 'DELETE',
				url: '/api/keys/',
				processData: false,
				contentType: 'application/json',
				data: data,
				success: function(data)
				{ 
					// deleteKey going to be signed K0, verify here if needed

							// Parse JWT
							let parsed_sig;
							try {
								const jws = new KJUR.jws.JWS();
								jws.parseJWS(data.token);

								parsed_sig = JSON.parse(jws.parsedJWS.payloadS);

								// If operation was asynchronous
								if (sPayload.async === true) {
									// Result should contain a location
									// Save it to the session
									window.async_loc = parsed_sig.data.location;
								}
							} catch (e) {
								console.log('JWS parse error');
							}

							// Update key field with response
							$('#deleteAllKeysResponse').html('Response signed K0: <pre>' + JSON.stringify(data, null, 4) + '</pre>Parsed: <pre>' + JSON.stringify(parsed_sig, null, 4) + '</pre>');
				},
				error: function (data) {
					$('#deleteAllKeysResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
				},
			});
		});
	});

	// --------------------------------------------------------
	// Get async operation status

	// Submit form
	$('#asyncStatus').submit(function (e) {

		e.preventDefault(); // Do not submit naturally
	
		cryptographer.setContentSignAlgorithm("RS256");
		
		let signer = new JoseJWS.Signer(cryptographer);

		co(function* () {

			let s_public_key_jwk;
			try {
				s_public_key_jwk = yield crypto.subtle.exportKey("jwk", window.signing_key.publicKey);

			} catch (e) {
				console.error('Export signing_key error: ', e);
			}

			const sPayload = {
				iat: Date.now(), // Issued at
				jti: uuid(),
				owner: {
					sign: {
						jwk: {n: s_public_key_jwk.n, e: s_public_key_jwk.e, kty: s_public_key_jwk.kty}
					}
				}
			};

			// Show parameters on the page
			$('#asyncStatusParams').html('Request (JWT signed K1 in background):<pre>' + JSON.stringify(sPayload, null, 4) + '</pre>');

			let sResult;
			try {
				yield signer.addSigner(window.signing_key.privateKey, '1');

				sResult = yield signer.sign(sPayload, null, {});
			} catch (e) {
				console.log('Jose sign error: ', e);
			}

			// Signed result
			const signed_result = sResult.protected + '.' + sResult.payload + '.' + sResult.signature;

			// Import Woodland K0 public key
			const public_rsa_key = Jose.Utils.importRsaPublicKey(Woodland_jwk);
			
			let encrypted_result;
			try {
				//let private_rsa_key = Jose.Utils.importRsaPrivateKey(rsa_key);
				let encrypter = new JoseJWE.Encrypter(cryptographer, public_rsa_key);

				// Encrypt request with K0 Signing Service public key (client discovers it by GET /cryptoservice)
				encrypted_result = yield encrypter.encrypt(signed_result);
			} catch (e) {
				console.log('Jose encryption error: ', e);
			}
			
			// Prepare request data
			const data = 'token=' + encrypted_result;

			// Make async POST request containing all of the data in the body
			$.ajax({
				type: 'GET',
				url: '/api' + window.async_loc,
				processData: false,
				contentType: 'application/json',
				data: data,
				success: function(data)
				{ 
					let parsed_sig;
					try {
						// Parse JWT
						const jws = new KJUR.jws.JWS();
						jws.parseJWS(data.token);

						// Parse response claims
						parsed_sig = JSON.parse(jws.parsedJWS.payloadS);
					} catch (e) {
						console.log('Parse JWS error: ', e);
					}
							
					// Update key field with response
					$('#asyncStatusResponse').html('Response signed K0: <pre>' + JSON.stringify(data, null, 4) + '</pre>Parsed: <pre>'+JSON.stringify(parsed_sig, null, 4)+'</pre>');
				},
				error: function (data) {
					$('#asyncStatusResponse').html('Response: <pre>' + JSON.stringify(JSON.parse(data.responseText), null, 4) + '</pre>');
				},
			});
		});
	});

});