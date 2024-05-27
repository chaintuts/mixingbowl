/* This script contains code for encrypting and decrypting text with AES and PBKDF2
*
* Author: Josh McIntyre
*/

// Wrapper functions for fetching inputs, calling cryptographic functions, and outputting the results
async function encrypt()
{
	try
	{
		plaintext = getPlaintextFromDocument();
		passphrase = getPassphraseFromDocument();
		salt = getSaltFromDocument();
		iv = getIVFromDocument();

		ciphertext = await encryptAES(plaintext, passphrase, salt, iv);
	}
	catch(err)
	{
		ciphertext = "Error encrypting plaintext";
	}

	setCiphertextInDocument(ciphertext);
}

async function decrypt()
{
	try
	{
		ciphertext = getCiphertextFromDocument();
		passphrase = getPassphraseFromDocument();
		salt = getSaltFromDocument();
		iv = getIVFromDocument();
		
		plaintext = await decryptAES(ciphertext, passphrase, salt, iv);
	}
	catch(err)
	{
		plaintext = "Error decrypting ciphertext";
	}
	
	setPlaintextInDocument(plaintext);
	
}

// Cryptographic operations
async function encryptAES(plaintext, passphrase, salt, iv)
{
	const enc = new TextEncoder();
	
	var keyMaterial =  await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits", "deriveKey"]);

	var deriveParams = {name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256"}
	var deriveParamsAES = { name: "AES-CBC", length: 256 }
	const key = await window.crypto.subtle.deriveKey(deriveParams, keyMaterial, deriveParamsAES, true, ["encrypt", "decrypt"]);

	var encryptParams = {name: "AES-CBC", iv: iv };
	var plaintextEnc = enc.encode(plaintext);
	const ciphertextBuffer = await window.crypto.subtle.encrypt(encryptParams, key, plaintextEnc);

	var ciphertext = encodeB64Buffer(ciphertextBuffer);


	return ciphertext;
}

async function decryptAES(ciphertext, passphrase, salt, iv)
{
	const enc = new TextEncoder();
	
	var keyMaterial =  await window.crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits", "deriveKey"]);

	var deriveParams = {name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256"}
	var deriveParamsAES = { name: "AES-CBC", length: 256 }
	const key = await window.crypto.subtle.deriveKey(deriveParams, keyMaterial, deriveParamsAES, true, ["encrypt", "decrypt"]);

	var decryptParams = {name: "AES-CBC", iv: iv };
	var ciphertextDec = decodeB64(ciphertext)
	const plaintextBuffer = await window.crypto.subtle.decrypt(decryptParams, key, ciphertextDec);
	
	var plaintext = decodeBuffer(plaintextBuffer);

	return plaintext;
}

function initialize()
{
	salt = generateSalt();
	iv = generateIV();
	
	setSaltInDocument(salt);
	setIVInDocument(iv);
}

function generateSalt()
{
	var salt = window.crypto.getRandomValues(new Uint8Array(16));
	
	return salt;
	
}

function generateIV()
{
	var iv = window.crypto.getRandomValues(new Uint8Array(16));
	
	return iv;
}

// Encoding and decoding
function encodeB64(value)
{
	valueEncoded = btoa(String.fromCharCode.apply(null, value));

	return valueEncoded;
}

function encodeB64Buffer(value)
{
	valueEncoded = btoa(String.fromCharCode.apply(null, new Uint8Array(value)));

	return valueEncoded;
}

function decodeB64(valueEncoded)
{
	var valueString = window.atob(valueEncoded);
	var valueBuffer = new ArrayBuffer(valueString.length);
	var value = new Uint8Array(valueBuffer);
	
	for (let i = 0; i < valueString.length; i++)
	{
		value[i] = valueString.charCodeAt(i);
	}
	
	return value;
}

function decodeBuffer(valueEncoded)
{
	var decoder = new TextDecoder();
	
	var value = decoder.decode(new Uint8Array(valueEncoded));
	
	return value;
}


// Document interaction functions
function getPlaintextFromDocument()
{
	var plaintext = document.getElementById("plaintext").value;

	return plaintext;
}

function getCiphertextFromDocument()
{
	var ciphertext = document.getElementById("ciphertext").value;

	return ciphertext;
}

function getPassphraseFromDocument()
{
	var passphrase = document.getElementById("passphrase").value;

	return passphrase;
}

function getSaltFromDocument()
{
	var saltEncoded = document.getElementById("salt").value;
	var salt = decodeB64(saltEncoded);

	return salt;
}

function getIVFromDocument()
{
	var ivEncoded = document.getElementById("iv").value;
	var iv = decodeB64(ivEncoded);

	return iv;
}

function setCiphertextInDocument(ciphertext)
{
	document.getElementById("ciphertext").value = ciphertext;
}

function setPlaintextInDocument(plaintext)
{
	document.getElementById("plaintext").value = plaintext;
}

function setSaltInDocument(salt)
{
	saltEncoded = encodeB64(salt);
	document.getElementById("salt").value = saltEncoded;
}

function setIVInDocument(iv)
{
	ivEncoded = encodeB64(iv);
	document.getElementById("iv").value = ivEncoded;
}
