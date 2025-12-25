AGE-PLUGIN-SE(1) "age-plugin-se @VERSION@" ""

# NAME

age-plugin-se - age plugin for Apple Secure Enclave


# SYNOPSIS

*age-plugin-se* *keygen* \[*--pq*\] \[*-o* _OUTPUT_\] \[*--access-control* _ACCESS_CONTROL_\] \[*--recipient-type* _RECIPIENT_TYPE_\]++
*age-plugin-se* *recipients* \[*--pq*\] \[*-o* _OUTPUT_\] \[*-i* _INPUT_\] \[*--recipient-type* _RECIPIENT_TYPE_\]


# DESCRIPTION

*age-plugin-se* is a plugin for age, enabling encryption protected by Apple's
Secure Enclave. It is automatically picked up by age for encryption and decryption
when the plugin is on the execution path.

The *keygen* subcommand generates a new private key (identity) bound to the
current Secure Enclave, with the given access controls, and outputs it to
_OUTPUT_ or standard output.

The *recipients* subcommand reads an identity file from _INPUT_ or standard
input, and outputs the corresponding recipient(s) to _OUTPUT_ or to standard
output.


# OPTIONS

*-i*, *--input* _INPUT_

	Read data from the file at path _INPUT_

*-o*, *--output* _OUTPUT_

	Write the result to the file at path _OUTPUT_

*--access-control* _ACCESS_CONTROL_

	Access control for using the generated key.
								
	When using current biometry, adding or removing a fingerprint stops the key
	from working. Removing an added fingerprint enables the key again. 

	Supported values: *none*, *passcode*, *any-biometry*,
	*any-biometry-and-passcode*, *any-biometry-or-passcode*,
	*current-biometry*, *current-biometry-and-passcode*.  Default:
	*any-biometry-or-passcode*.

*--pq*

	Generate post-quantum keys

*--recipient-type* _RECIPIENT_TYPE_

	Recipient type to generate.

	*tag* recipients use built-in support in age (>=v1.3.0), and don't require
	this plug-in to be installed to encrypt.

	Post-quantum keys (generated with *--pq*) always use the *tag* recipient type.

	Supported values: *se*, *tag*.
	Default: *se*.
	The default will change to *tag* in future versions.


# EXAMPLES

Generate a new key (identity) protected by biometry (e.g. Touch ID):

```
$ age-plugin-se keygen --access-control=any-biometry -o key.txt
Public key: age1se1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak
```

Encrypt data using the generated public key:

```
$ tar cvz ~/data | age -r age1se1qfn44rsw0xvmez3pky46nghmnd5up0jpj97nd39zptlh83a0nja6skde3ak
```

Decrypt the encrypted file:

```
$ age --decrypt -i key.txt data.tar.gz.age > data.tar.gz
```


# AUTHOR

Remko Tronçon <r@mko.re>


# SEE ALSO

age(1)

## Project homepage

https://github.com/remko/age-plugin-se


