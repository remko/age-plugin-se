AGE-PLUGIN-SE(1) "age-plugin-se @VERSION@" "age-plugin-se manual"

# NAME

age-plugin-se - age plugin for Apple Secure Enclave


# SYNOPSIS

*age-plugin-se* *keygen* \[*-o* _OUTPUT_\] \[*--access-control* _ACCESS_CONTROL_\]++
*age-plugin-se* *recipients* \[*-o* _OUTPUT_\] \[*-i* _INPUT_\]


# DESCRIPTION

The *keygen* subcommand generates a new private key bound to the current Secure
Enclave, with the given access controls, and outputs it to _OUTPUT_ or standard
output.

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


# EXAMPLES

Generate a new key protected by biometry (e.g. Touch ID):

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


# SEE ALSO

age(1)


# AUTHORS

Remko Tronçon <r@mko.re>
