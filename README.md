OutlookES classes

This provides custom classes to work with Outlook 2016's email security settings in trust center.
Included are some top level functions to list outlook profiles, retrieve the data from a 
given profile, and to set data into the correct registry key.


Notes:
- The ESAlgorithmAsn class does not parse ASN1 data. Instead, the binary streams for each algorithm type are stored as byte arrays and
	the resultant stream is generated as an ASN1 stream of sub-streams

- One of the helper functions if FindInArray. This is not only used in the classes but is also useful for error checking or testing.
	If you load existing settings from the current profile and then use FindInArray to compare
	[ESConfig].GetBytes() to the original blob. If no changes are made, both blobs should be identical (ignoring any padding that Outlook
	may have appended

- I found that sometimes Outlook will append padding to config sets. Data generated from these classes will not have that padding.

- These classes provide the ability to remove algorithms from the ASN1 stream. In my testing this did not actually prevent them from
	displaying in email security settings dialog

- It's possible to have an algorithm flag set as the default in an ESAlgorithmAsn object as well as set in the Other* property of the same
	type. This is perfectly safe and the algo duplicate will be removed when generating the resultant stream

- If you have multiple flags set in the default has or encryption property for an ESAlgorithmAsn object when you call GetBytes(), it will
	throw an error and fail to complete

- The thumbprint and hash properties are read-only and will throw an error if you try to set one. Instead use either
	SetSignatureCert or SetEncryptionCert as described below

- Once you load settings into an [ESConfig] object, you are able to manipulate the attached sub-objects and then write the settings back to
	the registry. Eash GetBytes method will call the GetBytes() method of its sub-object, thus saving changes made to said sub-object



Usage:

Get-OutlookProfileList
Retrieves a list of Outlook profiles in the current user's list

Get-OutlookESConfig -profileName name
Returns an object of type ESConfig for the given profile. This contains the whole collection of all email security configurations

Set-OutlookESConfig -profileName name -ESConfig [byte[]] binary_blob [-noBackup]
This will save the new data back to the registry key for current user. If a settings key already exists, it will be backed up unless -nobackup is set




[ESConfig] class

property [ESConfigSet[]] Entries
Collection of config sets indexed by int


constructor New()
constructor New($name)

Create a new instance of ESConfig object with a single config set and the name specified or a name of "Default Settings"

method New([byte[]]$blob)
Create a new instance of ESConfig object and import data from the byte array. This byte array is pulled directly from the settings registry key.

method AddEntry([ESConfigSet]$set)
Add a configSet object to the Entries collection. This object can be created using [ESConfigSet]::New('name')

method RemoveEntry([int]$index)
Removes a configset from the collection

method SetDefaultEntry((int]$index)
method SetDefaultEntry([string]$name)
Mark the designated configset as default

method GetLength()
Returns the total length of the byte array that would be created with GetBytes()

method GetBytes()
Returns a byte array of all config sets. This can be written directly to the settings registry key



[ESConfigSet] class

property [string] Name
Name of the config set. This is the same name you would see in email security settings for this set

property [ESConfigOption] Options
This is an enum collection of settings. The only currently known settings are Default 1 and 2 which correspond to
	"Default Security Setting for this cryptographic message format" and "Default Security Setting for all cryptographic messages
	as well as "Send these certificates with signed messages"
It's unknown which default represents which setting. These are labelled Default1 and Default2 in the enum structure
The third option is labelled SendWithMsgs in the enum

property [ESAlgorithmAsn] AlgorithmAsn
This is an ASN1 stream of data. This can be created or loaded using [ESAlgorithmAsn]::New() or [ESAlgorithmAsn]::New([byte[]]$stream) respectively

property [byte[]] SignatureCertHash
This is a read-only binary hash of the chosen signature cert

property [string] SignatureCertThumbprint
This is a read-only string representation of the hash

property [byte[]] EncryptionCertHash
This is a read-only binary has of the chosen encryption cert

property [string] EncryptionCertThumbprint
This is a read-only string representation of the hash


method New()
method New([string]$name)
This creates a new instance of the object with the given name of with a name of "Default Settings" if not provided

method New([byte[]]$blob)
This creates a new instance of the object and imports settings from the provided blob. This blob is the same binary data that exists in
	the ESConfig.Entries collection as a single index

The following 12 methods allow to set/updatea the signature or encryption certifates chosen for this config set
The function will validate that the chosen certificate is available in the current user's cert store unless $Force is set to true
SetSignatureCert([string]$thumbprint
SetSignatureCert([string]$thumbprint, $Force
SetSignatureCert([byte[]]$hash
SetSignatureCert([byte[]]$hash, $Force
SetSignatureCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert
SetSignatureCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert, $Force
SetEncryptionCert([string]$thumbprint
SetEncryptionCert([string]$thumbprint, $Force
SetEncryptionCert([byte[]]$hash
SetEncryptionCert([byte[]]$hash, $Force
SetEncryptionCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert
SetEncryptionCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert, $Force

method GetLength()
Get the length of the byte array that would be output by GetBytes()

method GetBytes()
Generates and returns a byte array of the current config set. This can be added to the [ESConfig].Entries collection using [ESConfig].AddEntry($blob)



[ESAlgorithm] class

enum [CryptAlgs]
AES_256
AES_192
TripleDES
AES_128
RC2_128
RC2_64

enum [HashAlgs]
SHA_512
SHA_384
SHA_256
SHA1

property enum EncryptionAlgorithm
The chosen encryption algorithm for this config set. This uses [CryptAlgs]

property enum HashAlgorithm
The chosen hash algorithm for this config set. This uses [HashAlgs]

property enum OtherEncryptionAlgorithms
Additional algorithms available in the list. This uses [CryptAlgs]

property enum OtherHashAlgorithms
Additional algorithms available in the list. This uses [HashAlgs]

constructor New()
This will create a new instance of this object with defaults set to AES_256 and SHA_512 with the Other* properties null/blank

constructor New([byte[]]$stream)
This will create a new instance and load the data from an existing binary stream

method GetLength()
Returns the lenght of the byte array that would be generated from GetBytes()

method GetBytes()
Returns a byte array of the constructed or reconstructed stream of ASN1 encoded data




