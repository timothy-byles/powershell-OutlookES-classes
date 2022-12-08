# Helper functions

# Unless I missed something, PS doesn't provide methods to find index of a sub-array
# This works just like [string].SubString

function FindInArray([byte[]]$source, [byte[]]$find) {
	if ($find.Length -gt $source.Length) { throw 'search bytes are longer than source' }
	$end = $source.Length - $find.Length

	# 0 would be the first array index so -1 means not found
	$iFound = -1
	for ($pos = 0; ($iFound -eq -1) -and ($pos -le ($end)); $pos++) {
		# First find a match for the first element
		if ($source[$pos] -eq $find[0]) {
			# Then check the remaining elements
			$iFound = $pos
			for ($pos2 = 1; $pos2 -lt $find.Length; $pos2++) {
				if ($source[$pos + $pos2] -ne $find[$pos2]) {$iFound = -1; break}
			}
		}
	}
	return $iFound
}


# Very efficient and clever function I found on Stackoverflow, but adapted to PS
# Moved inline as I don't really need a count, I just need to know if there are more than 1
#function CountFlags([enum]$flags) {
#	$count = 0
#	while ($flags) {
#		# I think this would work with a bit shift but I haven't tested that way
#		$flags = $flags -band ($flags - 1)
#		$count++
#	}
#	return $count
#}


# Take a 40 char hex string and return a byte array
# This allows us to accept various types of input to specify a certificate
# Since Windows uses Little-Endian, we have to write it in reverse, then reverse the array

function tp2Hash([string]$tp) {
	$hash = [bigint]::parse($tp, 512).ToByteArray()
	if ([bitconverter]::IsLittleEndian) {[array]::Reverse($hash)}
	return $hash
}


###########################  BEGIN ESAlgorithmAsn custom class  ###########################

[Flags()] enum CryptAlgs {
	AES_256 = 1
	AES_192 = 2
	TripleDES = 4
	AES_128 = 8
	RC2_128 = 16
	RC2_64 = 32
}


# I could not figure out how to assign these during initialization so we'll just do them one-by-one >:-[
# Hashtable for ASN1 encoded encryption algorithms


$CryptAsn = @{[CryptAlgs]::AES_256 = [byte[]]@(0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2A)}
$CryptAsn[[CryptAlgs]::AES_192] = [byte[]]@(0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16)
$CryptAsn[[CryptAlgs]::TripleDES] = [byte[]]@(0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07)
$CryptAsn[[CryptAlgs]::AES_128] = [byte[]]@(0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02)
$CryptAsn[[CryptAlgs]::RC2_128] = [byte[]]@(0x30, 0x0E, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x02, 0x02, 0x02, 0x00, 0x80)
$CryptAsn[[CryptAlgs]::RC2_64] = [byte[]]@(0x30, 0x0D, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x02, 0x02, 0x01, 0x40)


[Flags()] enum HashAlgs {
	SHA_512 = 1
	SHA_384 = 2
	SHA_256 = 4
	SHA1 = 8
}


# Hashtable for ASN1 encoded hash algorithms


$HashAsn = @{[HashAlgs]::SHA_512 = [byte[]]@(0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)}
$HashAsn[[HashAlgs]::SHA_384] = [byte[]]@(0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)
$HashAsn[[HashAlgs]::SHA_256] = [byte[]]@(0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)
$HashAsn[[HashAlgs]::SHA1] = [byte[]]@(0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A)


# Custom class to handle creating or modifying the ASN1 data that Outlook holds in its email security settings

class ESAlgorithmAsn {
	# It's just one contiguous stream but the 'chosen' algs are moved to the head of each section
	# All encryption entries are listed first then hash entries
	# This is strictly ASN1 encoded data. The accompanying header is handled by the ESConfigSet class

	# Properties
	[CryptAlgs]$EncryptionAlgorithm
	[CryptAlgs]$OtherEncryptionAlgorithms
	[HashAlgs]$HashAlgorithm
	[HashAlgs]$OtherHashAlgorithms

	# Create a new instance with only one of each default and set them to the strongest available
	# This could be moved to a settings section at the beginning of the script
	ESAlgorithmAsn() {
		$this.EncryptionAlgorithm = [CryptAlgs]::AES_256
		$this.HashAlgorithm = [HashAlgs]::SHA_512
	}

	# Is the appropriate way to handle this? Should it be a function like LoadData($stream) ?
	# Maybe we could define a class function and here we would just use that function?
	ESAlgorithmAsn([byte[]]$stream) {
		$CryptAsn = $Script:CryptAsn
		$HashAsn = $Script:HashAsn

		# Currently we use FindInArray to search for each blob in the stream
		# I wonder if it would be more efficient to step through the stream?
		# Need to see what that code looks like since doing it this way loops through the stream quite a few times
		# However, this is very fast as-is and stepping through the stream means needing to parse ASN1 encoded data

		# firstEnum holds the enum of the blob found with the lowest index
		# This becomes the default while others are added to the $this.OtherAlgorithm
		$firstEnum = 0
		$firstPos = -1

		foreach ($enum in [CryptAlgs].GetEnumValues()) {
			$pos = FindInArray $stream $CryptAsn[$enum]
			if ($pos -ne -1) {
				$this.OtherEncryptionAlgorithms += $enum
				if (($firstPos -eq -1) -or ($pos -lt $firstPos)) {
					$firstPos = $pos
					$firstEnum = $enum
				}
			}
		}
		$this.EncryptionAlgorithm = $firstEnum
		# We know that Other also includes the default so we can subtract instead of using -band -bnot (see in GetBytes())
		$this.OtherEncryptionAlgorithms -= $firstEnum

		# Forgot to reset these at first and of course, got some unexpected results
		$firstEnum = 0
		$firstPos = -1

		foreach ($enum in [HashAlgs].GetEnumValues()) {
			$pos = FindInArray $stream $HashAsn[$enum]
			if ($pos -ne -1) {
				$this.OtherHashAlgorithms += $enum
				if (($firstPos -eq -1) -or ($pos -lt $firstPos)) {
					$firstPos = $pos
					$firstEnum = $enum
				}
			}
		}
		$this.HashAlgorithm = $firstEnum
		$this.OtherHashAlgorithms -= $firstEnum

	}# End constructor ESAlgorithmAsn($stream)

	# I can't imagine this string being longer than 65535 but we're going to code for it anyway
	hidden [uint64]GetDataLength() {
		# Globals aren't available here... who knew...
		$CryptAsn = $Script:CryptAsn
		$HashAsn = $Script:HashAsn

		[uint64]$size = 0
		$allCrypts = $this.EncryptionAlgorithm -bor $this.OtherEncryptionAlgorithms
		$allHashes = $this.HashAlgorithm -bor $this.OtherHashAlgorithms

		# Loop through enum values and see if each flag exists
		foreach ($enum in [CryptAlgs].GetEnumValues()) {
			if ($allCrypts -band $enum) {$size += $CryptAsn[$enum].length}
		}
		foreach ($enum in [HashAlgs].GetEnumValues()) {
			if ($allHashes -band $enum){$size += $HashAsn[$enum].length}
		}

		return $size
	}

	hidden [uint64]GetHeaderLength($dataLength) {
		# Minimum header size
		[byte]$size = 2

		# If the size is 0x80 or greater then the size must be stored in the next n bytes
		# 0x7F would be stored in this byte. 0x80 would be represented by 0x81,0x80

		# When total length is greater than 0x80, we have to set the greatest bit and use the
		# rest of this byte to define how many additional bytes are needed to express the total size
		# For example: if total size is 0xFF00FF then the ASN1 header will look like this
		# 0x0 = 0x30
		# 0x1 = 0x83	<- 0x80 || 0x03 for 3 bytes to express EE00FF
		# 0x30 0x83 0xFF 0x00 0xEE <rest of ASN1 data>
		if ($dataLength -ge 0x80) {
			while ($dataLength -ge 1) {$size++; $dataLength /= 256}
		}
		return $size
	}

	[uint64]GetLength() {
		$size = $this.GetDataLength()
		$size += $this.GetHeaderLength($size)
		return $size
	}

	# Build and return the stream
	[byte[]]GetBytes() {
		if ($this.HashAlgorithm -eq 0) {throw 'Must include default hash algorithm'}
		if ($this.EncryptionAlgorithm -eq 0) {throw 'Must include default encryption algorithm'}

		# If there is more than one flag set then you can catch it by using -band (flags - 1)
		if ($this.HashAlgorithm -band ($this.HashAlgorithm - 1)) {
				throw "Invalid flags for default Hash Algorithm: $this.HashAlgorithm"}
		if ($this.EncryptionAlgorithm -band ($this.EncryptionAlgorithm - 1)) {
				throw "Invalid flags for default Encryption Algorithm: $this.EncryptionAlgorithm"}

		# Make sure that Other doesn't contain the default flag
		$this.OtherEncryptionAlgorithms = $this.OtherEncryptionAlgorithms -band (-bnot $this.EncryptionAlgorithm)
		$this.OtherHashAlgorithms = $this.OtherHashAlgorithms -band (-bnot $this.HashAlgorithm)

		$outputArray = $null
		$defaultCrypt = $null
		$dataSize = $this.GetDataLength()

		# pos and headerSize are used synonymously
		$pos = $this.GetHeaderLength($dataSize)
		$outputArray = [byte[]]::new($dataSize + $pos)
		$outputArray[0] = [byte]0x30

		if ($pos -eq 2) {
			$outputArray[1] = [byte]$dataSize
		} else {
			$outputArray[1] = [byte]($pos - 2) -bxor 0x80
			
			$sizeBytes = [bitconverter]::GetBytes($dataSize)
			if ([bitconverter]::IsLittleEndian) {[array]::Reverse($sizeBytes)}

			# We need to skip leading zeros
			$iPos = 0
			# Find the first non-zero byte
			while ($sizeBytes[$iPos] -eq 0) {$iPos++}
			$iPos2 = 2
			# Start at pos 2 and copy elements until end of $sizeBytes
			while ($iPos -lt $sizeBytes.Length) {$outputArray[$iPos2++] = $sizeBytes[$iPos++]}
		}

		# Header is complete, now we can compile the ASN1 data
		$CryptAsn = $Script:CryptAsn
		$HashAsn = $Script:HashAsn

		$defaultCrypt = $CryptAsn[$this.EncryptionAlgorithm]
		$defaultCrypt.CopyTo($outputArray, $pos)
		$pos += $defaultCrypt.Length

		# This clever bit of code was written by bb-froggy (Christoph Hannebauer) https://github.com/bb-froggy
		#     based on the CountFlags function above
		# When I was looking at CountFlags, I thought about attempting this and then talked myself out of it
		# After seeing it in action, I think it makes sense to include it
		$enum = $this.OtherEncryptionAlgorithms
		while ($enum) {
			$enumLast = $enum
			# When you subtract 1 and -band to the original, you retain all flags save for the flag of highest value
			$enum = $enum -band ($enum - 1)
			# Here we use -bxor to extract the one flag we removed in the last step
			$addBytes = $CryptAsn[$enumLast -bxor $enum]
			$addBytes.CopyTo($outputArray, $pos)
			$pos += $addBytes.Length
		}

		$defaultHash = $HashAsn[$this.HashAlgorithm]
		$defaultHash.CopyTo($outputArray, $pos)
		$pos += $defaultHash.Length

		# Again, credit to bb-froggy (Christoph Hannebauer) https://github.com/bb-froggy
		$enum = $this.OtherHashAlgorithms
		while ($enum) {
			$enumLast = $enum
			$enum = $enum -band ($enum - 1)
			$addBytes = $HashAsn[$enumLast -bxor $enum]
			$addBytes.CopyTo($outputArray, $pos)
			$pos += $addBytes.Length
		}

		return $outputArray

	}# End method GetBytes
}# End class ESAlgorithmAsn

###########################  END ESAlgorithmAsn custom class  ###########################


###########################  BEGIN ESConfigSet custom class  ###########################

# We've been unable to reverse this data. So far it's the same 20-byte string for every config entry
# I suspect they could be for Cryptography format as well as security labels
# My limited tests showed that converting from Object[] -> Byte[] -> BigInt[] was slightly faster than using
#     a BigInt construtor to directly convert an Object[]
Set-Variable ESConfigStaticData -Option ReadOnly -value [bigint]'178416850623986534400950605670343782125010945'
		#([bigint][byte[]](0x1,0x0,0x8,0x0,0x1,0x0,0x0,0x0,0x6,0x0,0x8,0x0,0x1,0x0,0x0,0x0,0x20,0x0,0x8,0x0))

enum ESConfigItemID {
	AsnHashList = 0x02
	SignatureCertHash = 0x09
	NameA = 0x0B
	EncryptionCertHash = 0x22
	NameW = 0x51
}

[Flags()] enum ESConfigOption {
	Default1 = 1
	Default2 = 2
	SendWithMsgs = 4
}


# This class handles a complete configuration set in Outlook's Email Security section
# Each set has a flag for being default so when building the stream, we check for
#     multiple defaults and remove any duplicates

class ESConfigSet {
	[string]$Name = ''
	[ESConfigOption]$Options = [ESConfigOption]::SendWithMsgs
	[ESAlgorithmAsn]$AlgorithmAsn

	# Internal method to update both hash and thumbprint
	# This is wrapped by another hidden method with three overloads, each of which is wrapped by
	#     two public methods for encryption and for signature
	# I really love how this allowed me to have six public functions with minimal redundant code
	hidden [void]UpdateCertValues([string]$thumbprint, [byte[]]$hash, [bool]$isSig, [bool]$Force) {
		# We either need $Force set to true or we check that the certificate exists in the "My" cert store
		if ($Force -or (Test-Path "Cert:\currentuser\my\$thumbprint")) {
			$o = $this.PSObject.Properties

			# Here we set the cert type as a string and use that to generate the return values
			#     for the dynamically added properties
			$certType = if ($isSig) {'Signature'} else {'Encryption'}

			$nameHash = "$certType"+'CertHash'
			$nameTP = "$certType"+'CertThumbprint'
			$nameFunc = 'Set'+"$certType"+'Cert'

			$o.Remove($nameHash)
			$o.Remove($nameTP)

			# Generate the error message used by both properties
			$sbe = [ScriptBlock]::Create('throw ''This property is Read Only. To update the'+`
					" certificate, use $nameFunc(`$input) instead'")

			# This resolves to the value or $thumbprint so when the scriptblock is passed to the property 'Getter' method
			#     it is passed as a literal string versus linking back to a variable
			# I would have had to dynamically generate the variable name anyway, so this felt more efficient
			$sb = [ScriptBlock]::Create("return '$thumbprint'")
			$o.Add([PSScriptProperty]::New($nameTP, $sb, $sbe))
			$hashString = ([bitconverter]::ToString($hash)).Replace('-',',0x')
			$sb = [ScriptBlock]::Create("return ([byte[]](@(0x$hashString)))")
			$o.Add([PSScriptProperty]::New($nameHash, $sb, $sbe))
		} else {
			# Force flag was not set and cert was not found
			throw "Unable to find $thumbprint in 'My' certificate store`r`n"+`
			"Set to skip this check"
		}
	}

	hidden [void]SetCert([string]$thumbprint, [bool]$isSig, [bool]$Force) {
		if ($thumbprint.Length -ne 40) {throw "Bad length: $($thumbprint.Length). Expected 40"}
		$hash = tp2Hash $thumbprint
		$this.UpdateCertValues($thumbprint, $hash, $isSig, $Force)
	}

	hidden [void]SetCert([byte[]]$hash, [bool]$isSig, [bool]$Force) {
		if ($hash.Length -ne 20) {throw "Bad length: $($hash.Length). Expected 20"}
		$thumbprint = ([bitconverter]::ToString($hash)).Replace('-','')
		$this.UpdateCertValues($thumbprint, $hash, $isSig, $Force)
	}

	hidden [void]SetCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert, [bool]$isSig, [bool]$Force) {
		$this.UpdateCertValues($cert.Thumbprint, $cert.GetCertHash(), $isSig, $Force)
	}

	ESConfigSet([string]$name) {
		$this.Name = $name
		$this.Options = [ESConfigOption]::SendWithMsgs
	}

	ESConfigSet() {
		$this.Name = 'Default Settings'
		$this.Options = [ESConfigOption]::SendWithMsgs
	}

	# Create a new configset object and import the blob
	ESConfigSet([byte[]]$blob) {
		# First we check for the expected static data
		# If we figure out what this data means and/or how to parse it, this will need to be reworked
		$ESConfigStaticData = [bigint]'178416850623986534400950605670343782125010945'
		$staticData = [bigint]([byte[]]($blob[0..19]))
		if ($staticData -ne $ESConfigStaticData) {
			$sExpected = [bitconverter]::ToString($ESConfigStaticData.ToByteArray())
			$sReceived = [bitconverter]::ToString($staticData.ToByteArray())
			throw ((
				'Unexpected staticData',
				"Expected $sExpected",
				"Received $sReceived") -join "`n")
		}

		# Import options flags
		$this.Options = [bitconverter]::ToUint32($blob, 20)

		# Now begin stepping through the data from pos 24
		# These config items should work in any order but I haven't tested this
		$pos = 24
		while ($pos -lt $blob.length) {
			[ESConfigItemID]$id = [bitconverter]::ToUint16($blob, $pos)
			$itemSize = [bitconverter]::ToUint16($blob, $pos + 2)
			$end = $pos + $itemSize - 1
			$bData = $blob[($pos + 4)..$end]
			switch ($id) {
				([ESConfigItemID]::NameW) {
					if ($this.Name.Length -eq 0) {
						# End is Length - 1 and then - 2 more for the unicode null terminator
						$this.Name = [Text.Encoding]::Unicode.GetString($bData[0..($bData.Length - 3)])
					}
				}
				([ESConfigItemID]::NameA) {
					if ($this.Name.Length -eq 0) {
						# Strip the trailing null terminator
						$this.Name = [Text.Encoding]::ASCII.GetString($bData[0..($bData.Length - 2)])
					}
				}
				([ESConfigItemID]::EncryptionCertHash) {
					if ($bData.Length -ne 0x14) {throw "Invalid hash size: $($bData.Length), expected 20"}
					$thumbprint = ([bitconverter]::ToString($bData)).Replace('-','')
					$this.UpdateCertValues($thumbprint, $bData, $false, $true)
				}
				([ESConfigItemID]::SignatureCertHash) {
					if ($bData.Length -ne 0x14) {throw "Invalid hash size: $($bData.Length), expected 20"}
					$thumbprint = ([bitconverter]::ToString($bData)).Replace('-','')
					$this.UpdateCertValues($thumbprint, $bData, $true, $true)
				}
				([ESConfigItemID]::AsnHashList) {
					$this.AlgorithmAsn = [ESAlgorithmAsn]::New($bData)
				}
			}
			$pos = $end + 1
		}
	}# End ESConfigSet($blob) constructor

	# Six Certifiate function overloads to wrap three common hidden methods
	[void]SetSignatureCert([string]$thumbprint) {$this.SetCert($thumbprint, $true, $false)}
	[void]SetSignatureCert([string]$thumbprint, $Force) {$this.SetCert($thumbprint, $true, $Force)}
	[void]SetSignatureCert([byte[]]$hash) {$this.SetCert($hash, $true, $false)}
	[void]SetSignatureCert([byte[]]$hash, $Force) {$this.SetCert($hash, $true, $Force)}
	[void]SetSignatureCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
			$this.SetCert($cert, $true, $false)}
	[void]SetSignatureCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert, $Force) {
			$this.SetCert($cert, $true, $Force)}
	[void]SetEncryptionCert([string]$thumbprint) {$this.SetCert($thumbprint, $false, $false)}
	[void]SetEncryptionCert([string]$thumbprint, $Force) {$this.SetCert($thumbprint, $false, $Force)}
	[void]SetEncryptionCert([byte[]]$hash) {$this.SetCert($hash, $false, $false)}
	[void]SetEncryptionCert([byte[]]$hash, $Force) {$this.SetCert($hash, $false, $Force)}
	[void]SetEncryptionCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert) {
			$this.SetCert($cert, $false, $false)}
	[void]SetEncryptionCert([Security.Cryptography.X509Certificates.X509Certificate2]$cert, $Force) {
			$this.SetCert($cert, $false, $Force)}


	[uint64]GetLength() {
		# First check that we have a name as well as thumbprints for certificates
		# This is efficient because PS will short circuit with the first true statement
		if (($this.Name.Length -eq 0) -or
				($this.EncryptionCertHash.Length -eq 0) -or
				($this.SignatureCertHash.Length -eq 0) -or
				($this.AlgorithmAsn.Length -eq 0)) {
			return 0
		}

		# $size = 20	#$staticData.Length
		# $size += 24	#20 byte Encryption hash plus its header
		# $size += 24	#20 byte Signature hash plus its header
		# $size += 4	#Uint32 for options flags
		# $size += 4	#Header for unicode name
		# $size += 4	#Header for ASCII name
		# $size += 4	#ASN1 data header

		[uint64]$size = 84

		# Since we need the name in ASCII as well as Unicode and both null-terminated
		#    we can simply multiply the length with terminator * 3
		$size += ($this.Name.Length + 1) * 3

		$size += $this.AlgorithmAsn.GetLength()

		return $size
	}

	[byte[]]GetBytes() {
		# Calculate Total size and create a byte array of that size
		[uint64]$size = $this.GetLength()
		if ($size -eq 0) {
			if ($this.Name.Length -eq 0) {throw 'Name not set'}
			if ($this.EncryptionCertHash.Length -eq 0) {throw 'Encryption certificate not configured'}
			if ($this.SignatureCertHash.Length -eq 0) {throw 'Signature certificate not configured'}
			if ($this.AlgorithmAsn.Length -eq 0) {throw 'Algorithms object is missing'}
		}

		$outputArray = [byte[]]::New($size)

		# Insert static data
		([bigint]'178416850623986534400950605670343782125010945').ToByteArray().CopyTo($outputArray, 0)

		# Insert options flags
		([bitconverter]::GetBytes([uint16]($this.Options))).CopyTo($outputArray, 20)
		$pos = 24

		# This looks overly complicated but it reduced many lines of redundant code
		# For each item in this list...
		foreach ($entryID in @(
					[ESConfigItemID]::NameW,
					[ESConfigItemID]::NameA,
					[ESConfigItemID]::EncryptionCertHash,
					[ESConfigItemID]::SignatureCertHash,
					[ESConfigItemID]::AsnHashList)) {
			# ... execute the following block
			([bitconverter]::GetBytes([uint16]$entryID)).CopyTo($outputArray, $pos)
			$addBytes = switch ($entryID) {
				([ESConfigItemID]::NameW) {([Text.Encoding]::Unicode).GetBytes($this.Name + "`0")}
				([ESConfigItemID]::NameA) {([Text.Encoding]::ASCII).GetBytes($this.Name + "`0")}
				([ESConfigItemID]::EncryptionCertHash) {$this.EncryptionCertHash}
				([ESConfigItemID]::SignatureCertHash) {$this.SignatureCertHash}
				([ESConfigItemID]::AsnHashList) {$this.AlgorithmAsn.GetBytes()}
			}
			([bitconverter]::GetBytes([uint16]($addBytes.Length + 4))).CopyTo($outputArray, $pos + 2)
			$pos += 4
			$addBytes.CopyTo($outputArray, $pos)
			$pos += $addBytes.Length
		}
		return $outputArray
	}
}# End class ESConfigSet

###########################  END ESConfigSet custom class  ###########################


###########################  BEGIN ESConfig custom class  ###########################


class ESConfig {
	[ESConfigSet[]]$Entries

	# I didn't see a reason to make these visible
	# These can still be called explicitly, they just don't show in the autocomplete list or when using Get-Member
	# This method ensures that only one config set has the default flag and removes any duplicates beyond first found
	hidden [void]ValidateDefault() {
		# I'm not able to have the 2 defaults separated to different config sets on my system
		#     but it might be possible on someone else's systems so we run this once for each default flag
		foreach ($config in @([ESConfigOption]::Default1, [ESConfigOption]::Default2)) {
			# Iterate entries and verify that only one is default
			$default = ''
			foreach ($entry in $this.Entries) {
				if ($entry.Options -band $config) {
					if ($default) {
						Write-Host "Removing $config flag from '$($entry.Name)' because '$default' is already default"
						$entry.Options = $entry.Options -band ( -bnot $config)
					} else {
						$default = $entry.Name
					}
				}
			}
			if ($default -eq '') {
				Write-Host "Setting '$($this.Entries[0].Name)' as default"
				$this.Entries[0].Options = $this.Entries[0].Options -bor $config
			}
		}
	}

	# This tries to intelligently rename any duplicate names
	hidden [void]ValidateNames() {
		if ($this.Entries.Count -gt 1) {
			$bFound = $true
			while ($bFound) {
				$bFound = $false
				for ($i1 = 0; $i1 -lt $this.Entries.Count - 1; $i1++) {
					$number = 2
					for ($i2 = $i1 + 1; $i2 -lt $this.Entries.Count; $i2++) {
						if ($this.Entries[$i1].Name -eq $this.Entries[$i2].Name) {
							$bFound = $true
							$this.Entries[$i2].Name += " ($number)"
							$number++
						}
					}
				}
			}
		}
	}

	# If constructed with no params, generate some default settings
	ESConfig() {
		$entry = [ESConfigSet]::New('DefaultSettings')
		$entry.Options = [ESConfigOption]::SendWithMsgs -bor
				[ESConfigOption]::Default1 -bor [ESConfigOption]::Default2
		$this.Entries = [ESConfigSet[]]::New(1)
		$this.Entries[0] = $entry
	}

	# Construct a new object and import everything from the blob
	ESConfig( [byte[]]$colBlob ) {
		# Do some basic error checking
		$pos = 0
		$numEntries = [bitconverter]::ToUint32($colBlob, 0)

		# Check that the total size is at least 4 + 0x10 * number of entries
		if ($colBlob.Length -lt (4 + ($numEntries * 0x10))) {
				throw 'Data too short: $($colBlob.Length), expected miminum $(4 + ($numEntries * 0x10))'}

		# Skip to the last entry, add offset + size and verify it matches the size of the blob
		$pos = (($numEntries - 1) * 0x10) + 4
		$end = [bitconverter]::ToUint64($colBlob, $pos) + [bitconverter]::ToUint64($colBlob, $pos + 8)
		if ($end -ne $colBlob.Length) {
			if ($end -ge $colBlob.Length) {
				throw 'Settings data appears to be corrupted (Data offset is beyond end of data)'
			} else {
				# Sometimes Outlook seems to add padding after the end so we'll verify that it's all zeros
				foreach ($byte in $colblob[$end..($colBlob.Length - 1)]) {
					if ($byte -ne 0) {throw 'Settings appear to be corrupted (Data beyond last offset)'}
				}
			}
		}

		# import each settings entry
		$this.Entries = [ESConfigSet[]]::new($numEntries)
		for ($i = 0;$i -lt $numEntries;$i++) {
			$pos = 4 + ($i * 0x10)
			$entrySize = [bitconverter]::ToUint64($colBlob, $pos)
			$offset = [bitconverter]::ToUint64($colBlob, $pos + 8)
			[byte[]]$blob = $colBlob[($offset)..($offset + $entrySize - 1)]
			$this.Entries[$i] = [ESConfigSet]::new($blob)
		}

		$this.ValidateDefault()
		$this.ValidateNames()
	}

	# Adds a new config set
	[void]AddEntry([ESConfigSet]$set) {
		$this.Entries = $this.Entries + $set
		$this.ValidateDefault()
		$this.ValidateNames()
	}

	# The default collection is fixed size so we have to generate a new one
	[void]RemoveEntry([uint32]$index) {
		if ($index -lt $this.Entries.Count -and $index -ge 0) {
			$newArray = [ESConfigSet[]]::new($this.Entries.Count - 1)

			$i1 = 0
			$i2 = 0
			while ($i1 -lt $this.Entries.Count) {
				if ($i1 -eq $index) {$i1++}
				$newArray[$i2++] = $this.Entries[$i1++]
			}

			$this.Entries = $newArray
			$this.ValidateDefault()
			$this.ValidateNames()
		} else {
			throw "$index is out of bounds. Expected to be from 0 to $($this.Entries.Count - 1)"
		}
	}

	[void]RemoveEntryByName([string]$name) {
		for ($index = 0; $index -lt $this.Entries.Count; $index++) {
			if ($this.Entries[$index].Name.Trim() -eq $name) {
				$this.RemoveEntry($index)
				break
			} else {
				throw 'No ConfigSet found with that name'
			}
		}
	}

	[void]SetDefaultEntry([int]$index) {
		if ($index -lt $this.Entries.Count -and $index -ge 0) {
			for ($i = 0; $i -lt $this.Entries.Count; $i++) {
				if ($i -eq $index) {
					$this.Entries[$i].Options = $this.Entries[$i].Options -bor
							[ESConfigOption]::Default1 -bor [ESConfigOption]::Default2
				} else {
					$this.Entries[$i].Options = $this.Entries[$i].Options -band ( -bnot
							([ESConfigOption]::Default1 -bor [ESConfigOption]::Default2))
				}
			}
		} else {
			"$index is out of bounds. Expected to be from 0 to $($this.Entries.Count - 1)"
		}
	}

	[void]SetDefaultEntry([string]$name) {
		for ($i = 0; $i -lt $this.Entries.Count; $i++) {
			if ($name -eq $this.Entries[$i].Name) {
				$this.SetDefaultEntry([uint32]$i)
				break
			}
		}
	}

	# If I figure out how to separate the two default flags, I'll have to rewrite this
	[uint32]GetDefaultAllIndex() {
		$this.ValidateDefault()
		for ($i = 0; $i -lt $this.Entries.Count; $i++) {
			if ($this.Entries[$i].Options = $this.Entries[$i].Options -bor [ESConfigOption]::Default2) {
				break
			}
		}
		return $i
	}

	[uint64]GetLength() {
		[uint64]$Size = (($this.Entries.Count * 0x10) + 4)
		foreach ($entry in $this.Entries) {$size += $entry.GetLength()}
		return $Size
	}

	[byte[]]GetBytes() {
		$this.ValidateDefault()
		$this.ValidateNames()

		$outputArray = [byte[]]::New($this.GetLength())
		([bitconverter]::GetBytes([uint32]$this.Entries.Count)).CopyTo($outputArray, 0)

		# We need to step back and forth so we need to keep track of data position as well as toc position
		$tocPos = 4
		[uint64]$dataPos = (($this.Entries.Count * 0x10) + 4)

		# Add each settings entry and update the TOC
		foreach ($entry in $this.Entries) {
			$curBlob = $entry.GetBytes()
			([bitconverter]::GetBytes([uint64]$curBlob.Length)).CopyTo($outputArray, $tocPos)
			$tocPos += 8
			([bitconverter]::GetBytes($dataPos)).CopyTo($outputArray, $tocPos)
			$tocPos += 8
			$curBlob.CopyTo($outputArray, $dataPos)
			$dataPos += $curBlob.Length
		}
		return $outputArray
	}

}# End class ESConfig

###########################  BEGIN ESConfig custom class  ###########################


###########################  BEGIN Top level functions  ###########################

function Get-OutlookProfileList() {
	return (gi HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\).GetSubKeyNames()
}

function Get-OutlookESConfig([string]$profileName) {
	if (Test-Path "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$profileName\c02ebc5353d9cd11975200aa004ae40e") {
		$blob = (gp "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$profileName\c02ebc5353d9cd11975200aa004ae40e" -Name 11020355).11020355
		return [ESConfig]::New($blob)
	}
}

function Set-OutlookESConfig([string]$profileName, [ESConfig]$ESConfig, [switch]$noBackup) {
	$key = "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$profileName\c02ebc5353d9cd11975200aa004ae40e"

	if (Test-Path $key) {
		$dest = Get-ItemProperty "$key" -Name 11020355 -EA Silent
		$newConfig = $ESConfig.GetBytes()
		if ($newConfig) {
			if ($dest) {
				if (! $noBackup -and $null -eq (gp "$key" -Name '11020355.bak' -EA Silent)) {
					$bak = gp "$key" -Name 11020355
					New-ItemProperty -Path "$key" -Name '11020355.bak' -Value $bak -PropertyType 'Binary' -EA Silent -OutVariable null
				}
				sp -Path "$key" -Name 11020355 -Value $ESConfig.GetBytes()
			} else {
				New-ItemProperty -Path "$key" -Name 11020355 -Value $newConfig -PropertyType 'Binary' -EA Silent -OutVariable null
			}
		} else {
			throw 'Unable to generate config set'
		}
	} else {
		throw "$profileName is missing cryptography settings. Unable to apply Email Security settings"
	}
}

###########################  END Top level functions  ###########################
