#!/usr/bin/env ruby
# Stand alone tool that can be used to extract local password hashes
# from an exported SYSTEM and SAM registry hive.	Lots and lots and lots
# of these codes are stolen from the Metasploitz
# contact: Royce Davis @r3dy__ royce.e.davis@gmail.com
require 'digest'
require 'openssl'

# This method was taken from tools/reg.rb	thanks bperry for all of your efforts!!
class Hashdump
	def get_boot_key(hive)
		begin
			return if !hive.root_key
			return if !hive.root_key.name
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
				bootkey << [tmp].pack("H*")
			end
			keybytes = bootkey.unpack("C*")
			p = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
			scrambled = ""
			p.each do |i|
				scrambled << bootkey[i]
			end
			return scrambled
		rescue StandardError => bootkeyerror
#			puts("Error ubtaining bootkey. #{bootkeyerror}")
			return bootkeyerror
		end
	end


	# More code from tools/reg.rb
	def get_hboot_key(sam, bootkey)
		num = "0123456789012345678901234567890123456789\0"
		qwerty = "!@#\$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
		account_path = "\\SAM\\Domains\\Account"
		accounts = sam.relative_query(account_path)
		f = nil
		accounts.value_list.values.each do |value|
			if value.name == "F"
				f = value.value.data
			end
		end
		raise "Hive broken" if not f
		md5 = Digest::MD5.digest(f[0x70,0x10] + qwerty + bootkey + num)
		rc4 = OpenSSL::Cipher::Cipher.new('rc4')
		rc4.key = md5
		return rc4.update(f[0x80,0x20])
	end


	# Some of this taken from tools/reb.rb some of it is from hashdump.rb some of it is my own...
	def dump_creds(sam, sys)
		empty_lm = "aad3b435b51404eeaad3b435b51404ee"
		empty_nt = "31d6cfe0d16ae931b73c59d7e0c089c0"
		bootkey = get_boot_key(sys)
		hbootkey = get_hboot_key(sam, bootkey)
		users = get_users(sam)
		usercount = users.size
		response = ''
		begin
			users.each do |user|
				if usercount == 1
					return response
				end
				rid = user.name.to_i(16)
				hashes = get_user_hashes(user, hbootkey)
				obj = []
				obj << get_user_name(user)
				obj << ":"
				obj << rid
				obj << ":"
				if hashes[0].empty?
					hashes[0] = empty_lm
				else
					hashes[0] = hashes[0].unpack("H*")
				end
				if hashes[1].empty?
					hashes[1] = empty_nt
				else
					hashes[1] = hashes[1].unpack("H*")
				end
				obj << hashes[0]
				obj << ":"
				obj << hashes[1]
				obj << ":::"
				if obj.length > 0
					response << "#{obj.join}\n"
				end
				usercount = usercount - 1
			end
		rescue StandardError => dumpcreds
			return ""
		end
	end

	# Method extracts usernames from user keys, modeled after credddump
	def get_user_name(user_key)
		v = ""
		user_key.value_list.values.each do |value|
			v << value.value.data if value.name == "V"
		end
		name_offset = v[0x0c, 0x10].unpack("<L")[0] + 0xCC
		name_length = v[0x10, 0x1c].unpack("<L")[0]
		return v[name_offset, name_length]
	end


	# More code from tools/reg.rb
	def get_users(sam_hive)
		begin
			# Get users from SAM hive
			users = []
			sam_hive.relative_query('\SAM\Domains\Account\Users').lf_record.children.each do |user_key|
				users << user_key unless user_key.name == "Names"
			end
		rescue StandardError => getuserserror
#			puts("Unable to retrieve users from SAM hive. Method get_users. #{getuserserror}")
			return getuserserror
		end
	end


	# More code from tools/reg.rb
	def get_user_hashes(user_key, hbootkey)
		rid = user_key.name.to_i(16)
		v = nil
		user_key.value_list.values.each do |value|
			v = value.value.data if value.name == "V"
		end
		hash_offset = v[0x9c, 4].unpack("<L")[0] + 0xCC
		lm_exists = (v[0x9c+4, 4].unpack("<L")[0] == 20 ? true : false)
		nt_exists = (v[0x9c+16, 4].unpack("<L")[0] == 20 ? true : false)
		lm_hash = v[hash_offset + 4, 16] if lm_exists
		nt_hash = v[hash_offset + (lm_exists ? 24 : 8), 16] if nt_exists
		return decrypt_hashes(rid, lm_hash || nil, nt_hash || nil, hbootkey)
	end


	# More code from tools/reg.rb
	def decrypt_hashes(rid, lm_hash, nt_hash, hbootkey)
		ntpwd = "NTPASSWORD\0"
		lmpwd = "LMPASSWORD\0"
		begin
			# Try to decrypt hashes
			hashes = []
			if lm_hash
				hashes << decrypt_hash(rid, hbootkey, lm_hash, lmpwd)
			else
				hashes << ""
			end
			if nt_hash
				hashes << decrypt_hash(rid, hbootkey, nt_hash, ntpwd)
			else
				hashes << ""
			end
			return hashes
		rescue StandardError => decrypthasherror
#			puts("Unable to decrypt hashes. Method: decrypt_hashes. #{decrypthasherror}")
			return decrypthasherror
		end
	end


	# This code is taken straight from hashdump.rb
	# I added some comments for newbs like me to benefit from
	def decrypt_hash(rid, hbootkey, enchash, pass)
		begin
			# Create two des encryption keys
			des_k1, des_k2 = sid_to_key(rid)
			d1 = OpenSSL::Cipher::Cipher.new('des-ecb')
			d1.padding = 0
			d1.key = des_k1
			d2 = OpenSSL::Cipher::Cipher.new('des-ecb')
			d2.padding = 0
			d2.key = des_k2
			#Create MD5 Digest
			md5 = Digest::MD5.new
			#Decrypt value from hbootkey using md5 digest
			md5.update(hbootkey[0,16] + [rid].pack("V") + pass)
			#create rc4 encryption key using md5 digest
			rc4 = OpenSSL::Cipher::Cipher.new('rc4')
			rc4.key = md5.digest
			#Run rc4 decryption of the hash
			okey = rc4.update(enchash)
			#Use 1st des key to decrypt first 8 bytes of hash
			d1o	= d1.decrypt.update(okey[0,8])
			d1o << d1.final
			# Use second des key to decrypt second 8 bytes of hash
			d2o	= d2.decrypt.update(okey[8,8])
			d1o << d2.final
			value = d1o + d2o
			return value
		rescue StandardError => desdecrypt
 #		 puts("Error while decrypting with DES. #{desdecrypt}")
			return desdecrypt
		end
	end


	# More code from tools/reg.rb
	def sid_to_key(sid)
		s1 = ""
		s1 << (sid & 0xFF).chr
		s1 << ((sid >> 8) & 0xFF).chr
		s1 << ((sid >> 16) & 0xFF).chr
		s1 << ((sid >> 24) & 0xFF).chr
		s1 << s1[0]
		s1 << s1[1]
		s1 << s1[2]
		s2 = s1[3] + s1[0] + s1[1] + s1[2]
		s2 << s2[0] + s2[1] + s2[2]
		return string_to_key(s1), string_to_key(s2)
	end


	# More code from tools/reg.rb
	def string_to_key(s)
		parity = [
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
		key << (s[0].unpack('C')[0] >> 1)
		key << ( ((s[0].unpack('C')[0]&0x01)<<6) | (s[1].unpack('C')[0]>>2) )
		key << ( ((s[1].unpack('C')[0]&0x03)<<5) | (s[2].unpack('C')[0]>>3) )
		key << ( ((s[2].unpack('C')[0]&0x07)<<4) | (s[3].unpack('C')[0]>>4) )
		key << ( ((s[3].unpack('C')[0]&0x0F)<<3) | (s[4].unpack('C')[0]>>5) )
		key << ( ((s[4].unpack('C')[0]&0x1F)<<2) | (s[5].unpack('C')[0]>>6) )
		key << ( ((s[5].unpack('C')[0]&0x3F)<<1) | (s[6].unpack('C')[0]>>7) )
		key << ( s[6].unpack('C')[0]&0x7F)
		0.upto(7).each do |i|
			key[i] = (key[i]<<1)
			key[i] = parity[key[i]]
		end
		return key.pack("<C*")
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


	class RegfBlock

		attr_accessor :timestamp, :root_key_offset

		def initialize(hive)

			regf_header = hive[0x00, 4]

			if regf_header !~ /regf/
#				puts "Not a registry hive"
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
#				puts "no vk at offset #{offset}"
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
end

#sys = Hive.new(ARGV[0])
#sam = Hive.new(ARGV[1])
#dump_creds(sam, sys)
