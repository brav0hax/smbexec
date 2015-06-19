require 'stringio'
require 'socket'
require 'resolv'
require 'timeout'
require 'base64'
require 'readline'

begin
	require 'nmap/xml'
	require 'netaddr'
rescue LoadError => e
	puts e
	puts
	puts "Load error: Make sure the Ruby gems are installed properly, run bundle install"
	puts
	exit!
end

module Utils

	# Because lazy, quick readline function
	def rgets(prompt = ' ', default_value = '')
		line = Readline.readline("#{prompt}", true)
		line = default_value if line.empty?
		return line.rstrip
	end

	# Open IO to save stderr
	def save_stderr
		out, $stderr = $stderr, StringIO.new
		yield
		$stderr.string
	ensure
		$stderr = out
	end
	
	# Remaps standard error to file, yields to code enclosed, then resets
	def capture_stderr_poet(thread)
		local = "#{Menu.opts[:log]}/debug/stderr_#{thread}"
		previous_stdout = $stderr.clone
		$stderr.reopen(local)
		yield
		read_file(local)
	ensure
		$stderr.reopen(previous_stdout)
		file_delete(local)
	end

	# Remaps standard error to file, yields to code enclosed, then resets
	def capture_stderr(local = '/dev/null')
		previous_stdout = $stderr.clone
		$stderr.reopen(local)
		yield
	ensure
		$stderr.reopen(previous_stdout)
	end

	# Remaps standard out to file, yields to code enclosed, then resets
	def capture_stdout(local)
		previous_stdout = $stdout.clone
		$stdout.reopen(local)
		yield
	ensure
		$stdout.reopen(previous_stdout)
	end

	# Lazy way to catch signal expections
	def catch_sig(&block)
		begin
			block.call
		rescue SignalException
		end
	end

	# COLOR YAY!
	# Bold teal on black 
	def color_title(text); "\e[1;36;40m#{text}\e[0m"; end
	# Bold blue on black
	def highlight(text); "\e[1;34;40m#{text}\e[0m"; end
	# highlight red
	def highlight_red(text); "\e[1;31;40m#{text}\e[0m"; end
	# Teal on black
	def color_banner(text); "\e[36;40m#{text}\e[0m"; end
	# Bold blue
	def color_header(text); "\e[1;4;34m#{text}\e[0m"; end

	def print_good(text); puts "\e[1;32m[+]\e[0m #{text}"; end
	def print_warning(text); puts "\e[1;33m[!]\e[0m #{text}"; end
	def print_bad(text); puts "\e[1;31m[-]\e[0m #{text}"; end
	def print_status(text); puts "\e[1;34m[*]\e[0m #{text}"; end

	def vprint_good(text); puts "\e[1;32m[+]\e[0m #{text}" if Menu.opts[:verbose]; end
	def vprint_warning(text); puts "\e[1;33m[!]\e[0m #{text}" if Menu.opts[:verbose]; end
	def vprint_bad(text); puts "\e[1;31m[-]\e[0m #{text}" if Menu.opts[:verbose]; end
	def vprint_status(text); puts "\e[1;34m[*]\e[0m #{text}" if Menu.opts[:verbose]; end

	# Returns IP of device with route to IP (google currently)
	def local_ip(ip = nil)
		begin
			addr = ip || '64.233.187.99'

			orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true 
			UDPSocket.open do |s|
				s.connect addr, 1
				s.addr.last
			end
		rescue
			return ''
		end
	ensure
		Socket.do_not_reverse_lookup = orig
	end

	# If no host set use this to resolve IPs
	# For now just prints IPv4
	def all_local_ips
		ips = []
		Socket.ip_address_list.each do |ip|
			unless ip.ipv4_loopback? or ip.ipv6_loopback?
				ips << ip.ip_address if ip.ipv4?
			end
		end
		return ips
	end

	# prompt user for host list
	def get_addr
		print "\nTarget IP, host list, or nmap XML file [#{Menu.get_banner(:hosts)}]" 
		host_input = rgets(" : ")

		if host_input.empty? and Menu.opts[:hosts].nil?
			return nil
		elsif host_input.empty? 
			hosts = Menu.opts[:hosts]
		else
			hosts = parse_addr(host_input)
		end

		# ensure we have hosts to scan
		if hosts.nil?
			return nil
		elsif hosts.empty?
			return nil			
		end

		return hosts
	end

	# Accept IP address formats and produce list
	# Ex: CIDR, nmap, 1.1.1.1-1.1.2.254
	def parse_addr(range)
		if File.file? range and range[-4,4].eql? ".xml"
			temp_range = []
			Nmap::XML.new(range) do |xml|
				xml.each_host do |host|
					# Add hosts to array if 139 or 445 is open
					ports_array = host.ports.map! {|port| port.to_i}
					temp_range << host.to_s unless (ports_array & [139, 445]).empty?
				end
			end
			# No need to continue parsing, return array of hosts
			return temp_range
		elsif File.file? range
			contents = File.read(range)
			range = contents.gsub(/\n/, ' ')
		end

		addrs = Array.new
		begin
			range.split(' ').each { |e| 
				e = e.chomp(',')
				# If CIDR
				if e =~ /\/\d{1,2}$/
					NetAddr::CIDR.create(e).enumerate.each {|i| addrs << i}
				# If 1.1.1.1-2.2.2.2
				elsif e =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})-([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/
					start, fin  = NetAddr::CIDR.create($1), NetAddr::CIDR.create($2)
					# Sanity check to make sure first address comes first
					return nil if NetAddr.ip_to_i(start.to_s.chomp('/32')) > NetAddr.ip_to_i(fin.to_s.chomp('/32'))
					(start..fin).entries.each {|i| addrs << i.to_s.chomp('/32')}
				# If normal IP
				elsif e =~ /^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$/
					addrs << e
				else
				# If nmap style
					# Add in combine for IP addresses
					# Enter target network range [192.168.0.0/24] : 1,2-3.1.1.1-5
					# [["1", "2", "3"], ["1"], ["1"], ["1", "2", "3", "4", "5"]]
					# To list of IPs
					ip_split = e.split('.')
					return nil if ip_split.length != 4

					# Create arry of array, sub array contains all octet variants
					ip_split.map! { |octet|
						octet = octet.split(',') 
						# Remap octets to arraies of possible values
						octet.map! { |suboctet|
							# Transform any wildcards to numerical
							if suboctet.include?('*')
								suboctet = '0-255'
							end
							# If octet contains a range
							if suboctet.include?('-')
								# Split and check if two numbers were given or implicit 0/255 given
								first, second = suboctet.split('-')
								first = 0 unless first
								second = 255 unless second
								first, second = first.to_i, second.to_i
								# Sanity check to make sure valid octet
								return nil if first > second or not first.between?(0,255) or not second.between?(0,255)
								suboctet = []
								# Create a range for octet possible values and add them to array
								(first..second).entries.each {|g| suboctet << g.to_s}
								suboctet
							else
								# Hack to make it an array of 1 element
								temp = suboctet
								suboctet = []
								suboctet << temp
							end
						}
					}

					# Flatten any third level arrays to only array or array
					ip_split.map! {|octet|
						octet.flatten!
					}

					# Create an address for each variant of octet
					ip_split[0].each {|a|
						ip_split[1].each {|b|
							ip_split[2].each {|c|
								ip_split[3].each {|d|
									addrs << "#{a}.#{b}.#{c}.#{d}"
								}
							}
						}
					}
				end
			}
		rescue => e
			puts e
		end
		return addrs
	end

	# Method takes list of CIDR or IPs and converts to smallest list of CIDR
	def to_cidr(range)
		range.map! {|i| i << "/32" unless i =~ /\/\d{1,2}$/ }
		range = NetAddr.merge(range)
		return range
	end

	def win_portscan(host)
		begin
			sock = Socket.new(:INET, :STREAM)
			Timeout.timeout(1) do
				raw = Socket.sockaddr_in(139, host)
				return true if sock.connect(raw)
			end	
		rescue
			if sock != nil
				sock.close
			end
		end

		begin
			sock = Socket.new(:INET, :STREAM)
			Timeout.timeout(1) do
				raw = Socket.sockaddr_in(445, host)
				return true if sock.connect(raw)
			end	
		rescue
			if sock != nil
				sock.close
			end
		end
		return false
	end

	# Write string to file, with optional location
	def write_file(contents, name, local = Menu.opts[:log], overwrite = false)
		begin
			# Make sure locaiton ends in a slash
			if not local =~ /\/$/
				local = "#{local}/"
			end
			backup_file("#{local}#{name}") unless overwrite
			File.open("#{local}#{name}", 'w') { |file| file.write(contents) }
		rescue => e
			print_bad("Issues saving file: #{e}")
		end
	end
	
	def read_file(file)
		begin
			File.read(file)
		rescue => e
			print_bad("Issues saving file: #{e}")
		end
	end

	# Rename a file
	def rename_file(infile, outfile)
		begin
			File.rename(infile, outfile)
		rescue => e
			print_bad("Issues saving file: #{e}")
		end
	end

	# if directory exists, return true
	def folder_exists(path)
		begin
			return File.directory?(path)
		rescue => e
			return nil
		end
	end

	# create directory
	def create_folder(path)
		begin
			Dir.mkdir(File.join(path), 0700)
			return true
		rescue => e
			puts "Issues creating folder: #{e}"
			return false
		end
	end
	
	# method to determine if a file exists on local system
	def file_exists?(file)
		begin
			File.exists?(file) if file
		rescue IOError => e
			print_warning("Issues checking file: #{e}")
		end	
	end

	def file_delete(file)
		begin
			File.delete(file)
		rescue IOError => e
			print_warning("Issues deleting file: #{e}")
		end	
	end

	def backup_file(file)
		if file_exists?(file)
			backup = File.split(file)
			rename_file(file, "#{backup[0]}/#{backup[1]}_#{Time.now.utc.iso8601}")
			vprint_status("#{file} already exists, backing up")
		end
	end
	
	# Query DNS to get records concerning DCs
	def get_dcs
		if not Menu.opts[:domain].empty? and not Menu.opts[:domain].eql? '.'
			begin
				Timeout.timeout(3) {
					pdc = ''
					resolver = Resolv::DNS.new
					resolver.getresources("_ldap._tcp.pdc._msdcs.#{Menu.opts[:domain]}.com", Resolv::DNS::Resource::IN::SRV).collect { |resource|
						pdc = resource.target.to_s
					}

					dcs = []
					resolver = Resolv::DNS.new
					resolver.getresources("_ldap._tcp.dc._msdcs.#{Menu.opts[:domain]}.com", Resolv::DNS::Resource::IN::SRV).collect { |resource|
						dcs << resource.target.to_s
					}
					return pdc, dcs
				}
			rescue Timeout::Error
				return '',''
			end
		end
	end

	def random_name
		(0...8 + Random.rand(4)).map{
			t = ''
			until t =~ /[a-zA-Z0-9]/
				t = (48+rand(74)).chr
			end
			t
		}.join
	end
end

# Monkey see monkey patch
class String
	# Escape characters
	def escape!(chars = '"')
		pattern = []
		slash = false

		# Split string into array of characters and build out regex
		chars.split(//).each do |char|
			
			# If it is a backslash we do something special to handle
			unless char.eql? '\\'
				pattern << char
			end
		end

		# Escape any odd numbered series of backslashes, regex FTW
		regex = /(?<!\\)(\\\\)*\\(?!\\)/
		self.gsub!(regex){|match| "\\" + match}

		temp = self.split('')
		return temp.map! { |char| 
			char = "\\#{char}" if pattern.include? char
			char
		}.join
	end

	# Return true if properly formated ntlm hash
	def is_ntlm?
		!!(self =~ /^[a-z0-9]{32}:[a-z0-9]{32}$/)
	end

	# Determine if a string is a valid IP address, v4 or v6 accepted
	def valid_ip?
		if self =~ Resolv::IPv4::Regex ? true : false
			return true
		elsif self =~ Resolv::IPv6::Regex ? true : false
			return true
		else
			return false
		end
	end

	# Remove defined characters from string
	def strip_chars!(chars)
		chars = Regexp.escape(chars)
		self.gsub!(/[#{chars}]/, "")
	end

	def to_ps_base64!
		# Remove ISE chars
		self.gsub!(/[\x00ef|\x00bb|\x00bf]/, '')
		# Convert to base64 and add null character between each character
		Base64.encode64(self.split('').join("\x00") << "\x00").gsub!("\n", '')
  end

  def is_ssl?
    if self[0..4] == 'https'
      ssl = true
    else
      ssl = false
    end
    return ssl
  end

end
