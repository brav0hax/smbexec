require 'poet'

class EnumerateShares < Poet::Scanner
	self.mod_name = "Enumerate Shares"
	self.description = "This module will enumerate shares on the " \
	"target host. If no credentials are provided it will check " \
	"annonymous access."
  	self.title = " "*4 + "Host".ljust(20) + "Share".ljust(16) + "Type".ljust(10) + "Description" + ' '*8

	# Allows for anonymous scans
	def initialize
		super(false)
	end

	def setup
		# anonymous if no user or pass supplied
		if not Menu.creds?
			puts "Enumerating Shares as anonymous"
			@anonymous = true
		else
			puts "Enumerating Shares as #{Menu.get_banner(:creds)}"
		end

		@shares = {}
	end

	def run(username, password, host)
		# create syntax
		if @anonymous == true
			cmd = "-N -L "
		else
			cmd = " -L "
		end

		# enumerate shares without credentials
		smbclient_output = smbclient("#{cmd}#{host}")

		# If the output contains shares and no error
		if smbclient_output =~ /Sharename/m and not smbclient_output =~ /Error returning browse list:/m
			share = []
			print = false
			smbclient_output = smbclient_output.split("\n")
			line = 0

			# While there are shares left, get the info
			while line < smbclient_output.length do
				if smbclient_output[line] =~ /Sharename/
					print = true
					line = line + 2
					next
				end
				line = line + 1
				# Check to see if it should still collect lines
				next unless print
				# Break if line starts with a tab
				break if not smbclient_output[line] =~ /^\t/
				print_good("#{host.ljust(15)}#{smbclient_output[line]}")
				
				share << smbclient_output[line].gsub(/\t/, '')
				@success = @success + 1
			end
			@shares[host.to_sym] = share
		else
			@failed = @failed + 1
			@logger.error("#{host}: Could not enumerate shares")
		end
	end

	def finish
		@logger.info("Shares found: #{@success}")
		puts "\nShares found: #{@success}\n\n"

		file_output = ''
		@shares.each do |key, value| 
			value.each do |i|
				file_output << "#{key.to_s.ljust(15)}: #{i}\n" 
			end
		end
		
		write_file(file_output, "results_#{self.class}_#{Time.now.strftime('%m-%d-%Y_%H-%M')}")

		store_banner("Shares found: #{@success}", :shares)
		store_opts(@shares, :shares)

		print "Press enter to Return to Enumeration Menu"
		gets
	end
end
