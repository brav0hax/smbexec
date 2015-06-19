require 'menus'
require 'lib_smb'

class Guide < Menu
	include Lib_smb

	def initialize(options)
		# Load config file
		config_file = options[:config] || "smbexec.yml"
		config = YAML.load_file(config_file)
		time = Time.now

		Menu.opts = {}

		# If user has given a state file pull from that
		if options[:state]
			Menu.opts = options[:state]

			# To prevent errors if day changes
			Menu.opts[:log] = "#{APP_ROOT}\/log\/smbexec-#{time.year}-#{time.month}-#{time.day}"
		else

			# Set up default variables from config or optparse
			Menu.opts[:banner] = {
				:hosts => color_banner('No hosts identified'),
				:creds => color_banner('No credentials provided'),
				:password => color_banner('No pass provided'),
			}

			# check if main log folder exists, if not create it
			log_dir = options[:log] || config['log']

			Menu.opts[:log] = "#{APP_ROOT}\/log\/smbexec-#{time.year}-#{time.month}-#{time.day}"

			Menu.opts[:verbose] = options[:verbose] || config['verbose']
			Menu.opts[:domain] = options[:domain] || config['domain']
			Menu.opts[:threads] = options[:threads] || config['threads']
			Menu.opts[:timeout] = options[:timeout] || config['timeout']
			Menu.opts[:xterm] = config['xterm'] || false
			Menu.opts[:wcedump] = config['wcedump'] || false
			Menu.opts[:nmap] = config['nmap'] || false
			Menu.opts[:module_description] = config['module_description'] || false

			# Update banner for hosts, IP if only one specified
			if options[:hosts]
				Menu.opts[:hosts] = parse_addr(options[:hosts])
				if Menu.opts[:hosts].length > 1 and Menu.opts[:hosts]
					Menu.update_banner(color_banner("#{Menu.opts[:hosts].length} hosts identified"), :hosts)
				else			
					Menu.update_banner(color_banner("#{Menu.opts[:hosts][0]}"), :hosts)
				end
			end

			# Update banner for credentials
			if options[:creds] and options[:pass]
				Menu.opts[:creds] = [[options[:creds], options[:pass].escape!('\\"$')]]
				Menu.update_banner(color_banner("#{Menu.opts[:domain]}\\#{options[:creds]}"), :creds)
				if options[:pass].is_ntlm?
					Menu.update_banner(color_banner("Pass: NTLM Hash"), :password)
				else
					Menu.update_banner(color_banner("Pass: #{options[:pass]}"), :password)
				end
			# Update banner for credentials file
			elsif options[:cred_file]
				Menu.opts[:creds] = parse_creds(options[:cred_file])
				if Menu.opts[:creds].nil?
					Menu.opts[:creds] = [['', '']]
				else
		 			Menu.update_banner(color_banner("#{Menu.opts[:domain]}\\#{Menu.opts[:creds].length} accounts"), :creds)
		  			Menu.update_banner(color_banner("Pass: #{Menu.opts[:creds].length} supplied"), :password)
				end
			else
				Menu.opts[:creds] = [['', '']]
			end
			
			# check if main log folder exists, if not create it
			create_folder

			# Set to . for auto-resolve
			Menu.opts[:domain] = '.' if Menu.opts[:domain].eql? "LOCALHOST"
		end

		# Set up location to binary and scripts
		Menu.extbin = {}
		config['dependancies'].each do |x, y|
			Menu.extbin[x.to_sym] = y
		end

		print_status("Checking if all external dependancies exist...")
		puts
		warn = false

		# import all binary locations
		Menu.extbin.each do |key, bin|
			if bin and not bin.empty?
				if not file_exists?(bin)
					if key.to_s.eql? 'smbwinexe' or key.to_s.eql? 'smbexeclient'
						print_warning("#{bin} does not exists, run the compile binaries options within the installer. If you already have, update smbexec.yml with the correct path")
					elsif key.to_s.eql? 'smbwmic'
						print_warning("#{bin} does not exists, functionality may break. You may need to get it from a 'apt-get install passing-the-hash'.")						
					else
						print_warning("#{bin} does not exists, functionality may break. Update smbexec.yml with correct path.")
					end
					
					warn = true
				else
					# When winexe comes up check the version to see if hashes must be exported
					if key.to_s.eql? 'smbwinexe'
						winexe_version = `#{bin}`
						if winexe_version =~ /winexe version 1\.01/
							Menu.opts[:export_hash] = false
						elsif winexe_version =~ /winexe version 1\.00/
							Menu.opts[:export_hash] = true
						# Figure out what to do if unknown version detected later
						else
							Menu.opts[:export_hash] = false
						end
					end
				end
			else
				print_warning("#{key} is not defined in the config, functionality may break")
				warn = true
			end
		end

		if warn
			puts
			print "Press enter to continue"
			gets
		end

		Menu.opts[:version] = options[:version] || "Huh?, how'd you kill the version number"
		Menu.opts[:stealth] = options[:stealth] || nil
		config['stealth_mode'].each do |x, y|
			Menu.opts[x.to_sym] = y.to_i
		end

		# Launch menu right after instance created
		launch!
	end

	def launch!
		options = []
		options << "Main Menu"
		options << "1. System Enumeration"
		options << "2. System Exploitation"
		options << "3. Obtain Hashes"
		options << "4. Options"
		self.main_menu(options, 'Exit')
	end

	def menu(input)
		case input
			when "1"
				@enumeration ||= Enumeration.new
				@enumeration.launch!
			when "2"
				@exploitation ||= Exploitation.new
				@exploitation.launch!
			when "3"
				@hashes ||= Hashes.new
				@hashes.launch!
			when "4"
				@options ||= Options.new
				@options.launch!
			when "5"
				exit
				return
			else
		end
		self.launch!
	end

	def create_folder
		# create main log directory
		begin
			Dir.mkdir(File.join("#{APP_ROOT}\/log"), 0700) unless File.directory?("#{APP_ROOT}\/log")
			Dir.mkdir(File.join("#{APP_ROOT}\/powershell"), 0700) unless File.directory?("#{APP_ROOT}\/powershell")
			Dir.mkdir(File.join(Menu.opts[:log]), 0700) unless File.directory?(Menu.opts[:log])
			Dir.mkdir(File.join("#{Menu.opts[:log]}/debug"), 0700) unless File.directory?("#{Menu.opts[:log]}/debug")
			Dir.mkdir(File.join("#{Menu.opts[:log]}/state"), 0700) unless File.directory?("#{Menu.opts[:log]}/state")
		rescue => e
			print_bad("Issues creating logs folder #{e}")
			print_bad("No logs will be saved.")
			print_bad("Press enter to continue")
			gets
		end
	end

	def exit
		puts
		# check if main log folder is empty, if it is delete
		print_status("Cleaning up...")
		if Dir["#{Menu.opts[:log]}\/*"].empty?
			begin
				# remove empty directory
				FileUtils.rm_rf("#{Menu.opts[:log]}")
				print_good("Removed empty log directory")
			rescue IOError => e
				print_bad("Issues removing directory: #{e}")
			end
		end

		# Save off state
		save_state(true)
	end
end
