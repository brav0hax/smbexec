require 'lib_smb'
require 'thread'
require 'timeout'
require 'logger'
require 'open3'

class Poet
	include Utils

	# Error classes for account issues
	class LogonError < StandardError; end
	class LockOutError < StandardError; end
	class DisplayError < StandardError; end
	class WinFileError < StandardError; end
	class ServiceStartError < StandardError; end
	class NoAccess < StandardError; end
	class NetError < StandardError; end

	# Create class variables
	class << self
		# mod_name and description are pulled to be used in menu items
		# The smbexec_plugin is a reference used to determine if the class
		# is used to check if a class is a plugin for smbexec (basically
		# any class that inherits from poet)
		attr_accessor :mod_name, :description, :smbexec_plugin, :invasive, :title
	end

	# Empty methods modules will override with their own, prevents issues if one is not needed in a module
	def setup; end
	def run; end
	def finish; end
	def cleanup; end

	# Class for modules that require hosts and SMB credentials
	class Scanner < Poet
		include Lib_smb

		def initialize(creds = true)
			t = Time.now
			@logger = Logger.new("#{Menu.opts[:log]}/debug/#{self.class}_#{t.strftime('%m-%d-%Y_%H-%M')}")
			@logger.datetime_format = "%Y-%m-%d %H:%M:%S"
			@logger.info("#{self.class} started")
			@logger.level = Logger::INFO unless Menu.opts[:debug_mode]

			@timeout = Menu.opts[:timeout]
			@log = Menu.opts[:log]

			# Instance variables to keep track of success/failed
			@failed = 0
			@success = 0

			# Variable to detect if an NTLM hash is being used
			@ntlm = ''

			puts "\n#{self.class.description}" if Menu.opts[:module_description]

			# Keep harrassing the user till good hosts provided
			while true
				@hosts = get_addr
				break unless @hosts.nil?
				print_bad("Choose a valid range, ip address or file")
			end

			store_opts(@hosts, :hosts)
			if @hosts.length > 1
				store_banner("#{@hosts.length} hosts identified", :hosts)
			else
				store_banner("#{@hosts[0]}", :hosts)
			end

			# ask user for smb info. If requires and empty, keep asking
			if creds
				while true
					smb_auth_info
					unless Menu.creds?
						print_bad("This module requires user credentials")
					else
						break
					end
				end
			else
				smb_auth_info
			end

			# Sleep to prevent end user from hitting enter a bunch of times to skip
			# and accidently missing something a module may ask for outside auth.
			sleep 0.3

			# Get timeout
			@timeout = Menu.opts[:timeout]

			# Call setup method to initialize vars and display title
			setup

			# Print title of module
			puts
			title ||= ""
		      	puts color_header(self.class.title)

			# Set up queue and thread array
			mutex = Mutex.new
			cred_queues = Array.new
			queue = ''
			is_ntlm = []

			host_list = Menu.opts[:hosts]
			host_list.shuffle! if Menu.opts[:stealth]

			# For each cred set, create queue for each host with run jobs
			if Menu.creds?
				Menu.opts[:creds].each do |creds|
					queue = Queue.new
					host_list.each do |host|
						queue << [*creds, host]
					end
					cred_queues << queue
					is_ntlm << creds[1]

					# Export the hash if the credentials are ntlm and old winexe is in use
					system("export SMBHASH=#{creds[1]}") if creds[1].is_ntlm? and Menu.opts[:export_hash]
				end
			# Handle no creds for anonoymous access
			else
				queue = Queue.new
				host_list.each do |host|
					queue <<  [nil, nil, host]
				end
				cred_queues << queue
			end

			# Boolean to manage logon failures
			die = false
			pause = false
			first_pause_done = false

			# Start timer
			start_time = Time.now

			################################### Threadpool ###################################

			# This section starts a loop for each credential set
			cred_queues.each_with_index do |queue, index|
				break if die # If user aborts scan midway
				continue = false
				threads = Array.new
				threadzero = ''
				# Check if credentials in this loop iteration are NTLM (used for old winexe, requires export)
				@ntlm = is_ntlm[index] || ''

				@bin_creds = "#{Menu.opts[:domain]}/#{Menu.opts[:creds][index][0]}%#{Menu.opts[:creds][index][1]}"

				# Start threads based on supplied threadcount
				# If stealth mode, only one thread allowed
				thread_times = Menu.opts[:stealth] ? 1 : Menu.opts[:threads].to_i

				# This will catch one SIGINT and allow running threads to finish if you want to gracefully exit
				trap('SIGINT') do
					unless die
						# Clear queue and gets boolean so threads have no jobs to pop and no more queues are loaded
						queue.clear
						die = true

						stars = '*' * 70
						puts "\e[1;34m#{stars}\e[0m"
						puts "\e[1;34mSignal Interupt Detected, stopping threads\e[0m".center(70)
						puts "\e[1;34m#{stars}\e[0m"
					else
						# If user sends another SIGINT, act normally and kill
						raise Interrupt
					end
				end

				thread_times.times do |i|
					# Let first job finish before starting all other jobs, this prevents immediate lockout
					# of accounts if bad password supplied and high threads
					sleep 0.1 until first_pause_done if i > 0

					# Put all threads into array
					threads << Thread.new do |thread|

						# Wait until the queue is empty and all threads are complete to start next queue
						until queue.empty?

							# Reset variable in case of pause, if not will redo a host
							work_unit = nil
							# Keep going until the queue is empty
							work_unit = queue.pop(true) unless pause rescue nil

							if work_unit
								# def print_good(text); puts "\e[1;32m[+]\e[0m #{work_unit[2].ljust(15)} - #{work_unit[0]}: #{text}"; end
								# Log run times
								@logger.debug("#{work_unit[2]} as #{work_unit[0]}")
								# Catch exceptions within thread due to connection, account, or timeout issues
								# Exec run within a timeout, 0 disables timeout
								begin
									if @timeout > 0
										Timeout.timeout(@timeout) {run(*work_unit)}
									else
										run(*work_unit)
									end

								# Print timeout warning
								rescue Timeout::Error
									@logger.warn("#{(work_unit[2]).ljust(15)} - Timed out")
									print_warning("#{(work_unit[2]).ljust(15)} - Timed out")

									# If the class installs winexe, cleanup on error
									winexe_cleanup(work_unit[2]) if self.class.invasive

								# If logon failure then kill current module
								rescue LogonError
									if work_unit[1]
										if work_unit[1].is_ntlm?
											print_bad("#{(work_unit[2]).ljust(15)} - Logon Failure User:#{work_unit[0]} Pass:NTLM Hash")
										else
											print_bad("#{(work_unit[2]).ljust(15)} - Logon Failure User:#{work_unit[0]} Pass:#{work_unit[1]}")
										end
									end
									@logger.error("#{(work_unit[2]).ljust(15)} - Logon Failure User:#{work_unit[0]} Pass:#{work_unit[1]}")

									# Ignore local accounts
									unless Menu.opts[:domain].eql? '.'
										# Lock threads with mutex and ask user what they would like to do when login failure occurs
										mutex.synchronize do

											# Temp if to appease eric for now, add config later
											unless first_pause_done
												unless continue
													pause = true

													# Sleep a little to let other threads finish up a little to make it easier to read
											#		sleep 5

													selection = ''
													until selection =~ /^(s|a|c)$/
														print "    [s]kip account #{highlight(work_unit[0])}, [a]bort scan, or [c]ontinue and ignore failures?"
														selection = rgets(' : ').downcase
													end

													case selection
													when "s"
														# Clear out current queue containing account with login issues
														queue.clear
													when "a"
														# Clear out current queue and set die to true to break loop for queues array
														queue.clear
														die = true
													when "c"
														# continue on and
														continue = true
													end
													pause = false
												end
											end
										end
									end

								# If access denied
								rescue NoAccess => e
									@logger.warn("#{(work_unit[2]).ljust(15)} - Account #{work_unit[0]} #{e}")
									vprint_warning("#{(work_unit[2]).ljust(15)} - Account #{highlight(work_unit[0])} #{e}")

								# If the account is locked out, warn and skip iteration
								rescue LockOutError
									@logger.warn("Account #{work_unit[0]} locked out, skipping account")
									print_warning("Account #{highlight(work_unit[0])} locked out, skipping account")
									queue.clear

								# If the winexe service fails to start
								rescue ServiceStartError, NetError => e
									@logger.warn("#{(work_unit[2]).ljust(15)} - #{e}")
									print_warning("#{(work_unit[2]).ljust(15)} - #{e}")

								# Catch all remaining StandardError
								rescue => e
									@logger.error("\e[1;31mERROR: \e[0m#{e}\n\n Backtrace:\n #{e.backtrace.join('\n')}")
									print_bad("#{(work_unit[2]).ljust(15)} - Unhandled error: #{e}") if work_unit[2]
									# If the class installs winexe, cleanup on error
									winexe_cleanup(work_unit[2]) if self.class.invasive
								end
							end

						# After first thread/job is done switch this off so other threads can start
						first_pause_done = true unless first_pause_done

						# If stealth mode, sleep within parameters given
						sleep (Menu.opts[:minimum_time_between] + rand(Menu.opts[:maximum_time_between] - Menu.opts[:minimum_time_between])) if Menu.opts[:stealth]

						end
					end # end putting threads into array
				end # end iterate creating threads

			threads.each { |t| t.join} # Make main thread wait for module threads
			end # end each queue

			################################# End Threadpool #################################

			# Prevent SIGINT from displaying junk if threadpool is already completed
			die = true

			# Set end time
			end_time = Time.now
			elapsed_time = end_time - start_time

			puts
			print_status("Module start time : #{start_time.ctime}")
			print_status("Module end time   : #{end_time.ctime}")
			print_status("Elapsed time      : #{elapsed_time.ceil} seconds")

			# Flush stdin to prevent previously entered input from skipping the final displays of a module
			STDIN.flush

			# Call finish method to clean up and report
			finish
			@logger.info("#{self.class} finished")
			@logger.close
		end
	end # End Scanner class

	def execute_command(bin, options, command)
		result = ''

		stderr_bins = capture_stderr_poet(Thread.current.object_id) do

			# Send full command to correct binary with logging
			options = %Q{-U "#{@bin_creds}" #{options}}
			if command
				result = log("#{bin} #{options} '#{command}'") {`#{bin} #{options} '#{command}'`}
			else
				result = log("#{bin} #{options} '#{command}'") {`#{bin} #{options}`}
			end
		end

		# Empty string any Nils
		stderr_bins ||= ""
		result ||= ""

		# Strip bad unicode characers caused by some language packs
		error_check = result.encode!('UTF-8', 'UTF-8', :invalid => :replace) + stderr_bins.encode!('UTF-8', 'UTF-8', :invalid => :replace)
    		error_check

		# Error checking based on SMB responses
	    	if error_check =~ /NT_STATUS_LOGON_FAILURE/
			raise LogonError
		elsif error_check =~ /NT_STATUS_ACCOUNT_LOCKED_OUT/
			raise LockOutError, "locked out"
		elsif error_check =~ /status=0x00000001/ or error_check =~ /Error: error Creating process() 87/
			raise ServiceStartError, "Winexe service failed to start"
		elsif error_check =~ /NT_STATUS_ACCESS_DENIED/ or error_check =~ /NT_STATUS_NET_WRITE_FAULT/
			raise NoAccess, "does not have required permissions"
		elsif error_check =~ /NT_STATUS_OBJECT_PATH_NOT_FOUND/ or error_check =~ /NT_STATUS_OBJECT_NAME_NOT_FOUND/
			raise NetError, "path not found"
		elsif error_check =~ /NT_STATUS_CONNECTION_REFUSED/
			raise NetError, "SMB ports appear closed"
		elsif error_check =~ /BAD_NETWORK_NAME/
			raise NetError, "Issues with path"
		end

 		# Hack to get rid of the hashes added to stdout by 1.01 if a hash is used for auth.
		result = result.split("\n").map! {|line|
			if line.strip.eql? @ntlm
				line = ''
			else
				"#{line}\n"
			end
		}.join() if @ntlm.is_ntlm?

		return result
	end

	def winexe(options, command = nil)
		return execute_command(Menu.extbin[:smbwinexe], options, command)
	end

	def smbclient(options, command = nil)
		return execute_command(Menu.extbin[:smbexeclient], options, command)
	end

	def smbwmic(options, command = nil)
		return execute_command(Menu.extbin[:smbwmic], options, command)
	end

	def log(tag = "", &block)
		begin
			@logger.debug("\e[1;37m[Starting]\e[0m #{tag}")
			value = block.call
			# If return is nil, make empty for string below
			value ||= ""
			@logger.info("\e[1;34m[Completed]\e[0m #{tag}\n\e[1;35m[Result]\e[0m: #{value}")
			return value
		rescue => e
			@logger.error("Error with #{tag} - #{e}") if @logger
			print_warning("Unhandled logging error: #{e}")
		end
	end

	def store_banner(value, tag)
		Menu.opts[:banner][tag] = color_banner(value)
	end

	def store_opts(value, tag)
		Menu.opts[tag] = value
	end

	# If invasive module fails due to time out or random error, make sure to uninstall service
	def winexe_cleanup(host)
		begin
			Timeout.timeout(15) { winexe("--uninstall //#{host}", '') }
		rescue Timeout::Error
			print_warning("#{(host).ljust(15)} - Cleanup uninstall timed out")
		rescue => e
			print_warning("#{(host).ljust(15)} - Uninstall had unexpected issue: #{e}")
		end
	end
end
