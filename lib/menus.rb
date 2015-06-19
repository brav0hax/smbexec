require 'menu'

class Enumeration < Menu
	self.path = "modules/enumeration"
	self.title = "System Enumeration Menu"

	# Make sure the create a host list menu item is first
	def initialize
		super
		@modules.insert(0, @modules.delete_at(@modules.index(Hostlist)))
	end
end

class Hashes < Menu
	self.path = "modules/hashdump"
	self.title = "Hash Dump Menu"

	def initialize
		# If user selects hash class, ensure folder exists to drop data.
		unless folder_exists("#{@log}/hashes")
			unless create_folder("#{@log}/hashes")
				print_bad("Could not create folder #{log}/hashes! Will be unable to save hashdumps")
				print_bad("Press enter to continue")
				gets
			end
		end
		super
	end
end

class Exploitation < Menu
	self.path = "modules/exploitation"
	self.title = "System Exploitation Menu"
end

class Options < Menu
	self.title = "Options Menu"
	def initalize

	end
	
	def launch!
		options = []
		options << "Options Menu"
		options << "1. Save State"
		options << "2. Load State"
		options << "3. Set Thread Count"
		options << "4. Generate SSL Cert"
		sm = Menu.opts[:stealth] ? "5. Leave Stealth Mode" : "5. Enter Stealth Mode"
		options << sm
		options << "6. About"
		self.main_menu(options)
	end

	def menu(input)
		case input
			when "1"
				puts
				catch_sig {
					save_state
					puts
					print "Press enter to Return to the Menu"
					gets
				}
			when "2"
				catch_sig {load_state}
			when "3"
				catch_sig {
					# Get valid threadcount
					threads = 0
					until (1..65535).member? threads.to_i
						print "Enter number of threads to use [#{color_banner(Menu.opts[:threads])}]"
						threads = rgets(": ")
						threads = Menu.opts[:threads] if threads.empty?
					end
					Menu.opts[:threads] = threads
				
					puts
					print "Threads set to #{color_banner(Menu.opts[:threads])}, Press enter to Return to the Menu"
					gets
				}
			when "4"
					catch_sig {generate_ssl}
			when "5"
				Menu.opts[:stealth] = !Menu.opts[:stealth]
			when "6"
				catch_sig {about}
			when "7"
				exit
				return
			else
		end
		self.launch!
	end
end