require 'yaml'
require 'utils'
require 'poet'

class Menu
	include Utils

	# Create class variables
	class << self
		attr_accessor :extbin, :opts, :path, :title
	end

	# Create instance variables
	attr_accessor :modules, :title

	def main_menu(options, back = 'Main menu')
		system('clear')
		options << "#{options.length}. #{back}"
		bar = "*" * 70

		if Menu.opts[:stealth]
			title_bar = "smbexec #{Menu.opts[:version]} - Stealth Mode"
			puts "\e[1;31m#{bar}\e[0m"
			puts "\e[1;31m*\e[0m#{color_title(title_bar.center(68))}\e[1;31m*\e[0m"
			puts "\e[1;31m#{bar}\e[0m"
		else
			title_bar = "smbexec #{Menu.opts[:version]}"
			puts "\e[1;34m#{bar}\e[0m"
			puts "\e[1;34m*\e[0m#{color_title(title_bar.center(68))}\e[1;34m*\e[0m"
			puts "\e[1;34m#{bar}\e[0m"
		end

		banner = ['']
		Menu.opts[:banner].each_value {|i| banner << i}

		# Determine if menu options or notes is longer
		iterations = options.length > banner.length ? options.length : banner.length

		puts
		puts color_header(options[0].center(70))
		puts

		# Print the menu while maintaining format regardless of whether either
		# column is longer than the other
		i = 1
		while i < iterations
			first, second = options[i], banner[i]
			line = ''
			# Blank string for nil to maintain formatting
			first ||= ''
			line << first.ljust(42) 
			line << second.rjust(40) if second
			puts line
			i = i + 1
		end

		puts
		print "Choice"
		
		# Catch interupt and call cleanup method
		begin
			menu(rgets(" : ").strip)
		rescue SignalException
			exit
		end
	end

	# Class method to get banner
	def self.get_banner(key = nil)
		if not key
			return Menu.opts[:banner]
		else 
			return Menu.opts[:banner][key]
		end
	end
	
	# Class method to update banner
	def self.update_banner(opts, key = nil)
		if not key
			Menu.opts[:banner] = opts
		else 
			Menu.opts[:banner][key] = opts
		end
	end

	# Class method to determine if credentials have been provided
	def self.creds?
		if Menu.opts[:creds].length == 1
			if Menu.opts[:creds][0][0].empty?
				return false
			end
		end
		return true
	end

	# Saves all items within the Menu @@opts variable to YAML
	def save_state(quiet = false)
		time = Time.now
		path = "#{Menu.opts[:log]}/state/"
		save_name = "smbexec_state_#{time.hour}-#{time.min}.yml"

		# Quiet save state for when quit or other needed cases
		unless quiet
			print("Enter filename for save state [#{color_banner(save_name)}]:")
			new_name = rgets

			# Check if empty, if not check if ends in '.yml'
			save_name = new_name unless new_name.empty?
			save_name = "#{save_name}.yml" unless save_name[-4,4].eql? ".yml"
		end

		print_status("Saving state to #{path}#{save_name}...")
		begin
			File.open("#{path}#{save_name}", 'w') { |file| file.write(Menu.opts.to_yaml) }
		rescue IOError => e
			print_bad("Issues saving state: #{e}")
		end
	end

	# Takes a YAML file of the Menu @@opts vairable and overwrites one in use.
	def load_state
		# Create list of state files and put into array
		state_files = []
		Dir.foreach("#{Menu.opts[:log]}/state") {|file| 
			if file[-4,4].eql? ".yml"
				state_files << file
			end
		}
		puts

		# Print out state files
		i = 0
		while i < state_files.length do
			puts "#{i+1}. #{state_files[i]}"
			i +=1
		end
		puts "#{i+1}. Exit"
		puts
		to_load = ''
		
		# Make sure the user gives a valid selection
		until (1..state_files.length+1).member?(to_load.to_i)
			print "Which state do you wish to load?"
			to_load = rgets
		end

		# Return to previous menu
		return if to_load.to_i.eql? i+1

		# Read the file and eval contents into the opts variable
		contents = File.read("#{Menu.opts[:log]}/state/#{state_files[to_load.to_i - 1]}")
		hashcheck =  YAML::load(contents)
		# sanity check
		if hashcheck.is_a? Hash
			Menu.opts = hashcheck
		else
			puts "Could not parse contents, press enter to return"
			gets
		end
	end

	# Print contents of the about.txt file
	def about
		puts
		begin
			puts File.read('about.txt')
		rescue IOError => e
			print_bad("Could not open about.txt, the about page can be found at ") #<insert github link>
		end
		puts
		print "Press enter to Return to the Menu"
		gets
	end

  def generate_ssl
    puts color_header("Create Certificates\n")

    country = rgets("Enter country #{color_banner('US')} : ", "US")
    state = rgets("Enter state #{color_banner('Denial')} : ", "Denial")
    city = rgets("Enter city #{color_banner('Goawaysville')} : ", "Goawaysville")
    org = rgets("Enter orginization #{color_banner('Legitimate Web Traffic Inc')} : ", "Legitimate Web Traffic Inc")
    cn = rgets("Enter website #{color_banner('Goawaysville.com')} : ", "Goawaysville.com")

    cert_cmd = "openssl req -x509 -nodes -days 365 -newkey rsa:2048  -subj "
    cert_cmd << "/C='#{country}'/ST='#{state}'/L='#{city}'/O='#{org}'/CN='#{cn}' "
    cert_cmd << "-keyout #{APP_ROOT}/certs/server.key -out #{APP_ROOT}/certs/server.crt"
    cert_create_result = system(cert_cmd)

    if cert_create_result
      print_good("New certificates created, press enter to return to options menu")
    else
      print_bad("Error creating certifications, press enter to return to options menu")
    end

    gets

  end

	# Blank def incase no override
	def exit; end

	# On initalize of menu, get path to where modules are, load and sort them
	def initialize
		# Get all ruby files from specified directory
		files = Dir.glob("#{File.dirname(__FILE__)}/#{self.class.path}/*.rb")
		# Return all objects as an array
		@modules = load_modules(files).to_a
		# Sort modules by the mod_name
		@modules.sort_by! {|mod| mod.mod_name.downcase}
	end

	# Require all modules given and return list of smbexec plugins
	def load_modules(class_files)
		# Find all the classes in ObjectSpace before the requires
		before = ObjectSpace.each_object(Class).to_a
		# Require all files
		class_files.each {|file| require file }
		# Find all the classes now
		after = ObjectSpace.each_object(Class).to_a
		
		# Iterate through all classes loaded and see if the class
		# respondes 
		modules = []
		(after - before).each do |mod|
			if mod.respond_to?(:smbexec_plugin)
				modules << mod
			end
		end

		# Return array of plugins
		return modules
	end

	# Create array of menu items
	def launch!
		options = []
		# First line should be the menu title
		options << self.class.title
		i = 1
		@modules.each {|mod| options << "#{i}. #{mod.mod_name}"; i+=1}
		# Menu item for back added within main_menu to allow for easier name changing
		main_menu(options)
	end

	# Create the options for the menu
	def menu(input)
		# Catch sig exceptions and bad input
		begin
			input = input.to_i
			# If last item, exit
			if input.eql? @modules.length + 1
				return
			elsif input.between?(1,@modules.length)
				@modules[input-1].new
			else
			end
		rescue SignalException, TypeError
			# Catch but don't do anything so it reloads the menu
		end
		self.launch!
	end
end