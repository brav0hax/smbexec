#!/usr/bin/env ruby

raise 'Must run as root' unless Process.uid == 0 or Process.euid == 0

require 'optparse'
require 'yaml'
options = {}
optparse = OptionParser.new do |opts|

	options[:version] = "2.0 - Machiavellian"

	bar = "*"*70 
	bar = "\e[1;34m#{bar}\e[0m"
	opts.banner = "\n#{bar}\n"
	title = "smbexec #{options[:version]}"
	opts.banner << "\e[1;34m*\e[0m\e[1;36;40m#{title.center(68)}\e[0m\e[1;34m*\e[0m" + "\n"
	opts.banner << "#{bar}\n\n"
	opts.banner << "Usage: ruby smbexec.rb [options]"
	opts.banner << ""
	opts.on('-c' , '--config <CONFIG FILE>', 'YML Configuration file to use' ) do |policy|
		options[:policy] = File.absolute_path(policy)
	end

	opts.on('-u' , '--user <USER>', 'Specify the password' ) do |creds|
		options[:creds] = creds
	end

	opts.on('-p' , '--password <PASSWORD>', 'Specify the user account' ) do |pass|
		options[:pass] = pass
	end

	opts.on('-d' , '--domain <DOMAIN>', 'Specify the AD Domain' ) do |domain|
		options[:domain] = domain
	end

	opts.on('-U' , '--user-file <USER_FILE>', 'Credential file, ":" delimited' ) do |cred_file|
		options[:cred_file] = File.absolute_path(cred_file)
	end

	opts.on('-h' , '--hosts <HOST_RANGE>', 'IP range of hosts' ) do |hosts|
		options[:hosts] = hosts
	end

	opts.on('-H' , '--hosts-file <HOST_FILE>', 'File containing hosts or nmap XML output' ) do |hosts|
		options[:hosts] = File.absolute_path(hosts)
	end

	opts.on('-l' , '--log <LOG_DIR>', 'Directory to log to' ) do |log|
		options[:log] = File.absolute_path(log)
	end

	opts.on('-t' , '--threads <NUM_THREADS>','Number of threads to use' ) do |threads|
		threads = 1 if threads.eql? '0' 
		options[:threads] = threads.to_i
	end
	
	opts.on('--timeout <SECONDS>','Timeout for each job to use' ) do |timeout|
		options[:timeout] = timeout.to_i
	end

	opts.on('-S', '--state <STATE_FILE>','Load a state file' ) do |state|
		begin
			options[:state] = YAML::load(File.read(state))
		rescue IOError => e
			puts "Issues loading saved state: #{e}"
		end
	end

	opts.on('--stealth','Adds random delays and randomizes hosts scanned' ) do
		options[:stealth] = true
	end
	
	opts.on_tail( '--help', 'Display this screen' ) do
		puts opts
		puts
		exit
	end

	opts.parse!
end

smbexec = __FILE__
while File.symlink?(smbexec)
	smbexec = File.readlink(smbexec)
end
APP_ROOT = File.dirname(smbexec)


$:.unshift( File.join(APP_ROOT, 'lib') )

# If user and pass, not either or, start guide class
if (!!(options[:creds].nil?) ^ !!(options[:pass].nil?))
	puts
	puts "User and password required, please specify both or no credentials"
	puts
else
	require 'guide'
	Dir.chdir(APP_ROOT) do
		Guide.new(options)
	end
end
