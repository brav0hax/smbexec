require 'poet'

class RemoteLogin < Poet::Scanner
	self.mod_name = "Remote login validation"
	self.description = "Identify where credentials have local administrative access."
  self.title = 'Remote Login Validation'

	def setup
		puts
		# Check if they want to enum DA
		@da_check = ''
		until @da_check.eql? 'y' or @da_check.eql? 'n'
			print "Do you want to look for Domain/Enterprise processes? [#{color_banner('y')}|#{color_banner('n')}]"
			@da_check = rgets.downcase
		end

		# Set up inital vars
		@access = {}
	end

	def run(username, password, host)
		# If the output contains the C$ share, print and save
		if check4remotelogin(username, password, host)
			print_good("#{host.ljust(15)} - Remote access identified as #{highlight(username)}")
			@access[:"#{host}"] = true
			@success += 1

			check4da(username, password, host) if @da_check.eql? 'y'
		else
			# Else log a failure
			@access[:"#{host}"] = false
		end
	end

	def finish
		puts
		puts "Remote login access identified to #{@success.to_s} devices"
		print "Press enter to Return to Enumeration Menu"
		puts
		gets

		# Update opts
		store_banner("Remote logins: #{@success.to_s}", :remote)
		store_opts(@access, :remote)
	end
end
