require 'poet'

class Loggedin < Poet::Scanner
	self.mod_name = "Check systems for logged in users"
	self.description = "Identify logged in users."
  self.title = 'Logged in users'
	
	def run(username, password, host)
		users = loggedin(username, password, host)
		if users
			@success += users.length
			users = users.join(", ")
			unless users.empty?
				print_good("#{host.ljust(15)}#{users}")
			else
				print_warning("#{host.ljust(15)}No users logged in")
			end
		end
	end

	def finish
		puts "\nLogged in users found: #{@success}\n\n"
		print "Press enter to Return to Enumeration Menu"
		gets

		store_banner("Logged in users found: #{@success}", :da)
		store_opts(@da, :da)
	end
end
