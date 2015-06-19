require 'poet'

class CheckUAC < Poet::Scanner
	self.mod_name = "Check systems for UAC"
	self.description = "Check target(s) if UAC is enabled."
  self.title = 'UAC Configuration Results'

	def setup
		@uac = {}
	end

	def run(username, password, host)
		# call check4uac function to determine uac status
		if check4uac(username, password, host)	
			@success = @success + 1
		else
			@failed = @failed + 1
		end
	end

	def finish
		puts "\nUAC found: #{@success}\n\n"
		print "Press enter to Return to Enumeration Menu"
		gets

		store_banner("UAC found: #{@success}", :uac)
		store_opts(@uac, :uac)
	end
end
