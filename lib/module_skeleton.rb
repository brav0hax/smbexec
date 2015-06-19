require 'poet'

class Skeleton < Poet::Scanner
	self.mod_name = "Insert Menu Name"
	self.description = ""

	def setup
		# Print title
		puts 
		title = "Write a title"
		puts color_header(title)

		# Create instance vars
		#@da = {}
	end

	def run(username, password, host)
		# Work!
		# @logger.info("we won/lost at #{host}")
	end

	def finish
		# Put ending titles
		#puts "\nBlah blah found: #{@success}\n\n"

		# Return to menu
		#print "Press enter to Return to Enumeration Menu"
		#gets

		# Save to Menu class
		#Menu.update_banner(color_banner("DA found: #{@success}"), :shares)
		#Menu.opts[:shares] = @shares
	end
end