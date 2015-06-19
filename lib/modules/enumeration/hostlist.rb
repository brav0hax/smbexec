require 'utils'

class Hostlist < Poet
	include Utils
	self.mod_name = "Create a host list"
	self.description = "Create a host list."

	def initialize
		local_addr = local_ip
		local_addr.sub!(/\.\d+$/,'.0/24') unless local_addr.empty?
		print "\nEnter target network range [#{color_banner(local_addr)}] :"
		range = rgets
		range = local_addr if range.empty?
		hostlist = Array.new

		# If they are using nmap
		if Menu.opts[:nmap]
			# Lazy load only if needed
			require 'nmap/program'
			require 'nmap/xml'
			print "\nScanning with nmap, this will take a little time"
			
			scanthread = Thread.new do
				capture_stdout('/dev/null') {
					Nmap::Program.scan(
						:tcp_scan => true,
						:xml => "#{Menu.opts[:log]}\/host_scan.xml",
						:ports => [139,445],
						:targets => range,
						:enable_dns => false
					)
				}
			end

			$stderr.print '.' until scanthread.join(1.5)

			# Grab all hosts with open ports
			Nmap::XML.new("#{Menu.opts[:log]}\/host_scan.xml") do |file|
				file.each_host do |host|
					unless host.open_ports.empty?
						hostlist << host.ip
					end
				end
			end
		else
			mutex = Mutex.new
			range = parse_addr(range)
			threads = []

			Menu.opts[:threads].to_i.times do
				threads << Thread.new do
					until range.empty?
						ip = range.shift
						hostlist << ip if win_portscan(ip)
					end
				end
			end		
			print "\nScanning, this will take a little time"
			$stderr.print '.' until threads[0].join(1.5)
			threads.each { |t| t.join }
		end

		puts
		# This creates columns so up to four addresses will be shown per line.
		hostlist.each_slice(4) { |slice| 
			line = ''
			slice.each { |ip|
				line << ip.ljust(15)
			}

			print_good(line)
		}
		puts "\nHosts found: #{hostlist.length}\n\n"
		print "Press enter to Return to Main Menu"
		gets
		Menu.opts[:hosts] = hostlist
		Menu.update_banner(color_banner("#{hostlist.length} hosts identified"), :hosts)
	end
end