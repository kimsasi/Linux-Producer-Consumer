======================== Linux Embedded Development Ex2 ======================== 
 Delivery Date : 12/01/2021

Submitted By:
	# Kim Sasi 206333163
	# Yotam Ishak 302344098

example command to run: 
	sudo ./Linux_ex2_mta_crypto -n 3 -l 24 -t 1

Comments:
	The program needs two arguments with these two flags to begin running:
	"--password-length" or "-l" - Represents key length (must be a factor of 8)
	"--num-of-decrypters" or "-n" - Represents number of decrypters

	And optionally you can add the following flag:
	"--timeout" or "-t" - Represents number of seconds decryptor has to solve the password before timeout

************  IMPORTANT!  *************

	Don't forget to use your Super-user permissions (aka "sudo") to run the executable.  (-;
