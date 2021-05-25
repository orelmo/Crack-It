Instructions:
1. run "make" command.

2. run the program using the following command "sudo ./main.out -l <passwordLen> -n <decryptersNumber> -t <timeout>"
	a. -n|--num-of-decrypters – will determine how many decrypter threads will be created.
	b. -l|--password-length – number of characters that will be encrypted, the more characters will be encrypted the harder it will be for the decrypters.
	c. -t|--timeout(optional) – time is seconds until server regenerates a password if it didn’t.

3. You can use the command "make clean" to clean the compilation outputs.
