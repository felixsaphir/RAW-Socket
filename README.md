# RAW-Socket
Example for raw socket on Windows 10 using mingw_w64 compiler.

*  Demo program that shows how to open RAW IP socket on WINDOWS 10 using MINGW_W64 compiler.
 *  Capture all IP frames, list the IP, TCP, UDP and ICMP headers and the rest of the message payload.
 *
 *  The program uses the semaphore and pthread libraries to allow one thread to be reasponsile for capturing the
 *  network traffic, while the other thread to print them on screen. This allows the program to hanlde high traffic
 *  load regradless of the slow output.
 *
 *  This small project is an attempt from my side to return to programming after more than 20 years. What can be a better
 *  language to return to than C ?
 *
 *  The program recieves two parameters IP_Add Duration
 *    IP_Add - local IP address of the NW inerface you want to connect to
 *    Duration - time on second to let the program run and capture traffic
 *
 *    (*) This program needs ADMIN privilages to run
