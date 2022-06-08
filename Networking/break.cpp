/*
 * Test client for the simple auth protocol.
 *
 * Run from the command line with arguments 
 *   server port userid perm password
 */
#include <cstdlib>
#include <ctime>

#include <iostream>
#include <string>
#include <random>
#include <chrono>

using namespace std;

#include <cleansocks.h>
#include <cleanip.h>
#include <cleanbuf.h>
using namespace cleansocks;

#include "sha256.h"

static const int BSIZE = 1024;

// The interaction should be logged.
static bool verbose = false;

// Name of the program.
string pgmname;

/*
 * Print a message and exit.
 */
void die(string message)
{
	cerr << message << endl;
	exit(1);
}

/*
 * Receive a one-line response.  Die if it's an E.  Otherwise, return the
 * the response.
 */
string getresp(buffered_socket &soc)
{ 
    
	// Get the response, die if none.
	char buf[BSIZE];
	
	//ISSUE WAITING TO RECIEVE
	int size = recvln(soc, buf, BSIZE);
	if(size == 0) die("Server closed on us.");

	// Make it into a string (without \r\n), and die on E response.
	// In verbose mode, print it, too.
	string ret(buf, size-2);
	cout << "ret is: "<<ret<< endl;
	if(verbose) cout << "  SER: " << ret << endl;
	if(ret[0] == 'E') die("Server reports error: " + ret);

	// Your problem now.
	return ret;
}

int main(int argc, char **argv)
{
	// Save the name of the program, and remove it from the parameters.
	pgmname = *argv++;
	argc--;

	// Check the verbose flag.
	if(argc > 0 && string(argv[0]) == "-v") {
		verbose = true;
		argv++; argc--;
	}

	// Need five parms.
	if(argc != 5)
		die("Usage: " + pgmname +
		    " [ -v ] <server> <port> <userid> <perm> <pass>");

	// Get the IP address, and convert the port number. 
	IPaddress comp = lookup_host(argv[0]);
	IPport port = atoi(argv[1]);

	// Create a socket and connect it to the server. 
	TCPsocket c;
	connect(c, IPendpoint(comp, port));

	// This is a job for... buffered_socket!  
	buffered_socket conn(c);

	// Request a nonce, and trim the request.  (This is hacky code
	// and it could blow up pretty badly if the server response is
	// not correctly formed.)
	if(verbose) cout << "  CLI: N" << endl;
	send(conn, string("R\r\n"));
	string server_nonce = getresp(conn);
	cout<< "server_nonce: "<<server_nonce << endl;
	server_nonce.erase(0,server_nonce.find_first_not_of(" ", 1));
	cout<< "server_nonce client corrected : "<<server_nonce << endl;

	// Choose a small, slightly random response nonce.  Using a plain 
	// C string for the response so I can use plain C sprintf().
	// This is easy to code, but not a particularly good nonce.
	std::default_random_engine generator
		(std::chrono::system_clock::now().time_since_epoch().count());
	std::uniform_int_distribution<int> distribution(0,0xffffffff);
	char client_nonce[11];
	sprintf(client_nonce, "%08x", distribution(generator));

	// Build the hash for the check message.
	sha256 hasher;
	string hash =
		hasher.process(server_nonce + client_nonce + argv[4]).getx();

	// Now send the check request message.
	string msg = string("C ") + argv[2] + " " + argv[3] + " " + 
		client_nonce + " " + hash;
	cout<<msg<<endl;
	if(verbose) cout << "  CLI: " << msg << endl;
	send(conn, msg + "\r\n");
	string approval = getresp(conn);
	cout<<"approval: "<<approval<<endl;
	if(approval[0] == '-')
		cout << "Not authenticated" << endl;
	else
		cout << "Authenticated" << endl;

	close(conn);
}
