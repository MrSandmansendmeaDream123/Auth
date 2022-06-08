/* This is Comer's CNAI webserver.c example ported to use cleansocks. */

/*-----------------------------------------------------------------------
 *
 * Program: webserver
 * Purpose: serve hard-coded webpages to web clients
 * Usage:   webserver <appnum>
 *
 *-----------------------------------------------------------------------
 */

#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <chrono>

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cleansocks.h>
#include <cleanip.h>
#include <cleanbuf.h>

using namespace std;
using namespace cleansocks;
#include "sha256.h"



static const int BUFFSIZE = 256;
const char *SERVER_NAME = "CNAI Demo Web Server [Cleansocks port]";

/* Some long strings which form the "files" of the web server. */
static const char *ERROR_400 =
"<html><head></head><body><h1>Error 400</h1>"
	"<p>The server couldn't understand your request.</body></html>\n";

static const char *ERROR_404 =
"<html><head></head><body><h1>Error 404</h1>"
	"<p>Document not found.</body></html>\n";

static const char *HOME_PAGE =
"<html><head></head><body><h1>Welcome to the CNAI Demo Server</h1>"
	"<p>Why not visit: <ul>"
	    "<li><a href=\"http://netbook.cs.purdue.edu\">Netbook Home "
		"Page</a>"
	    "<li><a href=\"http://www.comerbooks.com\">"
		"Comer Books Home Page<a>"
            "<li><a href=\"http://sandbox.mc.edu/~bennet/cs423/"
		"cleansocks.html\">The Cleansocks Page</a>"
        "</ul>"
"</body></html>\n";

void handle_client(buffered_socket &conn);
void send_head(buffered_socket &conn, int stat, int len);
unordered_map<string,pair<string,string>> users_map;
unordered_map<string,pair<string,string>>::iterator it;

int main(int argc, char *argv[])
{
	//making a map to hold users as the key and the users
	//Password and permissions as the values, had to make them a pair


	if (argc != 3) {
		cerr << "usage: " << argv[0] << " <portnum> <datafile>" << endl;
		exit(1);
	}

	//Attempt to process file
	ifstream datafile;
	datafile.open(argv[2]);
	if(datafile.is_open()){
		
		/*Get each line of the file and process the data so it 
		  can be stored in the map*/
		while(datafile){ 

			string userdata;	
			getline(datafile,userdata);

			//Prevents the empty string from causing issues
			if(userdata.compare("") != 0){ 
				string user = userdata.substr(0,userdata.find(":"));
				userdata = userdata.substr(userdata.find(":")+1,userdata.length());
				string password = userdata.substr(0,userdata.find(":"));
				string perm = userdata.substr(userdata.find(":")+1,userdata.length());
				/*
				//=================Testing===================
				cout<<user<<endl;
				cout<<password<<endl;
				cout<<perm<<endl;
				cout<<"========================="<<endl;
				//===========================================
				*/

				//Add to the map
				auto userstuff = make_pair(password,perm);
				users_map.insert(make_pair(user,userstuff));

		}

	}

	}else{
		cerr<<"Failed to open file: "<<argv[2]<< endl; 
		exit(1);
	}
	/*
	//====================================================Testing==========================================================
	for(auto& x:users_map){
		 std::cout<<"User: " << x.first << " Password: " << x.second.first <<" Permissions: "<< x.second.second<< std::endl;
	}
	*/



	/* Create a listening socket. */
	TCPsocket listener;
	IPport lport = atoi(argv[1]);
	IPendpoint lend(IPaddress::any(), lport);
	bind(listener, lend);
	listen(listener);
	

	while(1) {
		/* Wait for contact from a client on specified appnum.  I have
		   extended this to print client info. */
		IPendpoint rmt;
		TCPsocket c = accept(listener, rmt);
		cout << "Accepted client " << rmt << endl;

		/* Read and parse the request line */
		buffered_socket conn(c);
		try {
			//30 seconds
			//chrono::seconds s(30);
			handle_client(conn);
		} catch(socket_error &boom) {
			cout << "Connection crashed while talking to " << rmt
			     << ": " << boom.what() << endl;
		}		

		//close(c);
	}
}
string hexit(){
	char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	string hexString = "";
	
  	for(int i=0;i < 32;i++)
  	{
    	hexString.push_back(hex_characters[rand()%16]);
  	}
  	return hexString;

}

string hashit(string nonce, string nonce2,string pass){
	//cout<<"server nonce: "<< nonce<<" client nonce2: "<<nonce2<<"pass: "<<pass<<endl;
	sha256 hasher;
	string hash =
		hasher.process(nonce + nonce2+pass).getx();
		return hash;
}
/*Returns true if the data sent by the client follows the correct formatting of the 
data we have stored in the server, and false otherwise*/
bool data_checking(string user,string permission,string nonce,string nonce2,string hash){
	//bool flag = true;
	//Check if user is in the datamap
	it = users_map.find(user);
	if(it != users_map.end()){
		//cout<<"account name: "<< user<<" valid"<<endl;
		//Check permissions
		if(users_map.find(user)->second.second.compare(permission) == 0){
			//cout<<"permission is valid"<<endl;
		}else{
			return false;
		}
		string server_hash = hashit(nonce,nonce2,users_map.find(user)->second.first);
		if(server_hash.compare(hash) == 0){
			//cout<<"The hashes match"<<endl;
			return true;
		}else{
			//cout<<"server computed hash: "<<server_hash<<endl;
			//cout<<"client hash: "<< hash<<endl;
			return false;
		}

	}else{
		return false;
	}
	return false;
}

/*
 * Respond to a client connection.
 */
void handle_client(buffered_socket &conn)
{


	int n;

	/* Read the request line (first line sent), and
	   break it into its parts. */
	char buff[BUFFSIZE];
	n = recvln(conn, buff, BUFFSIZE-1);
	buff[n] = '\0';
	istringstream reqin(buff);
	string cmd, path, vers;

	reqin >> cmd >> path >> vers;
	//cout<<"cmd1: "<<cmd<<endl;
	//If the first thing is an N we know the client has requested a nonce, so lets send one
	if(cmd.compare("N") == 0){
		string server_nonce = hexit();
		string nonce = "+ " + server_nonce +" \n";
		//cout << "og ser: "<< server_nonce<<endl;
		//cout<<"clietns ser: "<<nonce<<endl;
		send(conn, nonce);
		cout << "SENT NONCE 30 SECS"<<endl;
		auto start = std::chrono::steady_clock::now();
		auto end = std::chrono::steady_clock::now() + std::chrono::seconds(30);
		
		bool timeout = true;
		while(start < end){
			//recvlm should wait 
			cout<<std::chrono::duration_cast<std::chrono::seconds>(end - std::chrono::steady_clock::now()).count()<<endl;
			n = recvln(conn, buff, BUFFSIZE-1);
			if(start < end){
				timeout = false;
				break;
			}else{
				timeout = true;
				cerr<<"Timeout has occurred "<< endl; 
				exit(1);
			}
		}
		if(timeout){
			cerr<<"Timeout has occurred "<< endl; 
				exit(1);
		}
	
		//get the client response
		
		istringstream reply(buff);
		string c,userid,userperm,nonce2,hash;
		reply >> c >> userid>>userperm>>nonce2>>hash;
		cout<<c<<endl;
		cout<<userid<<endl;
		cout<<userperm<<endl;
		cout<<nonce2<<endl;
		cout<<hash<<endl;

		bool valid = data_checking(userid,userperm,server_nonce,nonce2,hash);
		//cout<<"The data is: "<<valid<<endl;
		if(valid){
			string validity = "";
			validity.push_back('+');
			validity.append(" \n");
			cout<<validity[0]<<endl;
			send(conn,validity);
		}else{
			string invalidity = "";
			invalidity.push_back('-');
			invalidity.append(" \n");
			cout<<invalidity[0]<<endl;
			send(conn,invalidity);
		}
	}

}


	// /* Skip all headers - read until we get \r\n alone
	//    (blank line) or  EOF. */
	// while((n = recvln(conn, buff, BUFFSIZE)) > 0) {
	// 	if (n == 2 && buff[0] == '\r' && buff[1] == '\n')
	// 		break;

	// }
	
	// /* Check for a request that we cannot understand */
	// if(cmd != "GET" || (vers != "HTTP/1.0" && 
	// 		    vers != "HTTP/1.1")) {
	// 	/* Send and HTTP 400 response: header, then
	// 	 * body, then close the connection and go back
	// 	 for another. */

	// 	send_head(conn, 400, strlen(ERROR_400));
	// 	send(conn, ERROR_400, strlen(ERROR_400));
	// 	return;
	// }
	
	//  Send the requested web page or a "not found" error.
	//  * We only have two pages, so we only recognize two
	//  paths. 
	// if(path == "/") {
	// 	/* Home page. */
	// 	send_head(conn, 200, strlen(HOME_PAGE));
	// 	send(conn, HOME_PAGE, strlen(HOME_PAGE));
	// } else if(path == "/time") {
	// 	/* Build the time page. */
	// 	time_t tv = time(NULL);
	// 	string timepage = 
	// 		"<html><head></head><body>"
	// 		"<h1>The current date is: " +
	// 		string(ctime(&tv)) +
	// 		"</h1></body></html>\n";
	// 	send_head(conn, 200, timepage.length());
	// 	send(conn, timepage);
	// } else { /* not found */
	// 	send_head(conn, 404, strlen(ERROR_404));
	// 	send(conn, ERROR_404, strlen(ERROR_404));
	// }
	
//}

/*-----------------------------------------------------------------------
 * send_head - send an HTTP 1.0 header with given status and content-len
 *-----------------------------------------------------------------------
 */
void send_head(buffered_socket &conn, int stat, int len)
{
// 	const char *statstr;

// 	/* Convert the status code to a string */
// 	switch(stat) {
// 	case 200:
// 		statstr = "OK";
// 		break;
// 	case 400:
// 		statstr = "Bad Request";
// 		break;
// 	case 404:
// 		statstr = "Not Found";
// 		break;
// 	default:
// 		statstr = "Unknown";
// 		break;
// 	}
	
	
// 	 * Send an HTTP/1.0 response header with Server, Content-Length,
// 	 * and Content-Type headers.
	 
// 	ostringstream hdr;
// 	hdr << "HTTP/1.0 " << stat << " " << statstr << "\r\n"
// 	    << "Server: " << SERVER_NAME << 00694f95b6"\r\n"
// 	    << "Content-Length: " << len << "\r\n"
// 	    << "Content-Type: text/html\r\n"
// 	    << "\r\n";
// 	send(conn, hdr.str());
// 
}
