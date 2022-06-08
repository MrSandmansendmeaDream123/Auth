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

using namespace std::chrono_literals;

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <thread>
#include <mutex>
#include <condition_variable>

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

/*Map to hold users as the key and the users password and permissions
  as the value (combined into pair<string,string>). Also made an iterator for it*/
unordered_map<string,pair<string,string>> users_map;
unordered_map<string,pair<string,string>>::iterator it;

int main(int argc, char *argv[])
{
	//If you do not have the right parameters, you will not run!
	if (argc != 3) {
		cerr << "usage: " << argv[0] << " <portnum> <datafile>" << endl;
		exit(1);
	}

	//Attempt to process file, open, check if open, if not exit, else start adding to the map
	ifstream datafile;
	datafile.open(argv[2]);
	if(datafile.is_open()){
		
		/*Get each line of the file and process the data so it 
		  can be stored in the map*/
		while(datafile){ 

			string userdata;	
			getline(datafile,userdata);

			//Prevents the empty string from causing issues,if the string is empty, do not process
			if(userdata.compare("") != 0){ 
				//Just some simple cleaning and parsing nothing to see here...
				//Removing the ":" and placing the values into their correct varriables
				string user = userdata.substr(0,userdata.find(":"));
				userdata = userdata.substr(userdata.find(":")+1,userdata.length());
				string password = userdata.substr(0,userdata.find(":"));
				string perm = userdata.substr(userdata.find(":")+1,userdata.length());
				/*
				//=================Testing===================
				cout<<user<<endl;
				cout<<password<<endl;
				cout<<perm<<endl;
				//===========================================
				*/

				//Add to the map,pair the password and permission,then add the username as the key
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
/*Method to produce a 16 byte long random number,represented as a hex number with 32 digits
Using an array of all hex values, pick a random choice from the array 32 times and concat them to a string*/
string hexit(){
	char hex_characters[]={'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
	string hexString = "";
	
  	for(int i=0;i < 32;i++)
  	{
    	hexString.push_back(hex_characters[rand()%16]);
  	}
  	return hexString;

}
/*Does the hasing that the client does but, with the data we have here,(excluding the nonce2)
Allows us to use the password without it being passed over the network,same calculation is performed
in the client, using sha256 to perform the encryption*/
string hashit(string nonce, string nonce2,string pass){
	sha256 hasher;
	string hash =
		hasher.process(nonce + nonce2+pass).getx();
		return hash;
}
/*Returns true if the data sent by the client follows the correct formatting of the 
data we have stored in the server, and false otherwise*/
bool data_checking(string user,string permission,string nonce,string nonce2,string hash){
	
	//Check if user is in the map that all of the users are stored in,if this does not
	//fail we precede to the permission, otherwise return false
	it = users_map.find(user);
	if(it != users_map.end()){
		//Check permissions for this user,if this is correct continue to the hash check, else return false;
		if(users_map.find(user)->second.second.compare(permission) == 0){
			//The permission is valid
			//cout<<"Valid Permission"<<endl;
		}else{
			//the permission is not correct for this user
			//cout<<"Invalid Permission"<<endl;
			return false;
		}
		//Get the servers hash and then compare it to the clients, if they match we have a valid user, else we do not
		string server_hash = hashit(nonce,nonce2,users_map.find(user)->second.first);
		if(server_hash.compare(hash) == 0){
			//The hashes match!
			//cout<<"The hashes match"<<endl;
			return true;
		}else{
			//The hashes do not match
			//cout<<"The hashes do not match"<<endl;
			//cout<<"server computed hash: "<<server_hash<<endl;
			//cout<<"client computed hash: "<< hash<<endl;
			return false;
		}

	}else{
		//user was not found
		//cout<<"Invalid User"<<endl;
		return false;
	}
	return false;
}

//Removed as inifite wait is assumed to not occurr
//Wrapper method for recvln, uses a thread detached thread for timeout
/*int recvln_wraper(buffered_socket &b, void *buf,int size){
	std::mutex m;
	std:: condition_variable c;
	int n;

	std::unique_lock<std::mutex> l(m);

	//if the recive occurs in the seperate thread it will notify c, and continue
	std::thread t([&b,&buf,&c, &n]() 
    {
        n = recvln(b, buf, BUFFSIZE-1);
        c.notify_one();
        
    });

	//Separates the thread of execution from the thread object, allowing execution to continue independently.
    t.detach();
    
        //Waits 30 seconds for the thread
        //std::cv_status describes whether a timed wait returned because of timeout or no
        //timeout 	the condition variable was awakened by timeout expiration 
        if(c.wait_for(l, 30s) == std::cv_status::timeout){
            throw std::runtime_error("Timeout has occured");
        }else{
        	cout<<"aok"<<endl;
        }
    
    //will only return n should the thread be fitting the above conditions
    return n;
}*/

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
	
	//If its a N the client has requested a nonce,so send one with the correct formatting
	if(cmd.compare("N") == 0){
		string server_nonce = hexit();
		string nonce = "+ " + server_nonce +" \n";
		send(conn, nonce);
		
		//Removed as threading not a requirement and the assumption of an infinite wait was not important
		//Recieves back from the client, using a timeout of 30s to prevent an infinite wait time
		/*try{ 
		n = recvln_wraper(conn, buff, BUFFSIZE-1);
		}catch(std::runtime_error& e){
			cout<<e.what() <<endl;
			exit(1);
		}*/

		//Threading is not needed for this program so I can use a simple timestamp that was my original solution
		//Set the current time as start, and 30 seconds in the future as timeout, simply check if after the recvln 30 seconds has not passed
		auto start = std::chrono::steady_clock::now();
		auto time_out = std::chrono::steady_clock::now() + std::chrono::seconds(30);
		n = recvln(conn, buff, BUFFSIZE-1);
		auto end = std::chrono::steady_clock::now();
	
		//If the end time is more than 30 seconds then we have timed out, so exit
		if(end > time_out){
				cerr<<"Timeout has occurred "<< endl; 
				exit(1);
			}
		
		
		
		//Seperate the data gathered from the client into seperate strings
		istringstream reply(buff);
		string c,userid,userperm,nonce2,hash;
		reply >> c >> userid>>userperm>>nonce2>>hash;

		//============Check===============
		// cout<<c<<endl;
		// cout<<userid<<endl;
		// cout<<userperm<<endl;
		// cout<<nonce2<<endl;
		// cout<<hash<<endl;
		//================================

		//Method checks the validity of the data the client sends to use, returns true if
		//the data is valid, and false if it is not valid
		bool valid = data_checking(userid,userperm,server_nonce,nonce2,hash);
		//If valid, send the appropriate string to the client, if not send the appropriate string as well
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
	}else{
		string error = "E Badly formed check message \n";
		send(conn, error);
	}
}




/*-----------------------------------------------------------------------
 * send_head - send an HTTP 1.0 header with given status and content-len
 *-----------------------------------------------------------------------
 */
void send_head(buffered_socket &conn, int stat, int len)
{
//Not used for this project
}
