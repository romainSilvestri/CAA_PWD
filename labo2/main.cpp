#include <iostream>
#include <fstream>
#include <sodium.h>
#include <cstring>
#include "base64.h"

#define PASSWORD_SIZE 1024

using namespace std;

void encode(unsigned char* cipher, unsigned char* msg, unsigned char* nonce,  unsigned char* key){

    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(cipher, msg, strlen((char*) msg), nonce, key);
}

int decode(unsigned char* plain, unsigned char* cipher, unsigned char* nonce, unsigned char* key){
    return crypto_secretbox_open_easy(plain, cipher, strlen((char*) cipher), nonce, key);
}

int main() {

    if(sodium_init()){
        return EXIT_FAILURE;
    }

    const string FILEPATH = "../db.txt";
    const string TMPPATH = "../tmp.txt";

    bool first = true;

    FILE* db = fopen(FILEPATH.c_str(), "r+");

    if(db == NULL){
        db = fopen(FILEPATH.c_str(), "wr+");

        char* pwd = (char*) sodium_malloc(PASSWORD_SIZE + 1); // on met + 1 pour avoir la place pour le \0
        if(pwd == NULL){
            return EXIT_FAILURE;
        }

        cout << "Enter a master password of, at most, " << PASSWORD_SIZE << " char:" << endl;

        cin >> pwd;

        char hashed_pwd[crypto_pwhash_STRBYTES];
        if(crypto_pwhash_str(hashed_pwd, pwd, strlen(pwd), crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN)){ // TODO: remettre en sensitive
            sodium_free(pwd);
            fclose(db);
            return EXIT_FAILURE;
        }

        unsigned char salt[crypto_pwhash_SALTBYTES];
        randombytes_buf(salt, sizeof salt);
        string encodedSalt = base64_encode(salt, sizeof(salt));

        fputs(hashed_pwd, db);
        fputc('\n', db);
        fputs(encodedSalt.c_str(), db);
        fputc('\n', db);
        sodium_free(pwd);

    }

    while(true){

        if(!first){
            db = fopen(FILEPATH.c_str(), "r+");
        }
        char* pwd = (char*) sodium_malloc(PASSWORD_SIZE + 1); // on met + 1 pour avoir la place pour le \0
        if (pwd == NULL) {
            return EXIT_FAILURE;
        }

        cout << "Please enter the master password" << endl;

        cin >> pwd;

        char storedHash[crypto_pwhash_STRBYTES];
        fgets(storedHash, crypto_pwhash_STRBYTES, db);

        size_t len = strlen(storedHash);    // Cette partie enleve le \n à la fin de la ligne si il y en a plus qu'une
        if(len > 0 && storedHash[len-1] == '\n'){
            storedHash[--len] = '\0';
        }

        if(crypto_pwhash_str_verify(storedHash, pwd, strlen(pwd) )){
            // The password is incorrect
            cout << "Master password incorrect" << endl;
            sodium_free(pwd);
            fclose(db);
            continue;
        }

        // this part recover the salt from the file
        fstream file2;
        file2.open("../db.txt");
        string storedEncodedSalt;
        getline(file2, storedEncodedSalt); // first line is the hash
        getline(file2, storedEncodedSalt); // this line is the salt

        file2.close();

        string storedSalt = base64_decode(storedEncodedSalt);


        unsigned char* key = (unsigned char*) sodium_malloc(crypto_secretbox_KEYBYTES);
        if (key == NULL) {
            cout << "Error allocating space" << endl;
            sodium_free(pwd);
            break;
        }

        if(crypto_pwhash(key, crypto_secretbox_KEYBYTES, pwd, strlen(pwd), (unsigned char*) storedSalt.c_str(), crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_ALG_DEFAULT)) {
            cout << "Failure in KDF" << endl;
            sodium_free(pwd);
            sodium_free(key);
            fclose(db);
            return EXIT_FAILURE;
        }

        fclose(db);
        sodium_free(pwd);
        first = false;

        while (true) { // We are unlocked
            fstream file;
            string command;
            string siteName;
            string delimiter = " ---- ";

            cout << "Please enter the command (lock, change, store or recover): " << endl;

            cin >> command; // todo: regarder pour mettre des fgets(variable, taille, stdin)

            if(command == "lock"){
                sodium_free(key);
                break;
            }

            if(command == "change"){

                file.open(FILEPATH);
                fstream newDB;

                newDB.open(TMPPATH.c_str(), ios::app);

                char* newPwd = (char*) sodium_malloc(PASSWORD_SIZE + 1); // on met + 1 pour avoir la place pour le \0
                if (newPwd == NULL) {
                    cout << "Error allocating space" << endl;
                    break;
                }

                cout << "Enter the new master password of, at most," << PASSWORD_SIZE << " char:" << endl;
                cin >> newPwd;

                unsigned char newSalt[crypto_pwhash_SALTBYTES];
                randombytes_buf(newSalt, sizeof newSalt);
                string encodedNewSalt = base64_encode(newSalt, sizeof(newSalt));

                unsigned char* newKey = (unsigned char*) sodium_malloc(crypto_secretbox_KEYBYTES);
                if (newKey == NULL) {
                    cout << "Error allocating space" << endl;
                    sodium_free(newPwd);
                    sodium_free(key);
                    break;
                }

                if(crypto_pwhash(newKey, crypto_secretbox_KEYBYTES, newPwd, strlen(newPwd), newSalt, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_ALG_DEFAULT)) {
                    cout << "Failure in KDF" << endl;
                    sodium_free(newPwd);
                    sodium_free(newKey);
                    sodium_free(key);
                    fclose(db);
                    return EXIT_FAILURE;
                }

                char newHashedPwd[crypto_pwhash_STRBYTES];
                if(crypto_pwhash_str(newHashedPwd, newPwd, strlen(newPwd), crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_MEMLIMIT_MIN)){ // TODO: remettre en sensitive
                    sodium_free(newPwd);
                    sodium_free(newKey);
                    sodium_free(key);
                    newDB.close();
                    return EXIT_FAILURE;
                }

                newDB << newHashedPwd << endl;
                newDB << encodedNewSalt << endl;

                sodium_free(newPwd);

                string line;
                getline(file, line); // Remove the hash
                getline(file, line); // Remove the salt

                // Iterate over all the stored sites
                while(getline(file, line)){
                    string storedSite = line.substr(0, line.find(delimiter));
                    string tmp = line.substr(line.find(delimiter) + delimiter.size());
                    string encodedStoredPwd = tmp.substr(0, tmp.find(delimiter));
                    string encodedStoredNonce = tmp.substr(tmp.find(delimiter) + delimiter.size());

                    unsigned char* recoverResult = (unsigned char*) sodium_malloc(PASSWORD_SIZE + 1);
                    if (recoverResult == NULL) {
                        cout << "Error allocating space" << endl;
                        break;
                    }

                    string storedPwd = base64_decode(encodedStoredPwd);
                    string storedNonce = base64_decode(encodedStoredNonce);

                    // Add a \0 at the end of the recovered password so we can print it
                    recoverResult[storedPwd.size() - crypto_secretbox_KEYBYTES] = '\0';

                    if(decode(recoverResult, (unsigned char*) storedPwd.c_str(), (unsigned char*) storedNonce.c_str(), key) != 0 ){
                        cout << "Error while recovering password" << endl;
                        sodium_free(newKey);
                        sodium_free(key);
                        sodium_free(recoverResult);
                        return EXIT_FAILURE;
                    }

                    unsigned char nonce[crypto_secretbox_NONCEBYTES];
                    unsigned char cipher[crypto_secretbox_KEYBYTES + strlen((char*) recoverResult)];

                    encode(cipher, recoverResult, (unsigned char*) nonce, newKey);

                    string encodedNonce = base64_encode(nonce, sizeof(nonce));
                    string encodedCipher = base64_encode(cipher, sizeof(cipher));

                    newDB << storedSite << delimiter << encodedCipher << delimiter << encodedNonce << endl;

                    sodium_free(recoverResult);
                }

                remove(FILEPATH.c_str());
                rename(TMPPATH.c_str(), FILEPATH.c_str());

                sodium_free(key);
                sodium_free(newKey);
                file.close();
                break;
            }

            if(command == "store"){
                file.open(FILEPATH, ios::app);

                cout << "Please enter the site name: " << endl;
                cin >> siteName;
                cout << "Please enter the password (min: 6 char): "  << endl;

                unsigned char* newPwd = (unsigned char*) sodium_malloc(PASSWORD_SIZE + 1); // on met + 1 pour avoir la place pour le \0
                if (newPwd == NULL) {
                    cout << "Error allocating space" << endl;
                    break;
                }
                cin >> newPwd;

                unsigned char nonce[crypto_secretbox_NONCEBYTES];
                unsigned char cipher[crypto_secretbox_KEYBYTES + strlen((char*) newPwd)];

                encode(cipher, newPwd, nonce, key);

                // We decode it on the spot to see if the password was a supported one. The decode doesn't work with 6 or less char passwords and 8 char passwords.
                if(decode(newPwd, cipher, nonce, key)){
                    cout << "Error, invalid password" << endl;
                    sodium_free(newPwd);
                    continue;
                }

                sodium_free(newPwd);

                string encodedNonce = base64_encode(nonce, sizeof(nonce));
                string encodedCipher = base64_encode(cipher, sizeof(cipher));

                file << siteName << delimiter << encodedCipher << delimiter << encodedNonce << endl;
            }

            if(command == "recover"){
                string line;
                bool found = false;
                string encodedStoredPwd;
                string encodedStoredNonce;

                file.open(FILEPATH);

                getline(file, line); // get the first line which is the hash
                getline(file, line); // get the second line which is the salt

                cout << "Please enter the site name: " << endl;
                cin >> siteName;

                while(getline(file, line)){
                    string storedSite = line.substr(0, line.find(delimiter));
                    if(storedSite == siteName){
                        found = true;
                        string tmp = line.substr(line.find(delimiter) + delimiter.size());
                        encodedStoredPwd = tmp.substr(0, tmp.find(delimiter));
                        encodedStoredNonce = tmp.substr(tmp.find(delimiter) + delimiter.size());
                        break;
                    }
                }

                if(found){
                    unsigned char* recoverResult = (unsigned char*) sodium_malloc(PASSWORD_SIZE + 1);
                    if (recoverResult == NULL) {
                        cout << "Error allocating space" << endl;
                        break;
                    }

                    string storedPwd = base64_decode(encodedStoredPwd);
                    string storedNonce = base64_decode(encodedStoredNonce);

                    // Add a \0 at the end of the recovered password so we can print it
                    recoverResult[storedPwd.size() - crypto_secretbox_KEYBYTES] = '\0';

                    if(decode(recoverResult, (unsigned char*) storedPwd.c_str(), (unsigned char*) storedNonce.c_str(), key) != 0 ){
                        cout << "Error while recovering password" << endl;
                        sodium_free(recoverResult);
                        continue;
                    }

                    cout << recoverResult << endl;

                    sodium_free(recoverResult);

                }else{
                    cout << "Not found" << endl;
                }
                continue;
            }
            file.close();
        }
    }
    return 0;
}