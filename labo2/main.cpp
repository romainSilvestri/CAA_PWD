#include <iostream>
#include <fstream>
#include <sodium.h>
#include <cstring>
#include "base64.h"

#define PASSWORD_SIZE 1024

using namespace std;

void encode(unsigned char* cipher, unsigned char* key, unsigned char* nonce, unsigned char* msg){

    randombytes_buf(nonce, sizeof nonce);
    crypto_secretbox_easy(cipher, msg, strlen((char*) msg), nonce, key);
}

void decode(unsigned char* cipher, unsigned char* key, unsigned char* nonce, unsigned char* plain){
    int ret = crypto_secretbox_open_easy(plain, cipher, strlen((char*) cipher), nonce, key);
}


int main() {

    if(sodium_init()){
        return EXIT_FAILURE;
    }

    bool first = true;

    FILE* db = fopen("../db.txt", "r+");

    if(db == NULL){
        db = fopen("../db.txt", "wr+");

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
            db = fopen("../db.txt", "r+");
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

        unsigned char key[crypto_secretbox_KEYBYTES]; // TODO: faire un malloc pour ca que l'on libère après


        if(crypto_pwhash(key, sizeof key, pwd, strlen(pwd), (unsigned char*) storedSalt.c_str(), crypto_pwhash_MEMLIMIT_MIN, crypto_pwhash_OPSLIMIT_MIN, crypto_pwhash_ALG_DEFAULT)) {
            cout << "Failure in KDF" << endl;
            /*sodium_free(pwd);
            fclose(db);
            return EXIT_FAILURE;*/
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

            cin >> command;

            if(command == "lock"){
                // TODO: free la clé
                break;
            }

            if(command == "change"){

                char* newPwd = (char*) sodium_malloc(PASSWORD_SIZE + 1); // on met + 1 pour avoir la place pour le \0
                if (newPwd == NULL) {
                    cout << "Error allocating space" << endl;
                    break;
                }

                cout << "Enter the new master password of, at most," << PASSWORD_SIZE << " char:" << endl;
                cin >> newPwd;

                cout << newPwd << endl;

                // todo: refaire le KDF et tout rechiffrer.

                sodium_free(newPwd);
                break;
            }

            if(command == "store"){
                file.open("../db.txt", ios::app);

                cout << "Please enter the site name: " << endl;
                cin >> siteName;
                cout << "Please enter the password: "  << endl;

                unsigned char* newPwd = (unsigned char*) sodium_malloc(PASSWORD_SIZE + 1); // on met + 1 pour avoir la place pour le \0
                if (newPwd == NULL) {
                    cout << "Error allocating space" << endl;
                    break;
                }
                cin >> newPwd;

                unsigned char nonce[crypto_secretbox_NONCEBYTES];
                unsigned char cipher[crypto_secretbox_KEYBYTES + siteName.size()];

                encode(cipher, key, nonce, newPwd);

                sodium_free(newPwd);

                string encodedNonce = base64_encode(nonce, sizeof(nonce));
                string encodedCipher = base64_encode(cipher, sizeof(cipher));


                // todo: chiffrer le newPwd, le mettre en b64 , mettre le nonce en b64 et le stocker aussi

                file << siteName << delimiter << encodedCipher << delimiter << encodedNonce << endl;
            }

            if(command == "recover"){
                string line;
                bool found = false;
                string cipherPwdString;
                string nonceString;

                file.open("../db.txt");

                getline(file, line); // get the first line which is the hash;

                cout << "Please enter the site name: " << endl;
                cin >> siteName;

                while(getline(file, line)){
                    string storedSite = line.substr(0, line.find(delimiter));
                    if(storedSite == siteName){
                        found = true;
                        string tmp = line.substr(line.find(delimiter) + delimiter.size());
                        cipherPwdString = tmp.substr(0, tmp.find(delimiter));
                        nonceString = tmp.substr(tmp.find(delimiter) + delimiter.size());
                        break;
                    }
                }

                if(found){
                    cout << "found" << endl;
                    /*
                    unsigned char plain[1000];
                    unsigned char* cipherPwd[cipherPwdString.size() + 1];
                    strcpy((char*) cipherPwd, cipherPwdString.c_str());
                    unsigned char* nonce[nonceString.size() + 1];
                    strcpy((char*) nonce, nonceString.c_str());

                    decode(*cipherPwd, key, *nonce, plain);*/
                    cout << cipherPwdString << endl; // todo: call the decypher function
                    cout << nonceString << endl;
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