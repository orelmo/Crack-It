#include "mta_crypt.h"
#include "mta_rand.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>

#define PASSWORD_BASE_MULTIPICATION 8
#define ENCRYPTED_DATA_MAX_LEN 200
#define UNINITIALIZE -1

typedef struct toencrypter{
	char* key;
	unsigned int keyLen;
	char* plainData;
	unsigned int plainDataLen;
	unsigned int decrypterNum;
}ToEncrypter;

typedef struct todecrypter{
	char* encryptedData;
	unsigned int encryptedDataLen;
	unsigned int keyLen;
}ToDecrypter;

#define BOOL int
#define TRUE 1
#define FALSE 0
#define SIGNALED 0

ToEncrypter toEncrypter;
ToDecrypter toDecrypter;
BOOL isEncrypterResponded;
BOOL isValidToDecrypter;
BOOL isUncheckedDecryption;

pthread_cond_t cv_toDecrypter;
pthread_cond_t cv_checkDecryptedData;

pthread_mutex_t waitForDecrypterMutex;
pthread_mutex_t toDecrypterLock;
pthread_mutex_t toEncrypterDercryptersLock;

pthread_attr_t decrypterAttr;
pthread_attr_t encrypterAttr;


void analyzeFlags(int argc,char* argv[],int* numOfDecrypters,int* passwordLen,int* timeOut);
void checkFlagValue(char* argv[], int i);
pthread_t createEncrypter(int timeOut,unsigned int passwordLen);
BOOL checkDecryption(char* plainData);
void initMutexesAndConditions();
void destroyMutexesAndConditions();
void getEncryptedData(char* key,unsigned int keyLen,char* plainData,
	unsigned int plainDataLength,char* encryptedData,unsigned int* encryptedDataLength);
void updateToDecrypter(char* encryptedData,unsigned int encryptedDataLength,unsigned int keyLen);
void printSuccessMessage();
void printFailerMessage(char* plainData);
void printCryptError(MTA_CRYPT_RET_STATUS status, char* sender);
void updateToEncrypter(char* key,unsigned int keyLen,char* plainData,unsigned int plainDataLen, int decrypterNum);
BOOL isPrintableString(char* string, unsigned int stringLen);
pthread_t* createDecrypters(unsigned int numOfDecrypters,int* decryptersNumbersums);
void* encrypt(void* param);
void* decrypt(void* decrypterNum);
void handleWithTimeOut(char* plainData,BOOL* isCorrectDecryption,int timeOut);
void handleWithoutTimeOut(char* plainData,BOOL* isCorrectDecryption);
void freeDecrypters(pthread_t* decrypters, int* decryptersNumbers);
void waitAllThreads(pthread_t encrypter,pthread_t* decrypters,unsigned int numOfDecrypters);
void getPrintablePlainData(char* plainData,unsigned int plainDataLength);
void printGeneratedData(char* plainData);
void printEncrypterStartGenerating();

int main( int argc, char* argv[]){
	int numOfDecrypters, passwordLen, timeOut=UNINITIALIZE;
	analyzeFlags(argc,argv,&numOfDecrypters,&passwordLen,&timeOut);
	int* decryptersNumbers = (int*)malloc(sizeof(int)*numOfDecrypters);
	initMutexesAndConditions();
	pthread_t encrypter = createEncrypter(timeOut,passwordLen);
	pthread_t* decrypters = createDecrypters(numOfDecrypters,decryptersNumbers);
	waitAllThreads(encrypter,decrypters,numOfDecrypters);
	destroyMutexesAndConditions();
	freeDecrypters(decrypters,decryptersNumbers);
}

void waitAllThreads(pthread_t encrypter,pthread_t* decrypters,unsigned int numOfDecrypters){
	pthread_join(encrypter, NULL);
	for( int i =0;i<numOfDecrypters; ++i){
		pthread_join(decrypters[i], NULL);
	}
}

void freeDecrypters(pthread_t* decrypters,int* decryptersNumbers){
	free(decrypters);
	free(decryptersNumbers);
}

void initMutexesAndConditions(){
	pthread_mutex_init(&toEncrypterDercryptersLock,NULL);
	pthread_mutex_init(&waitForDecrypterMutex,NULL);
	pthread_mutex_init(&toDecrypterLock,NULL);
	pthread_cond_init(&cv_toDecrypter,NULL);
	pthread_cond_init(&cv_checkDecryptedData,NULL);
}

void destroyMutexesAndConditions(){
	pthread_mutex_destroy(&toEncrypterDercryptersLock);
	pthread_mutex_destroy(&waitForDecrypterMutex);
	pthread_mutex_destroy(&toDecrypterLock);
	pthread_cond_destroy(&cv_toDecrypter);
	pthread_cond_destroy(&cv_checkDecryptedData);
	pthread_attr_destroy(&encrypterAttr);
	pthread_attr_destroy(&decrypterAttr);
}

void analyzeFlags(int argc,char* argv[],int* numOfDecrypters,int* passwordLen,int* timeOut){
	if(argc<5){
		printf("Not enought input arguments\n");
		exit(-1);
	}
	for (int i=1; i<argc-1; i+=2){
		if(strcmp("-n", argv[i])==0 || strcmp("--num-of-decrypters",argv[i])==0){
			checkFlagValue(argv,i);
			*numOfDecrypters = atoi(argv[i+1]);
		}
		else if(strcmp("-l", argv[i])==0 || strcmp("--password-length",argv[i])==0){
			checkFlagValue(argv,i);
			*passwordLen = atoi(argv[i+1]);
		}
		else if(strcmp("-t", argv[i])==0 || strcmp("--timeout",argv[i])==0){
			checkFlagValue(argv,i);
			*timeOut = atoi(argv[i+1]);
		}
	}
}

void checkFlagValue(char* argv[], int i){
	if(argv[i+1]==NULL){
		printf("%s Flag has no value\n",argv[i]);
		exit(-1);
	}
	int valueAsInt = atoi(argv[i+1]);
	if(valueAsInt<=0){
		printf("%s Flag value is incorrect\n", argv[i]);
		exit(-1);
	}
	if(strcmp("-l", argv[i])==0 || strcmp("--password-length",argv[i])==0){
		if(valueAsInt%PASSWORD_BASE_MULTIPICATION != 0){
			printf("Password length must be a multiplication of 8\n");
			exit(-1);
		}
	}
}

pthread_t createEncrypter(int timeOut,unsigned int passwordLen){
	struct sched_param max_prio = {sched_get_priority_max(SCHED_FIFO)}; 
	assert(pthread_attr_init(&encrypterAttr)==0);
	assert(pthread_attr_setschedpolicy(&encrypterAttr, SCHED_FIFO)==0);
	assert(pthread_attr_setschedparam(&encrypterAttr, &max_prio)==0);
	assert(pthread_attr_setinheritsched(&encrypterAttr, PTHREAD_EXPLICIT_SCHED)==0);

	pthread_t encrypter;
	int* args =(int*)malloc(sizeof(int)*2);
	args[0] =timeOut;
	args[1] = passwordLen;
	assert(pthread_create(&encrypter,&encrypterAttr,encrypt,args)==0);
	return encrypter;
}

void handleWithoutTimeOut(char* plainData,BOOL* isCorrectDecryption){
	while(*isCorrectDecryption== FALSE){
		while(isUncheckedDecryption == FALSE){
			pthread_cond_signal(&cv_checkDecryptedData);
			pthread_cond_wait(&cv_checkDecryptedData,&waitForDecrypterMutex);
		}
		*isCorrectDecryption = checkDecryption(plainData);
		if(*isCorrectDecryption){
			printSuccessMessage();
		}
		else{
			printFailerMessage(plainData);
		}
		isUncheckedDecryption = FALSE;
		isEncrypterResponded = TRUE;
	}
}

void handleWithTimeOut(char* plainData,BOOL* isCorrectDecryption,int timeOut){
	struct timespec waitingTime;
	clock_gettime(CLOCK_REALTIME, &waitingTime);
	waitingTime.tv_sec += timeOut;
	int status=UNINITIALIZE;
	while(status !=ETIMEDOUT && *isCorrectDecryption== FALSE ){
		while((status != ETIMEDOUT && status != SIGNALED )){
			pthread_cond_signal(&cv_checkDecryptedData);
			status = pthread_cond_timedwait(&cv_checkDecryptedData,&waitForDecrypterMutex,&waitingTime);
		}
		if(status == ETIMEDOUT){
			printf("[Server]\tNo password recived during the configured timeout period (%d seconds), regenerating password\n", timeOut);
			isEncrypterResponded = TRUE;
			break;
		}
		else{
			*isCorrectDecryption = checkDecryption(plainData);
			if(*isCorrectDecryption){
				printSuccessMessage();
				isEncrypterResponded = TRUE;
				
				break;
			}
			else{
				status=UNINITIALIZE;
				printFailerMessage(plainData);
				isEncrypterResponded = TRUE;
			}
		}
		
	}
}



void printFailerMessage(char* plainData){
	printf("[Server]\tWrong password recived from Client #%d, recived (%s) should be (%s)\n",
		toEncrypter.decrypterNum, toEncrypter.plainData, plainData);
}

void printSuccessMessage(){
	printf("[Server]\tPassword decryped successfully by Client #%d, recived (%s)\n",
	toEncrypter.decrypterNum, toEncrypter.plainData);
}

void updateToDecrypter(char* encryptedData,unsigned int encryptedDataLength,unsigned int keyLen){
	pthread_mutex_lock(&toDecrypterLock);
	toDecrypter.encryptedData = encryptedData;
	toDecrypter.encryptedDataLen = encryptedDataLength;
	toDecrypter.keyLen = keyLen;
	isValidToDecrypter = TRUE;
	pthread_mutex_unlock(&toDecrypterLock);
}

void getEncryptedData(char* key,unsigned int keyLen,char* plainData,
	unsigned int plainDataLength,char* encryptedData,unsigned int* encryptedDataLength){
	MTA_CRYPT_RET_STATUS retStatus;
	do{
		retStatus = MTA_encrypt(key,keyLen,plainData
			,plainDataLength,encryptedData,encryptedDataLength);
		if(retStatus!=MTA_CRYPT_RET_OK){
			printCryptError(retStatus,"Server");
		}
	}while(retStatus!=MTA_CRYPT_RET_OK);
}

void printCryptError(MTA_CRYPT_RET_STATUS status, char* sender){
	char* errors[8] = {"MTA_CRYPT_RET_OK","MTA_CRYPT_RET_ERROR", "MTA_CRYPT_RET_NULL_PTR_RECEIVED",
		"MTA_CRYPT_RET_DATA_ZERO_LENGTH", "MTA_CRYPT_RET_DATA_MAX_LENGTH_EXCEEDED",
		"MTA_CRYPT_RET_KEY_ZERO_LENGTH", "MTA_CRYPT_RET_KEY_MAX_LENGTH_EXCEEDED",
		"MTA_CRYPT_RET_NOT_8_BYTE_MULTIPLICATION"};
	printf("[%s]\tAn error occurred: %s\n",sender,errors[status]);
	if(status>=2){
		exit(-1);
	}
}

BOOL checkDecryption(char* plainData){
	BOOL res = memcmp(plainData, toEncrypter.plainData,toEncrypter.plainDataLen)==0 ? TRUE:FALSE;

	return res;
}

pthread_t* createDecrypters(unsigned int numOfDecrypters,int* decryptersNumbers){
	struct sched_param min_prio = {sched_get_priority_min(SCHED_RR)}; 
	assert(pthread_attr_init(&decrypterAttr)==0);
	assert(pthread_attr_setschedpolicy(&decrypterAttr, SCHED_RR)==0);
	assert(pthread_attr_setschedparam(&decrypterAttr, &min_prio)==0);
	assert(pthread_attr_setinheritsched(&decrypterAttr, PTHREAD_EXPLICIT_SCHED)==0);

	pthread_t* decrypters = (pthread_t*)malloc(numOfDecrypters*sizeof(pthread_t));
	for (int i=0; i<numOfDecrypters;++i){
		decryptersNumbers[i]=i;
		assert(pthread_create(&decrypters[i],NULL,decrypt,&decryptersNumbers[i])==0);
	}
	return decrypters;
}

void getPrintablePlainData(char* plainData,unsigned int plainDataLength){
	char c;
	for(int i =0; i<plainDataLength;++i){
		do{
			c = MTA_get_rand_char();
		}while(isprint(c)==FALSE);
		plainData[i] = c;
	}
	plainData[plainDataLength] = '\0';
}

void* encrypt(void* param){
	printf("[Server]\tStarting...\n");

	BOOL isCorrectDecryption = FALSE;
	unsigned int encryptedDataLength;
	int plainDataLength = ((int*)param)[1];
	char *encryptedData = (char*)malloc(sizeof(char)*ENCRYPTED_DATA_MAX_LEN);
	char* plainData = (char*)malloc(sizeof(char)*(plainDataLength+1));
	int keyLen= plainDataLength/PASSWORD_BASE_MULTIPICATION;
	char* key = (char*)malloc(sizeof(char)*keyLen);
	int timeout = ((int*)param)[0];
	int retStatus;
	pthread_mutex_lock(&waitForDecrypterMutex);
	while(1){
		isValidToDecrypter = FALSE;
		isCorrectDecryption = FALSE;
		printEncrypterStartGenerating();
		getPrintablePlainData(plainData,plainDataLength);
		MTA_get_rand_data(key,keyLen);
		getEncryptedData(key,keyLen,plainData,plainDataLength,encryptedData,&encryptedDataLength);
		if(encryptedDataLength%PASSWORD_BASE_MULTIPICATION!=0){
			continue;
		}
		updateToDecrypter(encryptedData, encryptedDataLength,keyLen);
		printGeneratedData(plainData);
		isValidToDecrypter = TRUE;
		pthread_cond_broadcast(&cv_toDecrypter);
		if(timeout != -1){
			handleWithTimeOut(plainData,&isCorrectDecryption,timeout);
		}
		else
		{
			handleWithoutTimeOut(plainData,&isCorrectDecryption);
		}
		isUncheckedDecryption = FALSE;
	}
	free(key);
	free(plainData);
	free(encryptedData);
}

void printEncrypterStartGenerating(){
	printf("[Server]\tStart generating a new password...\n");
}

void printGeneratedData(char* plainData){
	printf("[Server]\tNew password was generated: (%s)\n",plainData);
}

void* decrypt(void* decrypterNum){
	printf("[Client #%d]\tStarting...\n",*((int*)decrypterNum)+1);

	unsigned int plainDataLen;
	unsigned int keyLen;
	char* encryptedData;
	unsigned int encryptedDataLen;

	pthread_mutex_lock(&toDecrypterLock);
	while(isValidToDecrypter == FALSE){
		pthread_cond_wait(&cv_toDecrypter,&toDecrypterLock);
	}
	pthread_mutex_unlock(&toDecrypterLock);

	while(1){
		pthread_mutex_lock(&toDecrypterLock);
		encryptedDataLen = toDecrypter.encryptedDataLen;
		encryptedData = (char*)malloc(sizeof(char)*encryptedDataLen);
		keyLen = toDecrypter.keyLen;
		memcpy(encryptedData,toDecrypter.encryptedData,encryptedDataLen);
		pthread_mutex_unlock(&toDecrypterLock);
		
		char* plainData = (char*)malloc(sizeof(char)*(encryptedDataLen+1));
		char* key = (char*)malloc(sizeof(char)*keyLen);
		MTA_get_rand_data(key,keyLen);
		MTA_CRYPT_RET_STATUS status = MTA_decrypt(key,keyLen,encryptedData,
			encryptedDataLen,plainData,&plainDataLen);
		plainData[plainDataLen] = '\0';
		if(status != MTA_CRYPT_RET_OK){
			char sender[256];
			sprintf(sender, "Client #%d",(*((int*)decrypterNum))+1);
			printCryptError(status,sender);
			continue;
		}
		if(isPrintableString(plainData,plainDataLen)==TRUE){
			pthread_mutex_lock(&toEncrypterDercryptersLock);

			updateToEncrypter(key,keyLen,plainData,plainDataLen,(*((int*)decrypterNum))+1);
			isEncrypterResponded = FALSE;

			printf("[Client #%d]\tAfter decryption (%s), sending to server\n",
				(*((int*)decrypterNum))+1,plainData);

			pthread_mutex_lock(&waitForDecrypterMutex);
			while(isEncrypterResponded == FALSE){
				pthread_cond_signal(&cv_checkDecryptedData);
				pthread_cond_wait(&cv_checkDecryptedData,&waitForDecrypterMutex);
			}
			pthread_mutex_unlock(&waitForDecrypterMutex);
			pthread_mutex_unlock(&toEncrypterDercryptersLock);
		}
		free(encryptedData);
		free(key);
		free(plainData);
	}
}

BOOL isPrintableString(char* string, unsigned int stringLen){
	for(int i =0; i<stringLen; ++i){
		if(isprint(string[i])==FALSE){
			return FALSE;
		}
	}
	return TRUE;
}

void updateToEncrypter(char* key,unsigned int keyLen,char* plainData,unsigned int plainDataLen, int decrypterNum){
	toEncrypter.key = key;
	toEncrypter.keyLen = keyLen;
	toEncrypter.plainData = plainData;
	toEncrypter.plainDataLen = plainDataLen;
	toEncrypter.decrypterNum = decrypterNum;
	isUncheckedDecryption = TRUE;
}