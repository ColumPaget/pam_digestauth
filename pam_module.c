/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: GPL-3.0
*/

#include "common.h"
#include "utility.h"
#include "sha2.h"
#include <syslog.h>
#include <unistd.h>
#include <time.h>


//Define which PAM interfaces we provide. In this case we are
//only going to provide an authentication interface, i.e. one 
//that decides if a login in allowed or not
#define PAM_SM_AUTH

// We do not supply these
/*
#define PAM_SM_ACCOUNT
#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
*/

// Include PAM headers 
#include <security/pam_appl.h>
#include <security/pam_modules.h>





char *ChallengeResponse(char *RetStr, pam_handle_t *pamh, const char *Challenge, const char *Prompt)
{
struct pam_conv *conv;
struct pam_message msg;
const struct pam_message *msgp;
struct pam_response *resp=NULL;
const char *pam_authtok=NULL;
char *Tempstr=NULL;

RetStr=CopyStr(RetStr,"");


Tempstr=CopyStr(Tempstr, "Challenge: ");
Tempstr=CatStr(Tempstr, Challenge);
Tempstr=CatStr(Tempstr, "\nResponse: ");

//if the above pam_get_item returned nothing, then we'll have to try doing the pam
//conversation 'by hand'.

#ifndef OPENPAM
if (pam_get_item(pamh, PAM_CONV, (const void **)&conv) != PAM_SUCCESS) return(RetStr);


msg.msg_style = PAM_PROMPT_ECHO_OFF;
msg.msg = Tempstr;
msgp = &msg;

if (conv)
{
	if ((*conv->conv)(1, &msgp, &resp, conv->appdata_ptr) == PAM_SUCCESS) RetStr=CopyStr(RetStr, resp->resp);
}

if (resp)
{
	Destroy(resp->resp);
	Destroy(resp);
}
#endif

Destroy(Tempstr);
return(RetStr);
}



void ParseCommandLine(int argc, const char **argv, char **Prompt, char **PassFile)
{
int i;
const char *ptr;

*Prompt=CopyStr(*Prompt, "Response: ");
*PassFile=CopyStr(*PassFile, "/etc/digestauth.auth");


for (i=0; i < argc; i++)
{
	ptr=argv[i];
	if (strncmp(ptr, "prompt=", 7)==0) *Prompt=CopyStr(*Prompt, ptr+7);
	if (strncmp(ptr, "credsfile=", 10)==0) *PassFile=CopyStr(*PassFile, ptr+10);
}
}


char *GenerateNonce(char *Nonce, const char *pam_user)
{
char *Tempstr=NULL, *Random=NULL;
FILE *f;
int ch, i;

srand(time(NULL));
Tempstr=(char *) calloc(256, 1);
f=fopen("/dev/random", "r");
if (! f) f=fopen("/dev/urandom", "r");
if (f)
{
	for (i=0; i < 32; i++)
	{
	ch=fgetc(f);
	snprintf(Tempstr, 255, "%x", ch);
	Random=CatStr(Random, Tempstr);
	}
	fclose(f);
}

//we add the time, pid and 'rand' to the Random bytes that we should have gotten from
//urandom, so that if there was no /dev/random or /dev/urandom we have *something*
//kinda random
snprintf(Tempstr, 255, "%s%ld%ld%ld%s", pam_user, (long) getpid(), (long) time(NULL), (long) rand(), Random);

Nonce=HashString(Nonce, Tempstr);
Nonce[30]='\0';

Destroy(Tempstr);
Destroy(Random);

return(Nonce);
}


// PAM entry point for authentication. This function gets called by pam when
//a login occurs. argc and argv work just like argc and argv for the 'main' 
//function of programs, except they pass in the options defined for this
//module in the pam configuration files in /etc/pam.conf or /etc/pam.d/
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	char *Tempstr=NULL, *User=NULL, *Prompt=NULL, *PassFile=NULL, *Nonce=NULL, *Value=NULL, *Hash=NULL;
	const char *ptr;
	int PamResult=PAM_IGNORE, val;
	FILE *f;

	//These are defined as 'const char' because they passwd to us from the parent
	//library. When we called pam_get_<whatever> the pam library passes pointers
	//to strings in it's own code. Thus we must not change or free them
	const char *pam_user = NULL, *pam_service=NULL, *pam_rhost=NULL;
	char *pam_authtok=NULL;


	if (pam_get_item(pamh, PAM_SERVICE, (const void **) &pam_service) != PAM_SUCCESS)
	{
		openlog("pam_digestauth",0,LOG_AUTH);
		syslog(LOG_ERR,"Failed to get pam_service");
		closelog();
		return(PAM_IGNORE);
	}

	openlog(pam_service,0,LOG_AUTH);

	//get the user. If something goes wrong we return PAM_IGNORE. This tells
	//pam that our module failed in some way, so ignore it. Perhaps we should
	//return PAM_PERM_DENIED to deny login, but this runs the risk of a broken
	//module preventing anyone from logging into the system!
	if ((pam_get_user(pamh, &pam_user, NULL) != PAM_SUCCESS) || (pam_user==NULL))
	{
		syslog(LOG_ERR,"pam_digestauth: Failed to get pam_user");
		closelog();
		return(PAM_IGNORE);
	}

	User=CopyStr(User,pam_user);
	ParseCommandLine(argc, argv, &Prompt, &PassFile);

	f=fopen(PassFile, "r");
	if (f)
	{
	Nonce=GenerateNonce(Nonce, pam_user);
	Tempstr=(char *) calloc(1025, 1);
	while (fgets(Tempstr, 1024, f) != NULL)
	{
		StripTrailingWhitespace(Tempstr);	
		ptr=GetTok(Tempstr, ':', &Value);
		if (strcmp(Value, User)==0)
		{
			ptr=GetTok(ptr, ':', &Value);

			pam_authtok=ChallengeResponse(pam_authtok, pamh, Nonce, Prompt);
			Tempstr=MCopyStr(Tempstr, Nonce, Value, NULL);
			Hash=HashString(Hash, Tempstr);
			if (strcmp(pam_authtok, Hash)==0) PamResult=PAM_SUCCESS;
		}
	}
	fclose(f);
	}

	closelog();

	Destroy(Hash);
	Destroy(Nonce);
	Destroy(Value);
	Destroy(Prompt);
	Destroy(Tempstr);
	Destroy(PassFile);
	Destroy(pam_authtok);

  return(PamResult);
}


//We do not provide any of the below functions, we could just leave them out
//but apparently it's considered good practice to supply them and return
//'PAM_IGNORE'

//PAM entry point for starting sessions. This is called after a user has 
//passed all authentication. It allows a PAM module to perform certain tasks
//on login, like recording the login occured, or printing a message of the day
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}


//PAM entry point for ending sessions. This is called when a user logs out
//It allows a PAM module to perform certain tasks on logout
//like recording the logout occured, or clearing up temporary files
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}

// PAM entry point for 'account management'. This decides whether a user
// who has already been authenticated by pam_sm_authenticate should be
// allowed to log in (it considers other things than the users password)
// Really this is what we should have used here
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}


//PAM entry point for setting 'credentials' or properties of the user
//If our module stores or produces extra information about a user (e.g.
//a kerberous ticket or geolocation value) then it will pass this information
//to a PAM aware program in this call
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) 
{
	return(PAM_IGNORE);
}

// PAM entry point for changing passwords. If our module stores passwords
// then this will be called whenever one needs changing
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	return(PAM_IGNORE);
}


//I couldn't find any documentation on this. I think it notifies PAM of our
//module name
#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_digestauth");
#endif
