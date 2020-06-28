/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: GPL-3.0
*/

//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c

#include "utility.h"
#include "sha2.h"




#ifndef va_copy
#define va_copy(dest, src) (dest) = (src) 
#endif

char *VCatStr(char *Dest, const char *Str1,  va_list args)
{
//initialize these to keep valgrind happy
size_t len=0;
char *ptr=NULL;
const char *sptr=NULL;


if (Dest !=NULL)
{
len=StrLen(Dest);
ptr=Dest;
}
else
{
 len=10;
 ptr=(char *) calloc(10,1);
}

if (! Str1) return(ptr);
for (sptr=Str1; sptr !=NULL; sptr=va_arg(args,const char *))
{
len+=StrLen(sptr)+1;
len=len*2;


ptr=(char *) realloc(ptr,len);
if (ptr && sptr) strcat(ptr,sptr);
}

return(ptr);
}


char *MCatStr(char *Dest, const char *Str1,  ...)
{
char *ptr=NULL;
va_list args;

va_start(args,Str1);
ptr=VCatStr(Dest,Str1,args);
va_end(args);

return(ptr);
}


char *MCopyStr(char *Dest, const char *Str1,  ...)
{
char *ptr=NULL;
va_list args;

ptr=Dest;
if (ptr) *ptr='\0';
va_start(args,Str1);
ptr=VCatStr(ptr,Str1,args);
va_end(args);

return(ptr);
}

char *CatStr(char *Dest, const char *Src)
{
return(MCatStr(Dest,Src,NULL));
}


char *CopyStr(char *Dest, const char *Src)
{
return(MCopyStr(Dest,Src,NULL));
}

void StripTrailingWhitespace(char *str)
{
size_t len;
char *ptr;

len=StrLen(str);
if (len==0) return;
for(ptr=str+len-1; (ptr >= str) && isspace(*ptr); ptr--) *ptr='\0';
}


void StripLeadingWhitespace(char *str)
{
char *ptr, *start=NULL;

if (! str) return;
for(ptr=str; *ptr !='\0'; ptr++)
{
  if ((! start) && (! isspace(*ptr))) start=ptr;
}

if (!start) start=ptr;
 memmove(str,start,ptr+1-start);
}



void StripQuotes(char *Str)
{
int len;
char *ptr, StartQuote='\0';

ptr=Str;
while (isspace(*ptr)) ptr++;

if ((*ptr=='"') || (*ptr=='\''))
{
  StartQuote=*ptr;
  len=StrLen(ptr);
  if ((len > 0) && (StartQuote != '\0') && (ptr[len-1]==StartQuote))
  {
    if (ptr[len-1]==StartQuote) ptr[len-1]='\0';
    memmove(Str,ptr+1,len);
  }
}

}



//I don't trust strtok, it's not reentrant, and this handles quotes
const char *GetTok(const char *In, char Delim, char **Token)
{
char quot='\0';
const char *ptr;
int i=0;

*Token=realloc(*Token,258);
//When input is exhausted return null
if ((! In) || (*In=='\0')) return(NULL);

for (ptr=In; *ptr != '\0'; ptr++)
{
	if (*ptr=='\0') break;

	if (quot != '\0') 
	{
		if (*ptr==quot) quot='\0';
	}
	else if ((*ptr=='"') || (*ptr=='\'')) quot=*ptr;
	else if (*ptr==Delim) break;
	else 
	{
		if (*ptr=='\\') ptr++;
		(*Token)[i]=*ptr;
		i++;
	}
	if (i > 256) break;
}

(*Token)[i]='\0';
StripQuotes(*Token);

//if it's not '\0', then it must be a delim, so go past it
if (*ptr !='\0') ptr++;

//Don't return null if ptr=='\0' here, because there's probably
//still something in Token
return(ptr);
}



char *HashString(char *RetStr, const char *String)
{
SHA2_SHA256_CTX ctx;
char *Tempstr=NULL;
char Hex[5];
int i;

SHA2_SHA256_Init(&ctx);
SHA2_SHA256_Update(&ctx, String, StrLen(String));

Tempstr=(char *) realloc(Tempstr, SHA2_SHA256_DIGEST_LENGTH + 1);
SHA2_SHA256_Final(Tempstr, &ctx);

for (i=0; i < SHA2_SHA256_DIGEST_LENGTH; i++) 
{
	snprintf(Hex,3,"%02x",Tempstr[i] & 0xFF);
	RetStr=CatStr(RetStr,Hex);
}

Destroy(Tempstr);

return(RetStr);
}




void Destroy(void *Item)
{
if (Item) free(Item);
}
