/*
Copyright (c) 2015 Colum Paget <colums.projects@googlemail.com>
* SPDX-License-Identifier: GPL-3.0
*/

//utility functions, mostly string handling
//if you are looking for PAM module example code, then look in pam_module.c


#ifndef PAM_DIGESTAUTH_UTIL_H
#define PAM_DIGESTAUTH_UTIL_H

#include "common.h"

#define StrLen(str) ( str ? strlen(str) : 0 )

char *VCatStr(char *Dest, const char *Str1,  va_list args);
char *MCatStr(char *Dest, const char *Str1,  ...);
char *MCopyStr(char *Dest, const char *Str1,  ...);
char *CatStr(char *Dest, const char *Src);
char *CopyStr(char *Dest, const char *Src);
char *HashString(char *Dest, const char *String);
void StripTrailingWhitespace(char *str);
void StripLeadingWhitespace(char *str);
void StripQuotes(char *Str);
const char *GetTok(const char *In, char Delim, char **Token);
void Destroy(void *Item);

#endif
