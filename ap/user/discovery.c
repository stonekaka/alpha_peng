/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:     curlt.c
* Author:        renleilei - renleilei@hiveview.com
* Description:   
* Others: 
* Last modified: 2015-11-02 10:16
***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
const char data[]="{\"method\":\"config\",\"params\":{\"data\":{\"idcode\":\"6A446YXI68\",\"passwd\":\"6A446YXI68\",\"pppoeid\":\"6A446YXI68\",\"ip\":\"192.168.3.168\"},\"serviceType\":2}}";
 
struct WriteThis {
  const char *readptr;
  long sizeleft;
};
 
struct recv_string {
  char *ptr;
  size_t len;
};

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp)
{
  struct WriteThis *pooh = (struct WriteThis *)userp;
 
  if(size*nmemb < 1)
    return 0;
 
  if(pooh->sizeleft) {
    *(char *)ptr = pooh->readptr[0]; /* copy one single byte */ 
    pooh->readptr++;                 /* advance pointer */ 
    pooh->sizeleft--;                /* less data left */ 
    return 1;                        /* we return 1 byte at a time! */ 
  }
 
  return 0;                          /* no more data left to deliver */ 
}

int init_string(struct recv_string *s) 
{
	if(!s){
		printf("%s: arg error.\n", __FUNCTION__);
		return -1;	
	}
	
  s->len = 0;
  s->ptr = malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    return -1;
  }
  s->ptr[0] = '\0';
  
  return 0;
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct recv_string *s)
{
  size_t new_len = s->len + size*nmemb;
  s->ptr = realloc(s->ptr, new_len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
    return -1;
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;

  return size*nmemb;
}

int lbps_discovery(void *arg)
{
  CURL *curl;
  CURLcode res;
  struct recv_string s;
 
  struct WriteThis pooh;
 
  pooh.readptr = data;
  pooh.sizeleft = (long)strlen(data);
 
  /* In windows, this will init the winsock stuff */ 
  res = curl_global_init(CURL_GLOBAL_DEFAULT);
  /* Check for errors */ 
  if(res != CURLE_OK) {
    fprintf(stderr, "curl_global_init() failed: %s\n",
            curl_easy_strerror(res));
    return 1;
  }
  
  if(init_string(&s) != 0){
  	
  	return -1;
  }
    
  /* get a curl handle */ 
  curl = curl_easy_init();
  if(curl) {
    /* First set the URL that is about to receive our POST. */ 
    curl_easy_setopt(curl, CURLOPT_URL, "https://lbps.ezlink-wifi.com");
 
    /* Now specify we want to POST data */ 
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
 
    /* we want to use our own read function */ 
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
 
    /* pointer to pass to our read function */ 
    curl_easy_setopt(curl, CURLOPT_READDATA, &pooh);
 
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
 		
    /* get verbose debug output please */ 
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
 
    /*
      If you use POST to a HTTP 1.1 server, you can send data without knowing
      the size before starting the POST if you use chunked encoding. You
      enable this by adding a header like "Transfer-Encoding: chunked" with
      CURLOPT_HTTPHEADER. With HTTP 1.0 or without chunked transfer, you must
      specify the size in the request.
    */ 
#ifdef USE_CHUNKED
    {
      struct curl_slist *chunk = NULL;
 
      chunk = curl_slist_append(chunk, "Transfer-Encoding: chunked");
      res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
      /* use curl_slist_free_all() after the *perform() call to free this
         list again */ 
    }
#else
    /* Set the expected POST size. If you want to POST large amounts of data,
       consider CURLOPT_POSTFIELDSIZE_LARGE */ 
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, pooh.sizeleft);
#endif
 
#ifdef DISABLE_EXPECT
    /*
      Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue"
      header.  You can disable this header with CURLOPT_HTTPHEADER as usual.
      NOTE: if you want chunked transfer too, you need to combine these two
      since you can only set one list of headers with CURLOPT_HTTPHEADER. */ 
 
    /* A less good option would be to enforce HTTP 1.0, but that might also
       have other implications. */ 
    {
      struct curl_slist *chunk = NULL;
 
      chunk = curl_slist_append(chunk, "Expect:");
      res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
      /* use curl_slist_free_all() after the *perform() call to free this
         list again */ 
    }
#endif
 
    /* Perform the request, res will get the return code */ 
    printf("%d: start send to lbps...\n", __LINE__);
    res = curl_easy_perform(curl);
    /* Check for errors */ 
    if(res != CURLE_OK) {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }
              
    printf("%d: get resp: %s.\n", __LINE__, s.ptr);
 
    if(s.ptr)free(s.ptr);
    
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  return 0;
}
