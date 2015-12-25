/***************************************************************************
* Copyright (C), 2013-2018, Beijing Hiveview Technology Co.,Ltd
* File name:	 curl_util.c
* Author:		 renleilei - renleilei@hiveview.com
* Description:	 
* Others: 
* Last modified: 2015-12-21 12:16
***************************************************************************/

#include <stdio.h>
#include <curl/curl.h>
#include <sys/stat.h>
#include <fcntl.h>

extern char g_ap_label_mac[];
extern char g_ap_label_mac_nocol[];
#if 0
/* <DESC>
 * Upload to a file:// URL
 * </DESC>
 */
int upload_file(const char *filename, const char *dst_url)
{
	CURL *curl;
	CURLcode res;
	struct stat file_info;
	double speed_upload, total_time;
	FILE *fp;
	char postarg[64] = {0};
	
	if(!filename || !dst_url){
		printf("%s:arg error\n", __FUNCTION__);
		return -1;
	}

	snprintf(postarg, sizeof(postarg) - 1, "apmac=%s", g_ap_label_mac);

	fp = fopen(filename, "rb"); /* open file to upload */
	if(!fp) {

		return 1; /* can't continue */
	}

	/* to get the file size */
	if(fstat(fileno(fp), &file_info) != 0) {

		return 1; /* can't continue */
	}

	curl = curl_easy_init();
	if(curl) {
		/* upload to this place */
		curl_easy_setopt(curl, CURLOPT_URL, dst_url);

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postarg);
//#define PUT  1
#define POST 1
#if PUT
		/* tell it to "upload" to the URL */
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

		/* set where to read from (on Windows you need to use READFUNCTION too) */
		curl_easy_setopt(curl, CURLOPT_READDATA, fp);

		/* and give the size of the upload (optional) */
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
						 (curl_off_t)file_info.st_size);
#elif POST
		struct curl_httppost *post = NULL;
		struct curl_httppost *last = NULL;
		curl_formadd(&post, &last,
				CURLFORM_COPYNAME, "mylogfile",
				CURLFORM_FILECONTENT, filename,
				CURLFORM_END
		);
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, post);
#endif
		/* enable verbose for easier tracing */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

		res = curl_easy_perform(curl);
		/* Check for errors */
		if(res != CURLE_OK) {
		  fprintf(stderr, "curl_easy_perform() failed: %s\n",
				  curl_easy_strerror(res));
		}
		else {
			/* now extract transfer info */
			curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &speed_upload);
			curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &total_time);

			fprintf(stderr, "Speed: %.3f bytes/sec during %.3f seconds\n",
				  speed_upload, total_time);

		}
#if POST
		curl_formfree(post);
#endif		
		/* always cleanup */
		curl_easy_cleanup(curl);
	}
	fclose(fp);
	return 0;
}
#endif

int download_file(const char *url, const char *filename)
{
	int ret = 0;
	CURL *curl;
	FILE *fp;
	
	if(!filename || !url){
		printf("%s:arg error\n", __FUNCTION__);
		return -1;
	}

	curl = curl_easy_init();
	if(curl) {
		/* upload to this place */
		curl_easy_setopt(curl, CURLOPT_URL, url);

		fp = fopen(filename, "w+");
		if(!fp){
			goto out;
		}

		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

		ret = curl_easy_perform(curl);
		/* Check for errors */
		if(ret != CURLE_OK) {
		  fprintf(stderr, "curl_easy_perform() failed: %s\n",
				  curl_easy_strerror(ret));
		}

		fclose(fp);
out:
		/* always cleanup */
		curl_easy_cleanup(curl);
	}

	return 0;
}

int upload_file(const char *filename, const char *dst_url, char *rname)  
{  
	CURL *curl;  
	CURLcode res;  
		  
	struct curl_httppost *formpost=NULL;  
	struct curl_httppost *lastptr=NULL;  
	struct curl_slist *headerlist=NULL;  
	static const char buf[] = "Expect:";  
				  
	if(!filename || !dst_url || !rname){
		printf("%s:arg error\n", __FUNCTION__);
		return -1;
	}

	curl_global_init(CURL_GLOBAL_ALL);  
				    
	curl_formadd(&formpost,  
				&lastptr,  
				CURLFORM_COPYNAME, "apmac",  
				CURLFORM_COPYCONTENTS, g_ap_label_mac_nocol,  
				CURLFORM_END);  
					    
	/* Fill in the file upload field */  
	curl_formadd(&formpost,  
				&lastptr,  
				CURLFORM_COPYNAME, "sendfile",  
				CURLFORM_FILE, filename,  
				CURLFORM_END);  
					  
	/* Fill in the filename field */  
	curl_formadd(&formpost,  
				&lastptr,  
				CURLFORM_COPYNAME, "filename",  
				CURLFORM_COPYCONTENTS, rname,  
				CURLFORM_END);  
					    
	/* Fill in the submit field too, even if this is rarely needed */  
	curl_formadd(&formpost,  
				&lastptr,  
				CURLFORM_COPYNAME, "submit",  
				CURLFORM_COPYCONTENTS, "Submit",  
				CURLFORM_END);  
						  
	curl = curl_easy_init();  
	/* initalize custom header list (stating that Expect: 100-continue is not 
	 *      wanted */  
	headerlist = curl_slist_append(headerlist, buf);  
	if(curl) {  
		/* what URL that receives this POST */  

		curl_easy_setopt(curl, CURLOPT_URL, dst_url);  
		//if ( (argc == 2) && (!strcmp(argv[1], "noexpectheader")) ){
			/* only disable 100-continue header if explicitly requested */  
		//	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);  
		//}
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);  
											     
		/* enable verbose for easier tracing */
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

		/* Perform the request, res will get the return code */  
		res = curl_easy_perform(curl);  
		/* Check for errors */  
		if(res != CURLE_OK)  
			fprintf(stderr, "curl_easy_perform() failed: %s\n",  
					curl_easy_strerror(res));  
													     
		/* always cleanup */  
		curl_easy_cleanup(curl);  
													     
		/* then cleanup the formpost chain */  
		curl_formfree(formpost);  
		/* free slist */  
		curl_slist_free_all (headerlist);  
	}  
	return 0;  
}  

#if 0
int main(void)
{
	upload_file("/var/log/dm.log", "");

	return 0;
}
#endif

