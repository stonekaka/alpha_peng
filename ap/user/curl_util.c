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

		/* tell it to "upload" to the URL */
		curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

		/* set where to read from (on Windows you need to use READFUNCTION too) */
		curl_easy_setopt(curl, CURLOPT_READDATA, fp);

		/* and give the size of the upload (optional) */
		curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
						 (curl_off_t)file_info.st_size);

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
		/* always cleanup */
		curl_easy_cleanup(curl);
	}
	fclose(fp);
	return 0;
}

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

#if 0
int main(void)
{
	upload_file("/var/log/dm.log", "");

	return 0;
}
#endif

