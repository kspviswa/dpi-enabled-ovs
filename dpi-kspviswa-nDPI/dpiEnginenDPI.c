/*
 * dpiEnginenDPI.c
 *
 *  Created on: 04-May-2015
 *      Author: kspviswa
 */

#include "dpi_plugin.h"

#ifdef linux
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>

//#include "../config.h"

#ifdef HAVE_JSON_C
#include <json.h>
#endif

#include "ndpi_api.h"
#include <json-c/json.h>
#include <curl/curl.h>

#include <sys/socket.h>

const char *szProto = "/tmp/proto.txt";

/**
 * Detection parameters
 */
static u_int32_t detection_tick_resolution = 1000;
static time_t capture_for = 0;
static time_t capture_until = 0;

static u_int32_t full_http_dissection = 1; /* enabling http dissection by default */

#define IDLE_SCAN_PERIOD           10 /* msec (use detection_tick_resolution = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET         1024

#define NUM_ROOTS                 512

static u_int32_t num_flows;
static u_int32_t ndpi_flow_count;

struct ndpi_detection_module_struct *ndpi_struct;
void *ndpi_flows_root[NUM_ROOTS];

#define MAX_NDPI_FLOWS  200000000
#define MAX_JSON_ARRAY 50

static json_object *jArray_flows;

/**
 * @brief ID tracking
 */
typedef struct ndpi_id {
	u_int8_t ip[4];				//< Ip address
	struct ndpi_id_struct *ndpi_id;		//< nDpi worker structure
} ndpi_id_t;

static u_int32_t size_id_struct = 0;		//< ID tracking structure size

// flow tracking
typedef struct ndpi_flow {
	u_int32_t lower_ip;
	u_int32_t upper_ip;
	u_int16_t lower_port;
	u_int16_t upper_port;
	u_int8_t detection_completed, protocol;
	u_int16_t vlan_id;
	struct ndpi_flow_struct *ndpi_flow;
	char lower_name[32], upper_name[32];

	u_int64_t last_seen;

	u_int64_t bytes;
	u_int32_t packets;

	// result only, not used for flow identification
	u_int32_t detected_protocol;

	char host_server_name[256];

	struct {
		char client_certificate[48], server_certificate[48];
	} ssl;

	void *src_id, *dst_id;
} ndpi_flow_t;

static u_int32_t size_flow_struct = 0;

/* ***************************************************** */

static void *malloc_wrapper(unsigned long size) {
	return malloc(size);
}

/* ***************************************************** */

static void free_wrapper(void *freeable) {
	free(freeable);
}

/* ***************************************************** */

static char* ipProto2Name(u_short proto_id) {
	static char proto[8];

	switch(proto_id) {
	case IPPROTO_TCP:
		return("TCP");
		break;
	case IPPROTO_UDP:
		return("UDP");
		break;
	case IPPROTO_ICMP:
		return("ICMP");
		break;
	case 112:
		return("VRRP");
		break;
	case IPPROTO_IGMP:
		return("IGMP");
		break;
	}

	snprintf(proto, sizeof(proto), "%u", proto_id);
	return(proto);
}

/* ***************************************************** */

/* ***************************************************** */

static void free_ndpi_flow(struct ndpi_flow *flow) {
	if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
	if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
	if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
}

/* ***************************************************** */

static void ndpi_flow_freer(void *node) {
	struct ndpi_flow *flow = (struct ndpi_flow*)node;

	free_ndpi_flow(flow);
	ndpi_free(flow);
}

/* ***************************************************** */

/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
	struct ndpi_flow *fa = (struct ndpi_flow*)a;
	struct ndpi_flow *fb = (struct ndpi_flow*)b;

	if(fa->vlan_id   < fb->vlan_id  )   return(-1); else { if(fa->vlan_id   > fb->vlan_id  )   return(1); }
	if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
	if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
	if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
	if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
	if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

	return(0);
}

/* ***************************************************** */

int32 engine_init()
{
	NDPI_PROTOCOL_BITMASK all;
	ndpi_struct = ndpi_init_detection_module(detection_tick_resolution,
			malloc_wrapper, free_wrapper, NULL);

	ndpi_struct->http_dissect_response = 1;

	// enable all protocols
	NDPI_BITMASK_SET_ALL(all);
	ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

	// allocate memory for id and flow tracking
	size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
	size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

	ndpi_load_protocols_file(ndpi_struct, szProto);

	jArray_flows = json_object_new_array();

	return 0;
}

int32 engine_destroy()
{
	int i;

	for(i=0; i<NUM_ROOTS; i++) {
		ndpi_tdestroy(ndpi_flows_root[i], ndpi_flow_freer);
		ndpi_flows_root[i] = NULL;
	}

	ndpi_exit_detection_module(ndpi_struct, free_wrapper);

	return 0;
}
/* ***************************************************** */

/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {

	DpiWriteLog(DPIINFO,"Inside curl_callback");

	size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    DpiWriteLog(DPIINFO,"Payload is being set");

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
    	DpiWriteLog(DPIERR, "ERROR: Failed to expand buffer in curl_callback");
      /* free buffer */
      free(p->payload);
      /* return */
      return -1;
    }

    DpiWriteLog(DPIINFO, "Copied the contents");
    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    DpiWriteLog(DPIINFO, "Null termination ensured");
    /* ensure null termination */
    p->payload[p->size] = 0;

    DpiWriteLog(DPIINFO, "After the assignment");

    /* return size */
    return realsize;
}

/* fetch and return url body via curl */
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;                   /* curl result code */

    DpiWriteLog(DPIINFO,"Inside curl_fetch_url");

    /* init payload */
    fetch->payload = (char *) calloc(1, sizeof(fetch->payload));

    /* check payload */
    if (fetch->payload == NULL) {
        /* log error */
    	DpiWriteLog(DPIERR, "ERROR: Failed to allocate payload in curl_fetch_url");
        /* return error */
        return CURLE_FAILED_INIT;
    }

    /* init size */
    fetch->size = 0;

    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) fetch);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 5);

    /* enable location redirects */
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

    /* set maximum allowed redirects */
    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);

    DpiWriteLog(DPIINFO, "Before curl_easy_perform");
    /* fetch the url */
    rcode = curl_easy_perform(ch);

    /* return */
    return rcode;
}

static void sendCurl(json_object *jObjCurl)
{

	DpiWriteLog(DPIINFO, "Entering sendCurl");


  CURL *ch;                                               /* curl handle */
    CURLcode rcode;                                         /* curl result code */

    json_object *json;                                      /* json post body */
    enum json_tokener_error jerr = json_tokener_success;    /* json parse error */

    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */
    struct curl_slist *headers = NULL;                      /* http headers to send with request */

    /* url to test site */
    char *url = "http://localhost:3000/db";

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
    	DpiWriteLog(DPIERR, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return ;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

/* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(jObjCurl));

    DpiWriteLog(DPIINFO, "Before curl_fetch_url");
    /* fetch page and capture return code */
    rcode = curl_fetch_url(ch, url, cf);

    DpiWriteLog(DPIINFO, "After curl_fetch_url");

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    DpiWriteLog(DPIINFO, "After cleanup");

    /* free headers */
    curl_slist_free_all(headers);
}

/* ***************************************************** */

/* ***************************************************** */

static void printFlow(struct ndpi_flow *flow) {

	json_object *jObj;

	/*  if(!json_flag) {
#if 0

  DpiWriteLog(DPIINFO "\t%s [VLAN: %u] %s:%u <-> %s:%u\n",
	   ipProto2Name(flow->protocol), flow->vlan_id,
	   flow->lower_name, ntohs(flow->lower_port),
	   flow->upper_name, ntohs(flow->upper_port));

#else
	 */
	//    printf("\t%u", ++num_flows);

	DpiWriteLog(DPIINFO, "\t%s %s:%u <-> %s:%u ",
			ipProto2Name(flow->protocol),
			flow->lower_name, ntohs(flow->lower_port),
			flow->upper_name, ntohs(flow->upper_port));

	if(flow->vlan_id > 0) DpiWriteLog(DPIINFO, "[VLAN: %u]", flow->vlan_id);

	DpiWriteLog(DPIINFO, "[proto: %u/%s][%u pkts/%llu bytes]",
			flow->detected_protocol,
			ndpi_get_proto_name(ndpi_struct, flow->detected_protocol),
			flow->packets, (long long unsigned int)flow->bytes);

	if(flow->host_server_name[0] != '\0') DpiWriteLog(DPIINFO, "[Host: %s]", flow->host_server_name);
	if(flow->ssl.client_certificate[0] != '\0') DpiWriteLog(DPIINFO, "[SSL client: %s]", flow->ssl.client_certificate);
	if(flow->ssl.server_certificate[0] != '\0') DpiWriteLog(DPIINFO, "[SSL server: %s]", flow->ssl.server_certificate);

	//printf("\n");
	//#endif
	/*  } else {
#ifdef HAVE_JSON_C
*/

    jObj = json_object_new_object();

    json_object_object_add(jObj,"protocol",json_object_new_string(ipProto2Name(flow->protocol)));
    json_object_object_add(jObj,"host_a.name",json_object_new_string(flow->lower_name));
    json_object_object_add(jObj,"host_a.port",json_object_new_int(ntohs(flow->lower_port)));
    json_object_object_add(jObj,"host_b.name",json_object_new_string(flow->upper_name));
    json_object_object_add(jObj,"host_n.port",json_object_new_int(ntohs(flow->upper_port)));
    json_object_object_add(jObj,"detected.protocol",json_object_new_int(flow->detected_protocol));
    json_object_object_add(jObj,"detected.protocol.name",json_object_new_string(ndpi_get_proto_name(ndpi_struct, flow->detected_protocol)));
    json_object_object_add(jObj,"packets",json_object_new_int(flow->packets));
    json_object_object_add(jObj,"bytes",json_object_new_int(flow->bytes));

    if(flow->host_server_name[0] != '\0')
      json_object_object_add(jObj,"host.server.name",json_object_new_string(flow->host_server_name));

    if((flow->ssl.client_certificate[0] != '\0') || (flow->ssl.server_certificate[0] != '\0')) {
      json_object *sjObj = json_object_new_object();

      if(flow->ssl.client_certificate[0] != '\0')
	json_object_object_add(sjObj, "client", json_object_new_string(flow->ssl.client_certificate));

      if(flow->ssl.server_certificate[0] != '\0')
	json_object_object_add(sjObj, "server", json_object_new_string(flow->ssl.server_certificate));

      json_object_object_add(jObj, "ssl", sjObj);
    }

    json_object_array_add(jArray_flows,jObj);


    //flow->protos.ssl.client_certificate, flow->protos.ssl.server_certificate);
    //if(json_flag == 1)
    //  json_object_array_add(jArray_known_flows,jObj);
    //else if(json_flag == 2)
    //  json_object_array_add(jArray_unknown_flows,jObj);
//#endif

    if(json_object_array_length(jArray_flows) == MAX_JSON_ARRAY)
    {
    	sendCurl(jArray_flows);
    	DpiWriteLog(DPIINFO,"Sent Rest POST call via CURL");

    	//json_object_put(jArray_flows);
    	//DpiWriteLog(DPIINFO, "Deleted jArray_flows");

		jArray_flows = json_object_new_array();
    }

}

/* ***************************************************** */

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow(const u_int8_t version,
		u_int16_t vlan_id,
		const struct ndpi_iphdr *iph,
		u_int16_t ip_offset,
		u_int16_t ipsize,
		u_int16_t l4_packet_len,
		struct ndpi_id_struct **src,
		struct ndpi_id_struct **dst,
		u_int8_t *proto,
		const struct ndpi_ip6_hdr *iph6) {
	u_int32_t idx, l4_offset;
	struct ndpi_tcphdr *tcph = NULL;
	struct ndpi_udphdr *udph = NULL;
	u_int32_t lower_ip;
	u_int32_t upper_ip;
	u_int16_t lower_port;
	u_int16_t upper_port;
	struct ndpi_flow flow;
	void *ret;
	u_int8_t *l3;

	/*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
	 */
	if(version == 4) {
		if(ipsize < 20)
			return NULL;

		if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
				|| (iph->frag_off & htons(0x1FFF)) != 0)
			return NULL;

		l4_offset = iph->ihl * 4;
		l3 = (u_int8_t*)iph;
	} else {
		l4_offset = sizeof(struct ndpi_ip6_hdr);
		l3 = (u_int8_t*)iph6;
	}

	/* if(l4_packet_len < 64)
    ndpi_thread_info[thread_id].stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    ndpi_thread_info[thread_id].stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    ndpi_thread_info[thread_id].stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    ndpi_thread_info[thread_id].stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    ndpi_thread_info[thread_id].stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    ndpi_thread_info[thread_id].stats.packet_len[5]++;

  if(l4_packet_len > ndpi_thread_info[thread_id].stats.max_packet_len)
    ndpi_thread_info[thread_id].stats.max_packet_len = l4_packet_len;
	 */

	if(iph->saddr < iph->daddr) {
		lower_ip = iph->saddr;
		upper_ip = iph->daddr;
	} else {
		lower_ip = iph->daddr;
		upper_ip = iph->saddr;
	}

	*proto = iph->protocol;

	if(iph->protocol == 6 && l4_packet_len >= 20) {
		// ndpi_thread_info[thread_id].stats.tcp_count++;

		// tcp
		tcph = (struct ndpi_tcphdr *) ((u_int8_t *) l3 + l4_offset);
		if(iph->saddr < iph->daddr) {
			lower_port = tcph->source;
			upper_port = tcph->dest;
		} else {
			lower_port = tcph->dest;
			upper_port = tcph->source;

			if(iph->saddr == iph->daddr) {
				if(lower_port > upper_port) {
					u_int16_t p = lower_port;

					lower_port = upper_port;
					upper_port = p;
				}
			}
		}
	} else if(iph->protocol == 17 && l4_packet_len >= 8) {
		// udp
		//ndpi_thread_info[thread_id].stats.udp_count++;

		udph = (struct ndpi_udphdr *) ((u_int8_t *) l3 + l4_offset);
		if(iph->saddr < iph->daddr) {
			lower_port = udph->source;
			upper_port = udph->dest;
		} else {
			lower_port = udph->dest;
			upper_port = udph->source;
		}
	} else {
		// non tcp/udp protocols
		lower_port = 0;
		upper_port = 0;
	}

	flow.protocol = iph->protocol, flow.vlan_id = vlan_id;
	flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
	flow.lower_port = lower_port, flow.upper_port = upper_port;

	//if(0)
	DpiWriteLog(DPIINFO, "[NDPI] [%u][%u:%u <-> %u:%u]\n",
			iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

	idx = (vlan_id + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
	ret = ndpi_tfind(&flow, &ndpi_flows_root[idx], node_cmp);

	if(ret == NULL) {
		if(ndpi_flow_count == MAX_NDPI_FLOWS) {
			DpiWriteLog(DPIINFO, "ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);

		} else {
			struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

			if(newflow == NULL) {
				DpiWriteLog(DPIINFO,"[NDPI] %s(1): not enough memory\n", __FUNCTION__);
				return(NULL);
			}

			memset(newflow, 0, sizeof(struct ndpi_flow));
			newflow->protocol = iph->protocol, newflow->vlan_id = vlan_id;
			newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
			newflow->lower_port = lower_port, newflow->upper_port = upper_port;

			if(version == 4) {
				inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
				inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
			} else {
				inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
				inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
			}

			if((newflow->ndpi_flow = malloc_wrapper(size_flow_struct)) == NULL) {
				DpiWriteLog(DPIINFO,"[NDPI] %s(2): not enough memory\n", __FUNCTION__);
				return(NULL);
			} else
				memset(newflow->ndpi_flow, 0, size_flow_struct);

			if((newflow->src_id = malloc_wrapper(size_id_struct)) == NULL) {
				DpiWriteLog(DPIINFO,"[NDPI] %s(3): not enough memory\n", __FUNCTION__);
				return(NULL);
			} else
				memset(newflow->src_id, 0, size_id_struct);

			if((newflow->dst_id = malloc_wrapper(size_id_struct)) == NULL) {
				DpiWriteLog(DPIINFO,"[NDPI] %s(4): not enough memory\n", __FUNCTION__);
				return(NULL);
			} else
				memset(newflow->dst_id, 0, size_id_struct);

			ndpi_tsearch(newflow, &ndpi_flows_root[idx], node_cmp); /* Add */
			ndpi_flow_count++;

			*src = newflow->src_id, *dst = newflow->dst_id;

			printFlow(newflow);

			return(newflow);
		}
	} else {
		struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

		if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
				&& flow->lower_port == lower_port && flow->upper_port == upper_port)
			*src = flow->src_id, *dst = flow->dst_id;
		else
			*src = flow->dst_id, *dst = flow->src_id;

		return flow;
	}
}

/* ***************************************************** */

/* ***************************************************** */

// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(const u_int64_t time,
		u_int16_t vlan_id,
		const struct ndpi_iphdr *iph,
		u_int16_t ip_offset,
		u_int16_t ipsize, u_int16_t rawsize) {
	struct ndpi_id_struct *src, *dst;
	struct ndpi_flow *flow;
	struct ndpi_flow_struct *ndpi_flow = NULL;
	u_int32_t protocol = 0;
	u_int8_t proto;

	if(iph)
	{
		flow = get_ndpi_flow(4, vlan_id, iph, ip_offset, ipsize, ntohs(iph->tot_len) - (iph->ihl * 4), &src, &dst, &proto, NULL);
	}
	// else
	//   flow = get_ndpi_flow6(thread_id, vlan_id, iph6, ip_offset, &src, &dst, &proto);

	if(flow != NULL) {
		// ndpi_thread_info[thread_id].stats.ip_packet_count++;
		// ndpi_thread_info[thread_id].stats.total_wire_bytes += rawsize + 24 /* CRC etc */, ndpi_thread_info[thread_id].stats.total_ip_bytes += rawsize;
		ndpi_flow = flow->ndpi_flow;
		flow->packets++, flow->bytes += rawsize;
		flow->last_seen = time;
	} else {
		return(0);
	}

	if(flow->detection_completed) return(0);

	protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_struct, ndpi_flow, (uint8_t *)iph, ipsize, time, src, dst);

	flow->detected_protocol = protocol;

	if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
			|| ((proto == IPPROTO_UDP) && (flow->packets > 8))
			|| ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
		flow->detection_completed = 1;

		snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

		if((proto == IPPROTO_TCP) && (flow->detected_protocol != NDPI_PROTOCOL_DNS)) {
			snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
			snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
		}

		if((
				(flow->detected_protocol == NDPI_PROTOCOL_HTTP)
				|| (flow->detected_protocol == NDPI_SERVICE_FACEBOOK)
		)
				&& full_http_dissection) {
			char *method;

			DpiWriteLog(DPIINFO, "[URL] %s\n", ndpi_get_http_url(ndpi_struct, ndpi_flow));
			DpiWriteLog(DPIINFO, "[Content-Type] %s\n", ndpi_get_http_content_type(ndpi_struct, ndpi_flow));

			switch(ndpi_get_http_method(ndpi_struct, ndpi_flow)) {
			case HTTP_METHOD_OPTIONS: method = "HTTP_METHOD_OPTIONS"; break;
			case HTTP_METHOD_GET: method = "HTTP_METHOD_GET"; break;
			case HTTP_METHOD_HEAD: method = "HTTP_METHOD_HEAD"; break;
			case HTTP_METHOD_POST: method = "HTTP_METHOD_POST"; break;
			case HTTP_METHOD_PUT: method = "HTTP_METHOD_PUT"; break;
			case HTTP_METHOD_DELETE: method = "HTTP_METHOD_DELETE"; break;
			case HTTP_METHOD_TRACE: method = "HTTP_METHOD_TRACE"; break;
			case HTTP_METHOD_CONNECT: method = "HTTP_METHOD_CONNECT"; break;
			default: method = "HTTP_METHOD_UNKNOWN"; break;
			}

			DpiWriteLog(DPIINFO, "[Method] %s\n", method);
		}

		free_ndpi_flow(flow);

		/*if(verbose > 1) {
      if(enable_protocol_guess) {
	if(flow->detected_protocol == 0  UNKNOWN ) {
	  protocol = node_guess_undetected_protocol(thread_id, flow);
	}
      }*/

		printFlow(flow);



#if 0
		if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
			printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif

		//  if(live_capture) {
		//    if(ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].last_time) {
		//      /* scan for idle flows */
		//      ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);
		//
		//      /* remove idle flows (unfortunately we cannot do this inline) */
		//      while (ndpi_thread_info[thread_id].num_idle_flows > 0)
		//	ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows],
		//		     &ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_cmp);
		//
		//      if(++ndpi_thread_info[thread_id].idle_scan_idx == NUM_ROOTS) ndpi_thread_info[thread_id].idle_scan_idx = 0;
		//      ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].last_time;
		//    }
		//  }
	}
		return 0;
	}


	/* ****************************************************** */

	int32 engine_process(void *packet, uint32 nSize)
	{
		const struct ndpi_ethhdr *ethernet;
		struct ndpi_iphdr *iph;
		//struct ndpi_ip6_hdr *iph6;
		u_int64_t time;
		u_int16_t type, ip_offset, ip_len;
		u_int16_t frag_off = 0, vlan_id = 0;
		u_int8_t proto = 0, vlan_packet = 0;
		struct timeval ts;
		gettimeofday (&ts, NULL);

		time = ((uint64_t) ts.tv_sec) * detection_tick_resolution +
				ts.tv_usec / (1000000 / detection_tick_resolution);

		ethernet = (struct ndpi_ethhdr *) packet;
		ip_offset = sizeof(struct ndpi_ethhdr);
		type = ntohs(ethernet->h_proto);

		//if(type == 0x8100 /* VLAN */) {
		//	vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
		//	type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
		//	ip_offset += 4;
		//	vlan_packet = 1;
		//}

		iph = (struct ndpi_iphdr *) &packet[ip_offset];


		// process the packet
		packet_processing(time, vlan_id, iph, ip_offset, (nSize - ip_offset), nSize);

		return 1;
}

