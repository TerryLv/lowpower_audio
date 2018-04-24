/*
 * audiovf.c
 * This file is part of audiovf
 *
 * Copyright (C) 2016 - Sanchayan Maity
 *
 * audiovf is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * audiovf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with audiovf. If not, see <http://www.gnu.org/licenses/>.
 */

#include <gstreamer-1.0/gst/gst.h>
#include <gstreamer-1.0/gst/gstelement.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <rpmsg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <rmtcore_shm.h>


#define POWER_STATE_DEV				"/sys/power/state"
#define TMP_FILE_LOCATION			"./audio_play.tmp"
#define GST_USE_BUS_MONITOR

#define RPMSG_CTRL_DEV 				"/dev/rpmsg_ctrl0"
#define RPMSG_EP_DEV 				"/dev/rpmsg0"
#define RMTCORE_SHM_DEV 			"/dev/rmtcore_shm"
#define RPMSG_DEV_NAME 				"audio_ept"
#define RPMSG_SRC_ADDR   								0x400U
#define RPMSG_DST_ADDR   								0x1EU

#define NUMBER_OF_BYTES_FOR_FILE_LOCATION				256

#define SRTM_AUDIO_CATEGORY                             (0x3U)
#define SRTM_AUDIO_VERSION                              (0x0100U)

#define SRTM_MESSAGE_TYPE_REQUEST 						(0x0U)
#define SRTM_MESSAGE_TYPE_RESPONSE 						(0x1U)
#define SRTM_MESSAGE_TYPE_NOTIFICATION 					(0x2U)

/* Audio Service Request Command definition */
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_OPEN             (0x0U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_START            (0x1U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_PAUSE            (0x2U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_RESTART          (0x3U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_TERMINATE        (0x4U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_CLOSE            (0x5U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_SET_PARAMETER    (0x6U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_SET_BUFFER       (0x7U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_SUSPEND          (0x8U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_RESUME           (0x9U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_OPEN             (0xAU)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_START            (0xBU)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_PAUSE            (0xCU)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_RESTART          (0xDU)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_TERMINATE        (0xEU)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_CLOSE            (0xFU)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_SET_PARAMETER    (0x10U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_SET_BUFFER       (0x11U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_SUSPEND          (0x12U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_RESUME           (0x13U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RESET               (0x14U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_TX_PERIOD_DONE      (0x15U)
#define SRTM_AUDIO_SERV_REQUEST_CMD_RX_PERIOD_DONE      (0x16U)

/* Audio Service Sample Format definition */
#define SRTM_AUDIO_SERV_SAMPLE_FORMAT_S16_LE            (0x0U)
#define SRTM_AUDIO_SERV_SAMPLE_FORMAT_S24_LE            (0x1U)

/* Audio Service Channel identifier definition */
#define SRTM_AUDIO_SERV_CHANNEL_LEFT                    (0x0U)
#define SRTM_AUDIO_SERV_CHANNEL_RIGHT                   (0x1U)
#define SRTM_AUDIO_SERV_CHANNEL_STEREO                  (0x2U)

#ifndef GST_USE_BUS_MONITOR
volatile gboolean exit_flag = FALSE;
#endif

static __s32 rpmsg_ctrl_fd = 0, rpmsg_ep_fd = 0, rmtcore_shm_fd = 0;

typedef struct _srtm_packet_head
{
	union {
		struct {
			__u8 category;
			__u8 majorVersion;
			__u8 minorVersion;
			__u8 type;
			__u8 command;
			__u8 priority;
			__u8 reserved[4U];
		};
		__u8 header[10U];
	};
} __attribute__((packed)) srtm_packet_head_t;

typedef struct _audio_request
{
	union {
		struct {
			__u8 index;
			__u8 sampleFormat;
			__u8 channels;
			__u32 sampleRate;
			__u32 bufferAddress;
			__u32 bufferSize;
			__u32 periodSize;
			__u32 periodOffset;
		} __attribute__((packed));
		__u8 data[23U];
	};
} __attribute__((packed)) audio_request_t;

typedef struct _audio_rpmsg_request {
	srtm_packet_head_t header;
	audio_request_t param;
} __attribute__((packed)) audio_rpmsg_request_t;

typedef struct _audio_response
{
	__u8 result[2];
} __attribute__((packed)) audio_response_t;

typedef struct _audio_rpmsg_response
{
	srtm_packet_head_t header;
	audio_response_t param;
} __attribute__((packed)) audio_rpmsg_response_t;

typedef struct _audio_notification
{
	__u8 notifi_data;
} __attribute__((packed)) audio_notification_t;

typedef struct _audio_rpmsg_notification
{
	srtm_packet_head_t header;
	audio_notification_t param;
} __attribute__((packed)) audio_rpmsg_notification_t;


typedef struct  
{
	GstElement *file_source;
	GstElement *pipeline;
	GstElement *mpeg_audio_parse;	
	GstElement *beep_dec;
	GstElement *file_sink;
	GstElement *bin_playback;
	GstBus *bus;
	GstMessage *message;		
	gchar file_src_loc[NUMBER_OF_BYTES_FOR_FILE_LOCATION];
	gchar file_dest_loc[NUMBER_OF_BYTES_FOR_FILE_LOCATION];
}gstData;

gstData gstreamerData;

/* Create the pipeline element */
static gboolean gst_create_pipeline(gstData *data)
{		
	data->pipeline = gst_pipeline_new("audio_pipeline");	

	if (data->pipeline == NULL)			
		return FALSE;

	gst_element_set_state (data->pipeline, GST_STATE_NULL);

	return TRUE;
}

/* Callback function for dynamically linking the "wavparse" element and "alsasink" element */
static void gst_on_pad_added (GstElement *src_element, GstPad *src_pad, gpointer data)
{
    g_print("\nLinking dynamic pad between wavparse and alsasink\n");

    GstElement *sink_element = (GstElement *) data; 	/* Is alsasink */
    GstPad *sink_pad = gst_element_get_static_pad (sink_element, "sink");
    gst_pad_link (src_pad, sink_pad);

    gst_object_unref (sink_pad);
    src_element = NULL; 	/* Prevent "unused" warning here */
}

/* Setup the pipeline */
static gboolean gst_init_audio_playback_pipeline(gstData *data)
{
	if (data == NULL)
		return FALSE;
		
	data->file_source = gst_element_factory_make("filesrc", "file_source");	
	if (!data->file_source)
		g_print("\nfilesrc element created failed!");
	
	if (strstr(data->file_src_loc, ".mp3")) {
		g_print("\nMP3 Audio decoder selected\n");
		data->mpeg_audio_parse = gst_element_factory_make("mpegaudioparse", "audioparse");
		if (!data->mpeg_audio_parse)
			g_print("\nmpegaudioparse element created failed!");
	} else {
		g_print("\nNot a .mp3 file?\n");
		return FALSE;
	}

	data->beep_dec = gst_element_factory_make("beepdec", "audio_decoder");
	if (!data->beep_dec)
		g_print("\nbeepdec element created failed!");
	
	data->file_sink = gst_element_factory_make("filesink", "file_sink");
	if (!data->file_sink)
		g_print("\nfilesink element created failed!");

	if (!data->file_source || !data->mpeg_audio_parse || !data->beep_dec || !data->file_sink)	{
		g_printerr ("\nNot all elements for audio pipeline were created\n");
		return FALSE;
	}	

#ifdef DEBUG
	g_signal_connect( data->pipeline, "deep-notify", G_CALLBACK( gst_object_default_deep_notify ), NULL );	
#endif

	g_print("\nFile location: %s\n", data->file_src_loc);
	g_object_set (G_OBJECT (data->file_source), "location", data->file_src_loc, NULL);			

	g_print("\nTmp File location: ./audio.tmp\n");
	g_object_set (G_OBJECT (data->file_sink), "location", data->file_dest_loc, NULL);			

	data->bin_playback = gst_bin_new ("bin_playback");	
	
	if (strstr(data->file_src_loc, ".mp3")) {
		gst_bin_add_many(GST_BIN(data->bin_playback), data->file_source, data->mpeg_audio_parse, data->beep_dec, data->file_sink, NULL);
	
		if (gst_element_link_many (data->file_source, data->mpeg_audio_parse, NULL) != TRUE) {
			g_printerr("\nFile source and mpeg audio parse element could not link\n");
			return FALSE;
		}
	
		if (gst_element_link_many (data->mpeg_audio_parse, data->beep_dec, NULL) != TRUE) {
			g_printerr("\nmpeg audio decoder and beep decoder element could not link\n");
			return FALSE;
		}
	
		if (gst_element_link_many (data->beep_dec, data->file_sink, NULL) != TRUE) {
			g_printerr("\nbeep decoder and file sink element could not link\n");
			return FALSE;
		}
	}

	return TRUE;
}

/* Starts the pipeline  */
static gboolean gst_start_playback_pipe(gstData *data)
{
	/* http://gstreamer.freedesktop.org/data/doc/gstreamer/head/gstreamer/html/GstElement.html#gst-element-set-state */
	gst_element_set_state (data->pipeline, GST_STATE_PLAYING);
	while(gst_element_get_state(data->pipeline, NULL, NULL, GST_CLOCK_TIME_NONE) != GST_STATE_CHANGE_SUCCESS)
	  ;	
	return TRUE;
}

/* Add the pipeline to the bin */
static gboolean gst_add_bin_playback_to_pipe(gstData *data)
{
	if ((gst_bin_add(GST_BIN (data->pipeline), data->bin_playback)) != TRUE) {
		g_print("\nbin_playback not added to pipeline\n");
		return FALSE;	
	}
	
	if (gst_element_set_state (data->pipeline, GST_STATE_NULL) == GST_STATE_CHANGE_SUCCESS) {		
		return TRUE;
	} else {
		g_print("\nFailed to set pipeline state to NULL\n");
		return FALSE;		
	}
}

/* Disconnect the pipeline and the bin */
static void gst_remove_bin_playback_from_pipe(gstData *data)
{
	gst_element_set_state (data->pipeline, GST_STATE_NULL);
	gst_element_set_state (data->bin_playback, GST_STATE_NULL);
	if ((gst_bin_remove(GST_BIN (data->pipeline), data->bin_playback)) != TRUE) {
		g_print("\nbin_playback not removed from pipeline\n");
	}	
}

/* Cleanup */
static void gst_delete_pipeline(gstData *data)
{
	if (data->pipeline)
		gst_element_set_state (data->pipeline, GST_STATE_NULL);	
	if (data->bus)
		gst_object_unref (data->bus);
	if (data->pipeline)
		gst_object_unref (data->pipeline);	
}

/* Function for checking the specific message on bus
 * We look for EOS or Error messages */
static gboolean gst_check_bus_cb(GstBus *bus, GstMessage *msg, gpointer data)
{
#ifdef GST_USE_BUS_MONITOR
    GMainLoop *loop = (GMainLoop *)data;
#endif
	GError *err = NULL;                
	gchar *dbg = NULL;   
		  
	g_print("\nGot message: %s\n", GST_MESSAGE_TYPE_NAME(msg));
#ifdef GST_USE_BUS_MONITOR
    switch (GST_MESSAGE_TYPE(msg)) {
#else
	switch(GST_MESSAGE_TYPE (data->message)) {
#endif
		case GST_MESSAGE_EOS: 	  
			g_print("\nEnd of stream... \n\n");
#ifdef GST_USE_BUS_MONITOR
            g_main_loop_quit(loop);
#else
			exit_flag = TRUE;
#endif
			break;

		case GST_MESSAGE_ERROR: 
#ifdef GST_USE_BUS_MONITOR
            gst_message_parse_error(msg, &err, &dbg);
#else
			gst_message_parse_error (data->message, &err, &dbg);
#endif
			if (err) {
				g_printerr ("\nERROR: %s\n", err->message);
				g_error_free (err);
			}
			if (dbg) {
				g_printerr ("\nDebug details: %s\n", dbg);
				g_free (dbg);
			}
#ifdef GST_USE_BUS_MONITOR
            g_main_loop_quit(loop);
#else
			exit_flag = TRUE;
#endif
			break;

		default:
			g_printerr ("\nUnexpected message of type %d\n", GST_MESSAGE_TYPE (msg));
			break;
	}
	return TRUE;
}

__s32 gst_generate_pcm(__s32 argc, char *argv[])
{
#ifdef GST_USE_BUS_MONITOR
	GMainLoop *gst_loop;
#endif
	if (argc != 2) {
		g_print("\nUsage: %s <path of .wav/.mp3 audio file>\n", argv[0]);
		g_print("Note: Number of bytes for file location: %d\n\n", NUMBER_OF_BYTES_FOR_FILE_LOCATION);
		return FALSE;
	}
	
	if ((!strstr(argv[1], ".mp3")) && (!strstr(argv[1], ".wav"))) {
		g_print("\nOnly mp3 & wav files can be played\n");
		g_print("Specify the mp3 or wav file to be played\n");
		g_print("\nUsage: %s <path of .wav/.mp3 audio file>\n", argv[0]);
		g_print("Note: Number of bytes for file location: %d\n\n", NUMBER_OF_BYTES_FOR_FILE_LOCATION);
		return FALSE;
	}	 
	
	/* Initialise gstreamer. Mandatory first call before using any other gstreamer functionality */
	gst_init (&argc, &argv); 
	
#ifdef GST_USE_BUS_MONITOR
	/* Create main loop, it will run after calling g_main_loop_run()  */
	gst_loop = g_main_loop_new(NULL, FALSE);
#endif

	memset(gstreamerData.file_src_loc, 0, sizeof(gstreamerData.file_src_loc));
	strcpy(gstreamerData.file_src_loc, argv[1]);		
	memset(gstreamerData.file_dest_loc, 0, sizeof(gstreamerData.file_dest_loc));
	strcpy(gstreamerData.file_dest_loc, TMP_FILE_LOCATION);
	
	if (!gst_create_pipeline(&gstreamerData))
		goto err;		
	
	if (gst_init_audio_playback_pipeline(&gstreamerData)) {	
		if (!gst_add_bin_playback_to_pipe(&gstreamerData))
			goto err;		
		
		if (gst_start_playback_pipe(&gstreamerData)) {
			gstreamerData.bus = gst_element_get_bus (gstreamerData.pipeline);
			
#ifdef GST_USE_BUS_MONITOR
			if (gstreamerData.bus) {
                gst_bus_add_watch(gstreamerData.bus, gst_check_bus_cb, gst_loop);
                gst_object_unref(gstreamerData.bus);
                g_main_loop_run(gst_loop);
            }
#else
			while (TRUE) {
				if (gstreamerData.bus) {	
					/* Check for End Of Stream or error messages on bus
					 * The global exit_flag will be set in case of EOS or error. Exit if the flag is set */
					gstreamerData.message = gst_bus_poll (gstreamerData.bus, GST_MESSAGE_EOS | GST_MESSAGE_ERROR, -1);
					if (GST_MESSAGE_TYPE (gstreamerData.message)) {
						gst_check_bus_cb(gstreamerData.bus, gstreamerData.message, NULL);
					}
					gst_message_unref(gstreamerData.message);			
				}			
				
				if (exit_flag)
					break;			
				
				sleep(1);				
			}					
#endif
		}	
		gst_remove_bin_playback_from_pipe(&gstreamerData);					
	}	

	return TRUE;
err:	
	gst_delete_pipeline(&gstreamerData);
	
	return FALSE;
}

static __u32 pcm_write_to_cma_buffer(__u8 *data_ptr, __u32 buf_size)
{
	unsigned long long buf_addr_phys = 0;
	__s32 ret = 0;

	/* Allocate audio buffer */
	rmtcore_shm_fd = open(RMTCORE_SHM_DEV, O_RDWR);
	if (rmtcore_shm_fd < 0) {
		printf("Unable to open device %s\r\n", RMTCORE_SHM_DEV);
		return -1;
	}

	if (ioctl(rmtcore_shm_fd, RMTCORE_SHM_CHG_BUF_SIZE, &buf_size)) {
		printf("change mem size failed\r\n");
		goto out;
	}

	if (ioctl(rmtcore_shm_fd, RMTCORE_SHM_GET_BUF_ADDR_PHY, &buf_addr_phys)) {
		printf("read phys mem addr failed\r\n");
		goto out;
	}
	printf("phys address: 0x%llx\r\n", buf_addr_phys);

	ret = write(rmtcore_shm_fd, data_ptr, buf_size);
	if (ret != buf_size) {
		printf("write failed or incompleted!\n");
		buf_addr_phys = 0;
		goto out;
	} else
		printf("Finish write audio data to CMA area!\r\n");

out:
	return (__u32)buf_addr_phys;
}

__s32 pcm_load_to_ddr(__u32 *data_phy_addr, __u32 *data_len)
{
	__s32 pcm_file_fd = 0;
	struct stat stat_buf;
	__u8 *tmp_buf_ptr = NULL;
	__s32 buf_len = 0;
	__u32 buf_phy_addr = 0;
	__s32 ret = 0;

	if (stat(TMP_FILE_LOCATION, &stat_buf)) {
		fprintf(stderr, "Unable to get file length\n");
		ret = -1;
		goto out;
	}
	buf_len= stat_buf.st_size;

	pcm_file_fd = open(TMP_FILE_LOCATION, O_RDONLY);
	if (pcm_file_fd < 0) {
		fprintf(stderr, "Unable to open file %s\n", TMP_FILE_LOCATION);
		ret = -1;
		goto out;
	}

	/* Allocate a memory for audio data */
	tmp_buf_ptr = (__u8 *)malloc(buf_len);
	if (!tmp_buf_ptr) {
		fprintf(stderr, "Failed to allocate buffer for audio data\n");
		ret = -1;
		goto out;
	}

	if (buf_len != read(pcm_file_fd, tmp_buf_ptr, buf_len)) {
		fprintf(stderr, "Failed to read audio data to buffer\n");
		ret = -1;
		goto out;
	}

	buf_phy_addr = pcm_write_to_cma_buffer(tmp_buf_ptr, buf_len);
	if (!buf_phy_addr) {
		fprintf(stderr, "Failed to write audio data to cma buffer\n");
		ret = -1;
		goto out;
	}

	*data_phy_addr = buf_phy_addr;
	*data_len = buf_len;

out:
	if (pcm_file_fd)
		close(pcm_file_fd);
	if (tmp_buf_ptr)
		free(tmp_buf_ptr);

	return ret;
}

__s32 pcm_sleep_and_wakeup(void)
{
	FILE *ch_fp = NULL;
	__s32 ret = 0;

	/* 4, Sleep, zzz~~~ */ 
	fprintf(stdout, "Enter suspend mode, zzz~~~\n");
#if 0
	if (system("echo mem > /sys/power/state"))
		fprintf(stdout, "Enter suspend mode failed!\n");
#endif
	ch_fp = popen("echo mem > /sys/power/state", "w");
	if (!ch_fp) {
		fprintf(stderr, "popen channel failed!\n");
		ret = -1;
		goto out;
	}
	ret = pclose(ch_fp);
	if (WIFEXITED(ret))
		fprintf(stdout, "subprocess exited, exit code: %d\n", WEXITSTATUS(ret));

	/* 5, Wakeup and end */
	fprintf(stdout, "Wakeup from sleep, 666~~~\n\n");

out:
	return ret;
}

static __s32 pcm_send_to_remote(__u32 data_ptr, __u32 data_len)
{
	struct rpmsg_endpoint_info eptinfo;
	audio_rpmsg_request_t audio_msg_req;
	audio_rpmsg_response_t audio_msg_resp;
	audio_rpmsg_notification_t audio_msg_notif;
	ssize_t rtn_bytes = 0;

	/* Send RPMSG packet */
	rpmsg_ctrl_fd = open(RPMSG_CTRL_DEV, O_RDWR);
	if (rpmsg_ctrl_fd < 0) {
		fprintf(stderr, "Unable to open device %s\n", RPMSG_CTRL_DEV);
		return -1;
	}

	memset(&eptinfo, 0, sizeof(struct rpmsg_endpoint_info));
	memcpy(&eptinfo.name, RPMSG_DEV_NAME, strlen(RPMSG_DEV_NAME));
	eptinfo.src  = RPMSG_SRC_ADDR;
	eptinfo.dst  = RPMSG_DST_ADDR;
	ioctl(rpmsg_ctrl_fd, RPMSG_CREATE_EPT_IOCTL, &eptinfo);

	rpmsg_ep_fd = open(RPMSG_EP_DEV, O_RDWR);
	if (rpmsg_ep_fd < 0) {
		fprintf(stderr, "Unable to open device %s\n", RPMSG_EP_DEV);
		return -1;
	}

	/* Open audio device */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_TX_OPEN;
	audio_msg_req.header.priority = 0;
	rtn_bytes = write(rpmsg_ep_fd, &audio_msg_req, sizeof(audio_rpmsg_request_t));
	if (rtn_bytes != sizeof(audio_rpmsg_request_t)) {
		fprintf(stderr, "Not all request msg data transmitted or send failed: %ld\n", rtn_bytes);
		return -1;
	}

	/* Read response */
	memset(&audio_msg_resp, 0, sizeof(audio_rpmsg_response_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_resp, sizeof(audio_rpmsg_response_t));
	if (rtn_bytes != sizeof(audio_rpmsg_response_t)) {
		fprintf(stderr, "Not all resp msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}
	if (SRTM_AUDIO_SERV_REQUEST_CMD_TX_OPEN == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[1])
			fprintf(stderr, "Got TX_OPEN response msg! Failed!\n");
		else
			fprintf(stderr, "Got TX_OPEN response msg! PASS!!\n");
	}

	/* Set parameter */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_TX_SET_PARAMETER;
	audio_msg_req.header.priority = 0;
	audio_msg_req.param.sampleFormat = SRTM_AUDIO_SERV_SAMPLE_FORMAT_S16_LE;
	audio_msg_req.param.channels = SRTM_AUDIO_SERV_CHANNEL_STEREO;
	audio_msg_req.param.sampleRate = 22050;
	rtn_bytes = write(rpmsg_ep_fd, &audio_msg_req, sizeof(audio_rpmsg_request_t));
	if (rtn_bytes != sizeof(audio_rpmsg_request_t)) {
		fprintf(stderr, "Not all request msg data transmitted or send failed: %ld\n", rtn_bytes);
		return -1;
	}

	/* Read response */
	memset(&audio_msg_resp, 0, sizeof(audio_rpmsg_response_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_resp, sizeof(audio_rpmsg_response_t));
	if (rtn_bytes != sizeof(audio_rpmsg_response_t)) {
		fprintf(stderr, "Not all resp msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}
	if (SRTM_AUDIO_SERV_REQUEST_CMD_TX_SET_PARAMETER == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[2])
			fprintf(stderr, "Got SET_PARAMETER response msg! Failed!\n");
		else
			fprintf(stderr, "Got SET_PARAMETER response msg! PASS!!\n");
	}

	/* Set buffer */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_TX_SET_BUFFER;
	audio_msg_req.header.priority = 0;
	audio_msg_req.param.bufferAddress = data_ptr;
	audio_msg_req.param.bufferSize = data_len;
	audio_msg_req.param.periodSize = data_len;
	audio_msg_req.param.periodOffset = 0;
	rtn_bytes = write(rpmsg_ep_fd, &audio_msg_req, sizeof(audio_rpmsg_request_t));
	if (rtn_bytes != sizeof(audio_rpmsg_request_t)) {
		fprintf(stderr, "Not all request msg data transmitted or send failed: %ld\n", rtn_bytes);
		return -1;
	}

	/* Read response */
	memset(&audio_msg_resp, 0, sizeof(audio_rpmsg_response_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_resp, sizeof(audio_rpmsg_response_t));
	if (rtn_bytes != sizeof(audio_rpmsg_response_t)) {
		fprintf(stderr, "Not all resp msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}
	if (SRTM_AUDIO_SERV_REQUEST_CMD_TX_SET_BUFFER == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[2])
			fprintf(stderr, "Got SET_BUFFER response msg! Failed!\n");
		else
			fprintf(stderr, "Got SET_BUFFER response msg! PASS!\n");
	}

	/* Start play */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_TX_START;
	audio_msg_req.header.priority = 0;
	rtn_bytes = write(rpmsg_ep_fd, &audio_msg_req, sizeof(audio_rpmsg_request_t));
	if (rtn_bytes != sizeof(audio_rpmsg_request_t)) {
		fprintf(stderr, "Not all request msg data transmitted or send failed: %ld\n", rtn_bytes);
		return -1;
	}

	/* Read response */
	memset(&audio_msg_resp, 0, sizeof(audio_rpmsg_response_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_resp, sizeof(audio_rpmsg_response_t));
	if (rtn_bytes != sizeof(audio_rpmsg_response_t)) {
		fprintf(stderr, "Not all resp msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}
	if (SRTM_AUDIO_SERV_REQUEST_CMD_TX_START == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[2])
			fprintf(stderr, "Got TX_START response msg! Failed!\n");
		else
			fprintf(stderr, "Got TX_START response msg! PASS!!\n");
	}

	pcm_sleep_and_wakeup();

	/* Read notification */
	memset(&audio_msg_notif, 0, sizeof(audio_rpmsg_notification_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_notif, sizeof(audio_rpmsg_notification_t));
	if (rtn_bytes != sizeof(audio_rpmsg_notification_t)) {
		fprintf(stderr, "Not all notify msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}

	if (SRTM_AUDIO_SERV_REQUEST_CMD_TX_PERIOD_DONE == audio_msg_notif.header.command)
		fprintf(stderr, "Got TX_PERIOD_DONE response msg!\n");

	/* close play */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_TX_CLOSE;
	audio_msg_req.header.priority = 0;
	rtn_bytes = write(rpmsg_ep_fd, &audio_msg_req, sizeof(audio_rpmsg_request_t));
	if (rtn_bytes != sizeof(audio_rpmsg_request_t)) {
		fprintf(stderr, "Not all request msg data transmitted or send failed: %ld\n", rtn_bytes);
		return -1;
	}

	/* Read response */
	memset(&audio_msg_resp, 0, sizeof(audio_rpmsg_response_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_resp, sizeof(audio_rpmsg_response_t));
	if (rtn_bytes != sizeof(audio_rpmsg_response_t)) {
		fprintf(stderr, "Not all resp msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}
	if (SRTM_AUDIO_SERV_REQUEST_CMD_TX_CLOSE == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[2])
			fprintf(stderr, "Got TX_CLOSE response msg! Failed!\n");
		else
			fprintf(stderr, "Got TX_CLOSE response msg! PASS!!\n");
	}

	return 0;
}

__s32 main(__s32 argc, char *argv[])
{
	__u32 audio_data_buf_addr = 0;
	__u32 audio_data_len = 0;
	__s32 ret = 0;

	/* 1, Generate PCM */
	fprintf(stdout, "Generating PCM audio...");
	if (!gst_generate_pcm(argc, argv)) {
		fprintf(stderr, "failed!\n");
		return 1;
	}
	fprintf(stdout, "DONE\n");
 
	fprintf(stdout, "Loading PCM audio...");
	/* 2, Read PCM and load to DDR */ 
	if (pcm_load_to_ddr(&audio_data_buf_addr, &audio_data_len)) {
		fprintf(stderr, "failed!\n");
		ret = -1;
		goto out;
	}
	fprintf(stdout, "DONE\n");

	/* 3, Send the address to M4 core to play  */
	fprintf(stdout, "Sending PCM audio to remote processor...");
	if (pcm_send_to_remote(audio_data_buf_addr, audio_data_len)) {
		fprintf(stderr, "failed!\n");
		ret = -1;
		goto out;
	}
	fprintf(stdout, "DONE\n");

out:
	/* 6. Clean up*/
	if (rpmsg_ep_fd)
		close(rpmsg_ep_fd);
	if (rpmsg_ctrl_fd)
		close(rpmsg_ctrl_fd);
	if (rmtcore_shm_fd)
		close(rmtcore_shm_fd);

	return ret;
}
