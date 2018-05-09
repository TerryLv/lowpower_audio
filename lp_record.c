/*
 * Copyright (C) 2018 - Terry Lv
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
#define TMP_FILE_LOCATION			"./audio_rec.tmp"
#define GST_USE_BUS_MONITOR

#define RPMSG_CTRL_DEV 				"/dev/rpmsg_ctrl0"
#define RPMSG_EP_DEV 				"/dev/rpmsg0"
#define RMTCORE_SHM_DEV 			"/dev/rmtcore_shm"
#define RPMSG_DEV_NAME 				"audio_ept"
#define RPMSG_SRC_ADDR   								0x400U
#define RPMSG_DST_ADDR   								0x1EU

/* Allocate a 5s stero, 22050, record buffer, buffer size should be:
 * 22050 * 2(stero) * 2(S16) * 5 = 441000 Bytes */
#define AUDIO_REC_DURATION			(5)
#define AUDIO_REC_SAMPLERATE		(48000)
#define AUDIO_REC_CHANNELS			(2)
#define AUDIO_REC_BUFFER_SIZE		(AUDIO_REC_SAMPLERATE * AUDIO_REC_CHANNELS * 2 * AUDIO_REC_DURATION)

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

static int rpmsg_ctrl_fd = 0, rpmsg_ep_fd = 0, rmtcore_shm_fd = 0;

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

static __u32 pcm_alloc_cma_buffer(__u32 buf_size)
{
	unsigned long long buf_addr_phys = 0;

	/* Allocate audio buffer */
	rmtcore_shm_fd = open(RMTCORE_SHM_DEV, O_RDWR);
	if (rmtcore_shm_fd < 0) {
		fprintf(stderr, "Unable to open device %s\r\n", RMTCORE_SHM_DEV);
		goto out;
	}

	if (ioctl(rmtcore_shm_fd, RMTCORE_SHM_CHG_BUF_SIZE, &buf_size)) {
		fprintf(stderr, "change mem size failed\r\n");
		goto out;
	}

	if (ioctl(rmtcore_shm_fd, RMTCORE_SHM_GET_BUF_ADDR_PHY, &buf_addr_phys)) {
		fprintf(stderr, "read phys mem addr failed\r\n");
		goto out;
	}
	fprintf(stdout, "phys address: 0x%llx\r\n", buf_addr_phys);

out:
	return (__u32)buf_addr_phys;
}

static __s32 pcm_load_to_ddr(__u8 **data_addr, const __u32 data_len)
{
	__u8 *tmp_buf_ptr = NULL;
	__u32 buf_len = 0;
	__s32 ret = 0;

	/* Allocate a memory for audio data */
	tmp_buf_ptr = (__u8 *)malloc(buf_len);
	if (!tmp_buf_ptr) {
		fprintf(stderr, "Failed to allocate buffer for audio data\n");
		ret = -1;
		goto out;
	}

	buf_len = data_len;
	if (buf_len != read(rmtcore_shm_fd, tmp_buf_ptr, buf_len)) {
		fprintf(stderr, "Failed to read audio data to buffer\n");
		ret = -1;
		goto out;
	}

out:
	*data_addr = tmp_buf_ptr;
	return ret;
}

static __s32 pcm_save_to_file(const __u8 *data_addr, const __u32 data_len)
{
	int pcm_file_fd = 0;
	int buf_len = 0;
	int ret = 0;

	pcm_file_fd = open(TMP_FILE_LOCATION, O_WRONLY);
	if (pcm_file_fd < 0) {
		fprintf(stderr, "Unable to open file %s\n", TMP_FILE_LOCATION);
		ret = -1;
		goto out;
	}

	if (buf_len != write(pcm_file_fd, data_addr, data_len)) {
		fprintf(stderr, "Failed to write audio data to buffer\n");
		ret = -1;
		goto out;
	}

out:
	if (pcm_file_fd)
		close(pcm_file_fd);
	if (data_addr)
		free((void *)data_addr);

	return ret;
}

int pcm_sleep_and_wakeup(void)
{
	FILE *ch_fp = NULL;
	int ret = 0;

	/* 4, Sleep, zzz~~~ */ 
	getchar();
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

int pcm_send_to_remote(__u32 data_addr, __u32 data_len)
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
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_RX_OPEN;
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
	if (SRTM_AUDIO_SERV_REQUEST_CMD_RX_OPEN == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[1])
			fprintf(stderr, "Got RX_OPEN response msg! Failed!\n");
		else
			fprintf(stderr, "Got RX_OPEN response msg! PASS!!\n");
	}

	/* Set parameter */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_RX_SET_PARAMETER;
	audio_msg_req.header.priority = 0;
	audio_msg_req.param.sampleFormat = SRTM_AUDIO_SERV_SAMPLE_FORMAT_S16_LE;
	audio_msg_req.param.channels = SRTM_AUDIO_SERV_CHANNEL_STEREO;
	audio_msg_req.param.sampleRate = AUDIO_REC_SAMPLERATE;
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
	if (SRTM_AUDIO_SERV_REQUEST_CMD_RX_SET_PARAMETER == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[1])
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
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_RX_SET_BUFFER;
	audio_msg_req.header.priority = 0;
	audio_msg_req.param.bufferAddress = data_addr;
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
	if (SRTM_AUDIO_SERV_REQUEST_CMD_RX_SET_BUFFER == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[1])
			fprintf(stderr, "Got SET_BUFFER response msg! Failed!\n");
		else
			fprintf(stderr, "Got SET_BUFFER response msg! PASS!\n");
	}

	/* Start record */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_RX_START;
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
	if (SRTM_AUDIO_SERV_REQUEST_CMD_RX_START == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[1])
			fprintf(stderr, "Got RX_START response msg! Failed!\n");
		else
			fprintf(stderr, "Got RX_START response msg! PASS!!\n");
	}

	//pcm_sleep_and_wakeup();

	/* Read notification */
	memset(&audio_msg_notif, 0, sizeof(audio_rpmsg_notification_t));
	rtn_bytes = read(rpmsg_ep_fd, &audio_msg_notif, sizeof(audio_rpmsg_notification_t));
	if (rtn_bytes != sizeof(audio_rpmsg_notification_t)) {
		fprintf(stderr, "Not all notify msg data received or read failed: %ld\n", rtn_bytes);
		return -1;
	}

	if (SRTM_AUDIO_SERV_REQUEST_CMD_RX_PERIOD_DONE == audio_msg_notif.header.command)
		fprintf(stderr, "Got RX_PERIOD_DONE response msg!\n");

	/* close record */
	memset(&audio_msg_req, 0, sizeof(audio_rpmsg_request_t));
	audio_msg_req.header.category = SRTM_AUDIO_CATEGORY;
	audio_msg_req.header.majorVersion = (__u8)((SRTM_AUDIO_VERSION & 0xFF00U) >> 8U);;
	audio_msg_req.header.minorVersion = (__u8)(SRTM_AUDIO_VERSION & 0xFFU);;
	audio_msg_req.header.type = SRTM_MESSAGE_TYPE_REQUEST;
	audio_msg_req.header.command = SRTM_AUDIO_SERV_REQUEST_CMD_RX_CLOSE;
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
	if (SRTM_AUDIO_SERV_REQUEST_CMD_RX_CLOSE == audio_msg_resp.header.command) {
		if (audio_msg_resp.param.result[1])
			fprintf(stderr, "Got RX_CLOSE response msg! Failed!\n");
		else
			fprintf(stderr, "Got RX_CLOSE response msg! PASS!!\n");
	}

	return 0;
}

int main(int argc, char *argv[])
{
	__u32 audio_data_phy_addr = 0;
	__u32 audio_data_len = 0;
	__u8 *audio_data_ptr = NULL;
	int ret = -1;

	/* 1, Allocate cma buffer for record data */
	fprintf(stdout, "Allocate audio record buffer...");
	/* Allocate a 5s stero, 22050, record buffer, buffer size should be:
	 * 22050 * 2(stero) * 2(S16) * 5 = 441000 Bytes */
	audio_data_phy_addr = pcm_alloc_cma_buffer(AUDIO_REC_BUFFER_SIZE);
	if (!audio_data_phy_addr) {
		fprintf(stderr, "failed!\n");
		goto out;
	}
	audio_data_len = AUDIO_REC_BUFFER_SIZE;
	fprintf(stdout, "DONE\n");
 
	/* 2, Send the address to M4 core to record  */
	fprintf(stdout, "Sending PCM audio request to remote processor...");
	if (pcm_send_to_remote(audio_data_phy_addr, audio_data_len)) {
		fprintf(stderr, "failed!\n");
		goto out;
	}
	fprintf(stdout, "DONE\n");

	/* 4, Load audio data to ddr */
	fprintf(stdout, "Loading recorded PCM audio data to DDR...");
	if (pcm_load_to_ddr(&audio_data_ptr, audio_data_len)) {
		fprintf(stderr, "failed!\n");
		goto out;
	}
	fprintf(stdout, "DONE\n");

	/* 5, Saving PCM data to file */
	fprintf(stdout, "Saving recorded PCM audio data to file...");
	if (pcm_save_to_file(audio_data_ptr, audio_data_len)) {
		fprintf(stderr, "failed!\n");
		goto out;
	}
	fprintf(stdout, "DONE\n");

	ret = 0;

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
