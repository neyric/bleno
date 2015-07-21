#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include "utility.h"

static int lastSignal = 0;

static void signalHandler(int signal) {
  lastSignal = signal;
}

struct hci_acl_hdr {
	uint16_t handle;
	uint16_t len;
};

struct signal_hdr {
	uint16_t len;
	uint16_t cid;
};

struct signal_payload_hdr {
	uint8_t  code;
	uint8_t  id;
	uint16_t len;
};

struct le_con_param_update_req {
	uint16_t interval_min;
	uint16_t interval_max;
	uint16_t slave_latency;
	uint16_t timeout_multiplier;
};


int hci_send_acl_data(int dd, uint16_t handle, uint8_t dlen, struct signal_hdr *sh, struct signal_payload_hdr *plh, void *pl)
{
	uint8_t type = HCI_ACLDATA_PKT;
        hci_acl_hdr ha;
	struct iovec iv[5];
	int ivn;

	ha.handle = handle & 0xFFF0; // Zero out the PB (packet boundary is host-to-controller) and BC (broadcast is point-to-point)
	ha.dlen = dlen;

	iv[0].iov_base = &type;
	iv[0].iov_len = 1;
	iv[1].iov_base = &ha;
	iv[1].iov_len = HCI_ACL_HDR_SIZE;
	ivn = 2;

	printf("\nACL Packet details[handle:%x, length:%d]\n", ha.handle, ha.dlen);

	if (dlen) {
		iv[2].iov_base = sh;
		iv[2].iov_len = 4; //HCI_SIGNAL_HDR_SIZE;
		ivn = 3;
		printf("\nACL signal command details[length:%d, cid:%d]\n", sh->len, sh->cid);
		if(sh->len > 0) {
			iv[3].iov_base = plh;
			iv[3].iov_len = 4; //HCI_SIGNAL_PAYLOAD_HDR_SIZE;
			ivn = 4;
			if(plh->len > 0) {
				iv[4].iov_base = pl;
				iv[4].iov_len = plh->len;
				ivn = 5;
			}
		}
	}

	while (writev(dd, iv, ivn) < 0) {
		if (errno == EAGAIN || errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

int hci_signal_le_con_param_update_req(int dd, uint16_t interval_min, uint16_t interval_max, uint16_t slave_latency, uint16_t timeout_multiplier, uint16_t id)
{
	struct signal_hdr sh;
	struct signal_payload_hdr pl;
	struct le_con_param_update_req ur;

	uint16_t handle = 0x0040;
	uint16_t length = 0x0010;

	memset(&sh, 0, sizeof(sh));
	memset(&pl, 0, sizeof(pl));
	memset(&ur, 0, sizeof(ur));

	sh.len = 0x000C; //HCI_SIGNAL_CON_PARAM_UPDATE_REQ_SIZE; //12 or 0x000C
	sh.cid = 0x0005; //LE_CHANNEL; //5 or 0x0005

	pl.code = 0x12; //LE_CON_PARAM_UPDATE_REQ_CODE
	pl.id = id;//0x77; // Need to randomize? Sequential?
	pl.len = 0x0008; // LE_CON_PARAM_UPDATE_LEN

	ur.interval_min = interval_min;
	ur.interval_max = interval_max;
	ur.slave_latency = slave_latency;
	ur.timeout_multiplier = timeout_multiplier;

        if (hci_send_acl_data(dd, handle, length, &sh, &pl, &ur) < 0)
		return -1;

        return 0;
}

int hci_le_set_advertising_data(int dd, uint8_t* data, uint8_t length, int to)
{
  struct hci_request rq;
  le_set_advertising_data_cp data_cp;
  uint8_t status;

  memset(&data_cp, 0, sizeof(data_cp));
  data_cp.length = length <= sizeof(data_cp.data) ? length : sizeof(data_cp.data);
  memcpy(&data_cp.data, data, data_cp.length);

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISING_DATA;
  rq.cparam = &data_cp;
  rq.clen = LE_SET_ADVERTISING_DATA_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  if (hci_send_req(dd, &rq, to) < 0)
    return -1;

  if (status) {
    errno = EIO;
    return -1;
  }

  return 0;
}

int hci_le_set_scan_response_data(int dd, uint8_t* data, uint8_t length, int to)
{
  struct hci_request rq;
  le_set_scan_response_data_cp data_cp;
  uint8_t status;

  memset(&data_cp, 0, sizeof(data_cp));
  data_cp.length = length <= sizeof(data_cp.data) ? length : sizeof(data_cp.data);
  memcpy(&data_cp.data, data, data_cp.length);

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_SCAN_RESPONSE_DATA;
  rq.cparam = &data_cp;
  rq.clen = LE_SET_SCAN_RESPONSE_DATA_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  if (hci_send_req(dd, &rq, to) < 0)
    return -1;

  if (status) {
    errno = EIO;
    return -1;
  }

  return 0;
}

// Set advertising interval to 100 ms
// Note: 0x00A0 * 0.625ms = 100ms
int hci_le_set_advertising_parameters(int dd, int to)
{
  struct hci_request rq;
  le_set_advertising_parameters_cp adv_params_cp;
  uint8_t status;

  memset(&adv_params_cp, 0, sizeof(adv_params_cp));
  adv_params_cp.min_interval = htobs(0x00A0);
  adv_params_cp.max_interval = htobs(0x00A0);
  adv_params_cp.chan_map = 7;

  memset(&rq, 0, sizeof(rq));
  rq.ogf = OGF_LE_CTL;
  rq.ocf = OCF_LE_SET_ADVERTISING_PARAMETERS;
  rq.cparam = &adv_params_cp;
  rq.clen = LE_SET_ADVERTISING_PARAMETERS_CP_SIZE;
  rq.rparam = &status;
  rq.rlen = 1;

  if (hci_send_req(dd, &rq, to) < 0)
    return -1;

  if (status) {
    errno = EIO;
    return -1;
  }

  return 0;
}

int main(int argc, const char* argv[])
{
  char *hciDeviceIdOverride = NULL;
  int hciDeviceId = 0;
  int hciSocket;
  struct hci_dev_info hciDevInfo;
  char address[18];

  int previousAdapterState = -1;
  int currentAdapterState;
  const char* adapterState = NULL;

  fd_set rfds;
  struct timeval tv;
  int selectRetval;

  char stdinBuf[256 * 2 + 1];
  char advertisementDataBuf[256];
  int advertisementDataLen = 0;
  char scanDataBuf[256];
  int scanDataLen = 0;
  int len;
  int i;

  memset(&hciDevInfo, 0x00, sizeof(hciDevInfo));

  // remove buffering
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  // setup signal handlers
  signal(SIGINT, signalHandler);
  signal(SIGKILL, signalHandler);
  signal(SIGHUP, signalHandler);
  signal(SIGUSR1, signalHandler);
  signal(SIGUSR2, signalHandler);

  prctl(PR_SET_PDEATHSIG, SIGKILL);

  hciDeviceIdOverride = getenv("BLENO_HCI_DEVICE_ID");
  if (hciDeviceIdOverride != NULL) {
    hciDeviceId = atoi(hciDeviceIdOverride);
  } else {
    // if no env variable given, use the first available device
    hciDeviceId = hci_get_route(NULL);
  }

  if (hciDeviceId < 0) {
    hciDeviceId = 0; // use device 0, if device id is invalid
  }

  // setup HCI socket
  hciSocket = hci_open_dev(hciDeviceId);
  hciDevInfo.dev_id = hciDeviceId;

  if (hciSocket == -1) {
    printf("adapterState unsupported\n");
    return -1;
  }

  while(1) {
    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    FD_SET(hciSocket, &rfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    // get HCI dev info for adapter state
    ioctl(hciSocket, HCIGETDEVINFO, (void *)&hciDevInfo);
    currentAdapterState = hci_test_bit(HCI_UP, &hciDevInfo.flags);

    if (previousAdapterState != currentAdapterState) {
      previousAdapterState = currentAdapterState;

      if (!currentAdapterState) {
        adapterState = "poweredOff";
      } else {
        hci_le_set_advertise_enable(hciSocket, 0, 1000);

        hci_le_set_advertise_enable(hciSocket, 1, 1000);

        if (hci_le_set_advertise_enable(hciSocket, 0, 1000) == -1) {
          if (EPERM == errno) {
            adapterState = "unauthorized";
          } else if (EIO == errno) {
            adapterState = "unsupported";
          } else {
            printf("%d\n", errno);
            adapterState = "unknown";
          }
        } else {
          adapterState = "poweredOn";
        }
      }

      ba2str(&hciDevInfo.bdaddr, address);
      printf("address %s\n", address);
      printf("adapterState %s\n", adapterState);
    }

    selectRetval = select(hciSocket + 1, &rfds, NULL, NULL, &tv);

    if (-1 == selectRetval) {
      if (SIGINT == lastSignal || SIGKILL == lastSignal) {
        // done
        break;
      } else if (SIGHUP == lastSignal) {
        // stop advertising
        hci_le_set_advertise_enable(hciSocket, 0, 1000);
      } else if (SIGUSR2 == lastSignal) {
        // TODO: make id unique ?
	hci_signal_le_con_param_update_req(hciSocket, htobs(0x0C8), htobs(0x0960),htobs(0x0007), htobs(0x0C80), htobs(0x0AAA));
      } else if (SIGUSR1 == lastSignal) {
        // stop advertising
        hci_le_set_advertise_enable(hciSocket, 0, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);

        // set advertisement parameters, mostly to set the advertising interval to 100ms
        hci_le_set_advertising_parameters(hciSocket, 1000);

        // start advertising
        hci_le_set_advertise_enable(hciSocket, 1, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
      }
    } else if (selectRetval) {
      if (FD_ISSET(0, &rfds)) {
        len = readLine(0, stdinBuf, sizeof(stdinBuf));

        if (len <= 0) {
          break;
        }

        i = 0;
        advertisementDataLen = 0;
        while(i < len && stdinBuf[i] != ' ') {
          unsigned int data = 0;
          sscanf(&stdinBuf[i], "%02x", &data);
          advertisementDataBuf[advertisementDataLen] = data;
          advertisementDataLen++;
          i += 2;
        }

        i++;
        scanDataLen = 0;
        while(i < len && stdinBuf[i] != '\n') {
          unsigned int data = 0;
          sscanf(&stdinBuf[i], "%02x", &data);
          scanDataBuf[scanDataLen] = data;
          scanDataLen++;
          i += 2;
        }

        // stop advertising
        hci_le_set_advertise_enable(hciSocket, 0, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);

        // set advertisement parameters, mostly to set the advertising interval to 100ms
        hci_le_set_advertising_parameters(hciSocket, 1000);

        // start advertising
        hci_le_set_advertise_enable(hciSocket, 1, 1000);

        // set scan data
        hci_le_set_scan_response_data(hciSocket, (uint8_t*)&scanDataBuf, scanDataLen, 1000);

        // set advertisement data
        hci_le_set_advertising_data(hciSocket, (uint8_t*)&advertisementDataBuf, advertisementDataLen, 1000);
      }
    }
  }

  // stop advertising
  hci_le_set_advertise_enable(hciSocket, 0, 1000);

  close(hciSocket);

  return 0;
}
