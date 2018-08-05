/*
 * Network.h
 *
 *  Created on: Aug 5, 2018
 *      Author: yoram
 */

#ifndef NETWORK_H_
#define NETWORK_H_

#include <winsock2.h>

#define NW_errno WSAGetLastError()
#define NW_read recv


int NW_inint (char *ip_addr);
void NW_close (int sock);
void NW_Print_IP (char *buff, int len);


#endif /* NETWORK_H_ */


