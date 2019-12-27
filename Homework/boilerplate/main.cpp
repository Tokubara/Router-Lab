#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern bool update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern uint16_t calculateIPChecksum(uint8_t *packet, size_t len);
extern uint16_t calculateUDPChecksum(uint8_t *packet, size_t len);

// void build_rip_packet(RipPacket* rippacket, bool is_broad, uint32_t t_if_index);
void build_rip_packet(RipPacket* rippacket, bool is_broad, uint32_t src_addr, uint32_t mask, uint32_t t_if_index);
void broadcast();
bool cope_with_response_packet(RipPacket* ripack, int rec_if_index, uint32_t src_addr);
void complete_ip_udp_head(uint32_t source_ip, uint32_t src_addr, uint32_t rip_len, uint32_t udp_len);
void print_routing_table();


uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
// in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a,
                                    //  0x0103000a};
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};
in_addr_t addrs_mask[N_IFACE_ON_BOARD] = {0x00ffffff, 0x00ffffff, 0x00ffffff, 0x00ffffff};

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }

  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  int mask0 = (1 << N_IFACE_ON_BOARD) - 1;
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i] & ~(255 << 24), // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .mask = addrs_mask[i],
        .metric = 0,
        .timestamp = 0,
        .entry_from = 0,
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {
      // What to do?
      // send complete routing table to every interface
      // ref. RFC2453 3.8
      // multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
      printf("5s Timer\n");

      broadcast();
      print_routing_table();

      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      printf("HAL_ERR_EOF\n");
      break;
    } else if (res < 0) {
      printf("UNEXPECTED ERROR\n");
      return res;
    } else if (res == 0) {
      // printf("TIMEOUT\n");
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }

    // 1. validate
    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    for(int i = 0 ; i < 4; i++){
      src_addr = (src_addr << 8) + packet[15-i];
      dst_addr = (dst_addr << 8) + packet[19-i];
    }
    // drop the packet from self
    bool from_self = false;
    for(int i = 0 ; i < N_IFACE_ON_BOARD; i++){
      if(addrs[i] == src_addr) from_self = true;
    }
    if(from_self) continue;

    // 2. check whether dst is me
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }

    // TODO: Handle rip multicast address(224.0.0.9)?
    in_addr_t multicast_addr = 0x090000e0;
    if(memcmp(&dst_addr, &multicast_addr, sizeof(in_addr_t)) == 0)
      dst_is_me = true;

    if (dst_is_me) {
      // 3a.1
      RipPacket rip;
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          printf("request packet from: %u.%u.%u.%u \n", src_addr & 255, (src_addr >> 8) & 255, (src_addr >> 16) & 255, (src_addr >> 24) & 255); 
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          RipPacket resp;
          // TODO: fill resp
          // build_rip_packet(&resp, false, addrs[if_index], addrs_mask[if_index]);
          build_rip_packet(&resp, false, src_addr, addrs_mask[if_index], if_index);
          // build_rip_packet(&resp, false, if_index);
          resp.command = 2;

          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          uint32_t udp_len = rip_len + 8;
          uint32_t source_ip = addrs[if_index];

          complete_ip_udp_head(source_ip, src_addr, rip_len, udp_len);
          // send it back
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } else {
          // 3a.2 response, ref. RFC2453 3.9.2
          // update routing table
          // new metric = ?
          // update metric, if_index, nexthop
          // what is missing from RoutingTableEntry?
          // TODO: use query and update
          // triggered updates? ref. RFC2453 3.10.1
           printf("response packet from: %u.%u.%u.%u \n", src_addr & 255, (src_addr >> 8) & 255, (src_addr >> 16) & 255, (src_addr >> 24) & 255); 
          if(cope_with_response_packet(&rip, if_index, src_addr)) broadcast();
        }
      }
    } else {
      // 3b.1 dst is not me
      // forward
      // beware of endianness
      printf("transfer packet from: %u.%u.%u.%u \n", src_addr & 255, (src_addr >> 8) & 255, (src_addr >> 16) & 255, (src_addr >> 24) & 255); 
      uint32_t nexthop, dest_if;
      if (query(dst_addr, &nexthop, &dest_if)) {
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nexthop == 0) {
          nexthop = dst_addr;
        }
        if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
          // found
          memcpy(output, packet, res);
          // update ttl and checksum
          forward(output, res);

          //在 TTL 减到 0 的时候建议构造一个 ICMP Time Exceeded 返回给发送者；
          // TODO: you might want to check ttl=0 case
          if(output[8] == 0) {// ttl = 0
            memcpy(&output[28], "ICMP Time Exceeded", 18);
            printf("ICMP Time Exceeded \n");
          }else{
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
        } else {
          // not found
          // you can drop it
          printf("ARP not found for %x\n", nexthop);
        }
      } else {
        // 如果没查到目的地址的路由，建议返回一个 ICMP Destination Network Unreachable；
        // not found
        // optionally you can send ICMP Host Unreachable
        memcpy(&output[28], "ICMP Destination Network Unreachable", 36);
        printf("IP not found for %u.%u.%u.%u\n", src_addr&255, (src_addr>>8)&255, (src_addr>>16)&255, (src_addr>>24)&255);
      }
    }
  }
  return 0;
}

// void build_rip_packet(RipPacket* rippacket, bool is_broad, uint32_t t_if_index){
void build_rip_packet(RipPacket* rippacket, bool is_broad, uint32_t src_addr, uint32_t mask, uint32_t t_if_index){
    int resp_entry_location = 0;
    RoutingTableEntry* routing_table = get_routingtable();
    uint32_t routing_table_len = get_routingtable_len();
    bool* valid_routing_table = get_valid_routing_table();
    for(int i = 0 ; i < routing_table_len; i++){
      if(!valid_routing_table[i]) continue;
      // if the addr is in the same sub-net of the target addr
      // if(routing_table[i].if_index == t_if_index || routing_table[i].nexthop == addrs[routing_table[i].if_index]) continue;
      // horizon split
      if(!is_broad && in_same_net(src_addr, mask, routing_table[i].addr, mask)) continue;
      if(t_if_index == routing_table[i].if_index) continue;
      rippacket->entities[resp_entry_location].addr = routing_table[i].addr;
      // mask ? 
      rippacket->entities[resp_entry_location].mask = routing_table[i].mask;
      rippacket->entities[resp_entry_location].nexthop = routing_table[i].nexthop;
      // if(is_broad) rippacket->entities[resp_entry_location].metric = 16 << 24;
      // else rippacket->entities[resp_entry_location].metric = routing_table[i].metric;
      rippacket->entities[resp_entry_location].metric = routing_table[i].metric + (1 << 24);
      resp_entry_location++;
    }
    rippacket->numEntries = resp_entry_location;
}

//multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
void broadcast(){
      RipPacket broad_rip;

      uint32_t dest_addr = 0x090000e0;

      macaddr_t broadcastMac;
      //todo 
      broadcastMac[0] = 0x01; broadcastMac[1] = 0x00; broadcastMac[2] = 0x5e; broadcastMac[3] = 0x00; broadcastMac[4] = 0x00;broadcastMac[5] = 0x09;

      // //TODO: source addr ?
      broad_rip.command = 2;
      uint32_t rip_len =  assemble(&broad_rip, &output[20+8]);
      uint32_t udp_len = rip_len + 8;

      for(int i = 0; i < N_IFACE_ON_BOARD; i++){
      // TODO: source addr ?
        // split horizon: broadcast will not send routing_entry to its source net
        build_rip_packet(&broad_rip, true, addrs[i], addrs_mask[i], i);
        // build_rip_packet(&broad_rip, false, i);
        //broad_rip.command = 2;
        // uint32_t rip_len =  assemble(&broad_rip, &output[20+8]);
        // uint32_t udp_len = rip_len + 8;

        complete_ip_udp_head(addrs[i], dest_addr, rip_len, udp_len);

        HAL_SendIPPacket(i, output, rip_len + 20 + 8, broadcastMac);
      }
}

bool cope_with_response_packet(RipPacket* ripack, int rec_if_index, uint32_t src_addr){
  bool routing_change_flag = false;
  RipPacket invalild_routing;
  int invalild_entities = 0;
  for(int i = 0 ; i < ripack->numEntries; i++){
    uint32_t len = 0;
    uint32_t mask = ripack->entities[i].mask;
    while(mask & 1 == 1){
      len ++;
      mask = mask >> 1;
    }
    RoutingTableEntry temp_entry;
      temp_entry.addr = ripack->entities[i].addr;
      temp_entry.len = len;
      temp_entry.if_index = rec_if_index;
      temp_entry.nexthop = src_addr;
      temp_entry.metric = ripack->entities[i].metric;
      temp_entry.mask = ripack->entities[i].mask;
      temp_entry.timestamp = 0;
      // entry_from = source_ip ( 入网口 )
      temp_entry.entry_from = addrs[rec_if_index];
    
    //metric == 16 && is_not_broad
    //metric is bigendian
    uint32_t metric_sv = (ripack->entities[i].metric >> 24) & 255;
    if((metric_sv + 1) > 16 && ripack->entities[i].nexthop == src_addr){
      routing_change_flag = routing_change_flag || update(false, temp_entry);
      invalild_routing.entities[invalild_entities] = ripack->entities[i];
      invalild_entities += 1;
      //print invalid packet
      printf("invalid: %u, %u, %u, %u", temp_entry.addr, temp_entry.if_index, temp_entry.metric, temp_entry.mask);
    }else{
      bool updated_entry = update(true, temp_entry);
      routing_change_flag = routing_change_flag || updated_entry;
      // if(updated_entry)
        // printf("updated: %u, %u, %u, %u\n", temp_entry.addr, temp_entry.if_index, temp_entry.metric, temp_entry.mask);
    }
  }

  macaddr_t broadcastMac;
  broadcastMac[0] = 0x01; broadcastMac[1] = 0x00; broadcastMac[2] - 0x5e; broadcastMac[3] = 0x00; broadcastMac[4] = 0x00;broadcastMac[5] = 0x09;

  uint32_t dest_addr = 0x090000e0;
  // broadcast the invalid routing
  // invalid routing seen as response
  invalild_routing.command = 2;
  invalild_routing.numEntries = invalild_entities;
  uint32_t rip_len =  assemble(&invalild_routing, &output[20 + 8]);
  uint32_t udp_len = rip_len + 8;

  //source ip
  if(invalild_entities > 0){
    for(int i = 0; i < N_IFACE_ON_BOARD; i++){
      if(i == rec_if_index) continue;
      // build_rip_packet(&invalild_routing, true, i);
      build_rip_packet(&invalild_routing, true, addrs[i], addrs_mask[i], i);
      invalild_routing.command = 2;
      complete_ip_udp_head(addrs[i], dest_addr, rip_len, udp_len);
      
      HAL_SendIPPacket(i, output, rip_len + 20 + 8, broadcastMac);
    }
  }
  // if(routing_change_flag) printf("routing changed\n");
  return routing_change_flag;
}

void complete_ip_udp_head(uint32_t source_ip, uint32_t src_addr, uint32_t rip_len, uint32_t udp_len){
    // assemble
    // IP
    // VERSION / IHL
    output[0] = 0x45;
    //TOS / ECN
    output[1] = 0;
    //total length
    uint32_t total_length = rip_len + 28;
    output[2] = (total_length >> 8) & 255;
    output[3] = total_length & 255;
    // ID
    output[4] = output[5] = 0;
    // FLAGS/OFF
    output[6] = output[7] = 0;
    // TTL
    output[8] = 1;
    // UDP
    output[9] = 17;

    //source ip
    // 本机网口 ip
    // in_addr_t source_ip = addrs[if_index];  
    output[12] = source_ip & 255;
    output[13] = (source_ip >> 8) & 255;
    output[14] = (source_ip >> 16) & 255;
    output[15] = (source_ip >> 24) & 255;
    // output[12] = 0; output[13] = 0; output[14] = 0; output[15] = 0;
    //dest ip
    output[16] = src_addr & 255;
    output[17] = (src_addr >> 8) & 255;
    output[18] = (src_addr >> 16) & 255;
    output[19] = (src_addr >> 24) & 255;
    // ...
    // UDP
    // port = 520
    //source port
    output[20] = 0x02; output[21] = 0x08;
    //dest port
    output[22] = 0x02; output[23] = 0x08;
    //udp_len
    output[24] = (udp_len >> 8) & 255;
    output[25] = udp_len & 255;

    // checksum calculation for ip and udp
    uint16_t ip_checksum = calculateIPChecksum(output, rip_len + 8 + 20);
    output[10] = (ip_checksum >> 8) & 255;
    output[11] = ip_checksum & 255;
    // if you don't want to calculate udp checksum, set it to zero
    uint16_t udp_checksum = 0;
    output[26] = 0; output[27] = 0; 
    udp_checksum = calculateUDPChecksum(output, rip_len + 8 + 20);
}

void print_routing_table(){
  /*
    typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
    uint32_t metric;
    uint32_t timestamp;
  } RoutingTableEntry;
  */
    RoutingTableEntry* routing_table = get_routingtable();
    uint32_t routing_table_len = get_routingtable_len();
    bool* valid_routing_table = get_valid_routing_table();

    for(int i = 0; i < routing_table_len; i++){
      if(!valid_routing_table[i]) continue;
      uint32_t ifad = addrs[routing_table[i].if_index];
      uint32_t addr = routing_table[i].addr;
      printf("%d. dest: %u.%u.%u.%u/%u via %u.%u.%u.%u, metric: %u\n",
        i,
        addr & 255, (addr >> 8) & 255, (addr >> 16) & 255, (addr >> 24) & 255, routing_table[i].len,
        ifad & 255, (ifad >> 8) & 255, (ifad >> 16) & 255, (ifad >> 24) & 255, (routing_table[i].metric >> 24)+1
      );
    }
    printf("\n");
}
