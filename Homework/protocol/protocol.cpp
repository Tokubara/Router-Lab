#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(for response) and 0(for request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系（见上面结构体注释），Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */

uint32_t transfer_to_32_big(const uint8_t *packet, uint32_t start_loc){
    uint32_t result = (uint32_t(packet[start_loc + 3]) << 24) + 
        (uint32_t(packet[start_loc + 2]) << 16) + 
        (uint32_t(packet[start_loc + 1]) << 8) +
        uint32_t(packet[start_loc]); 
    return result;
}

uint32_t transfer_to_32_small(const uint8_t *packet, uint32_t start_loc){
    uint32_t result = uint32_t(packet[start_loc + 3]) + 
        (uint32_t(packet[start_loc + 2]) << 8) + 
        (uint32_t(packet[start_loc + 1]) << 16) +
        (uint32_t(packet[start_loc]) << 24); 
    return result;
}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  uint32_t total_len = (uint32_t(packet[2]) << 8) + uint32_t(packet[3]);
  if(total_len > len)
    return false;
  uint8_t command = packet[28];
  uint8_t version = packet[29];
  if(version != 2) return false;
  if(command != 1 && command != 2) return false;
  uint8_t glb_family = 0;
  if(command == 2) glb_family = 2;

  output->command = command;
  output->numEntries = 0; 
  uint32_t packet_num = (total_len - 32) / 20;
  for(int i = 0 ; i < packet_num; i++){
    uint32_t start_loc = 32 + 20 * i;
    uint32_t family = (uint32_t(packet[start_loc]) << 8) + uint32_t(packet[start_loc + 1]);
    if(family != glb_family) return false;

    uint8_t tag = (uint32_t(packet[start_loc + 2]) << 8) + uint32_t(packet[start_loc + 3]);
    if(tag != 0) return false;

    uint32_t addr = transfer_to_32_big(packet, start_loc + 4);
   
    uint32_t mask = transfer_to_32_big(packet, start_loc + 8);
    uint8_t mask_num = (mask & 1);
    bool mask_flag = false;
    for(int i = 0 ; i < 32; i++){
      uint8_t temp = (mask >> i) & 1;
      if(temp != mask_num && !mask_flag){
        mask_flag = true;
        mask_num = temp;
      }else if(temp != mask_num)
        return false;
    }

    uint32_t next_hop = transfer_to_32_big(packet, start_loc + 12);
    uint32_t metric_sv = transfer_to_32_big(packet, start_loc + 16);
    uint32_t metric = transfer_to_32_small(packet, start_loc + 16);

    if(metric < 1 || metric > 16) return false;

    RipEntry tempEntry = RipEntry();
    tempEntry.addr = addr;
    tempEntry.mask = mask;
    tempEntry.metric = metric_sv;
    tempEntry.nexthop = next_hop;
    output->entities[output->numEntries] = tempEntry;
    output->numEntries += 1;
  }

  
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */

void transfer_to_discrete_8(uint8_t* buffer, uint32_t data, uint32_t start_loc){
    for(int i = 0 ; i < 4 ; i++){
        uint8_t temp = (data >> (i * 8)) & 255;
        buffer[start_loc + i] = temp;
    }
}

void transfer_to_discrete_8_from_small(uint8_t* buffer, uint32_t data, uint32_t start_loc){
    for(int i = 0 ; i < 4 ; i++){
        uint8_t temp = (data >> (i * 8)) & 255;
        buffer[start_loc + 3 - i] = temp;
    }
}

uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  const uint32_t LOW_TRUNC = 255;
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = buffer[3] = 0;
  uint8_t family = 0;
  if(buffer[0] == 2) family = 2;
  for(int i = 0 ; i < rip->numEntries; i++){
      uint32_t start_loc = 4 + i*20;
      buffer[start_loc] = 0;
      buffer[start_loc + 1] = family;
      buffer[start_loc + 2] = buffer[start_loc + 3] = 0;
      transfer_to_discrete_8(buffer, rip->entities[i].addr, start_loc + 4);
      transfer_to_discrete_8(buffer, rip->entities[i].mask, start_loc + 8);
      transfer_to_discrete_8(buffer, rip->entities[i].nexthop, start_loc + 12);
      transfer_to_discrete_8(buffer, rip->entities[i].metric, start_loc + 16);
  }
  return 4 + 20 * rip->numEntries;
}
