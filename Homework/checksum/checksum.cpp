#include <stdint.h>
#include <stdlib.h>
#include<stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */

uint16_t calculateIPChecksum(uint8_t *packet, size_t len){
    const uint32_t checkpoint = 65536;
    const uint32_t low_checkpoint = 256;
    uint8_t check_high = packet[10];
    uint8_t check_low = packet[11];
    uint16_t checksum = (check_high << 8) + check_low;
    int HEADER_LEN = packet[0] % 16 * 4;
    packet[10] = packet[11] = 0;
    uint32_t sum = 0;
    for(int i = 0 ; i < HEADER_LEN; i += 2){
        uint32_t h = uint32_t(packet[i]) * low_checkpoint;
        uint32_t l = uint32_t(packet[i+1]);
        sum = sum + h + l;
    }
    while(( sum / checkpoint ) > 0){
        uint32_t temp1 = sum % checkpoint;
        uint32_t temp2 = sum / checkpoint;
        sum = temp1 + temp2;
    }
    sum = (~sum) % checkpoint;
    uint32_t low = sum % low_checkpoint;
    uint32_t high = (sum % checkpoint / low_checkpoint) % low_checkpoint;
    uint16_t cal_checksum = (high << 8) + low;
    packet[10] = high;
    packet[11] = low;
    return cal_checksum;
}

bool validateIPChecksum(uint8_t *packet, size_t len) { // [0, 19], [10, 11]
  bool isVaild = false;
  //计算长度
  int header_len = 4 * (packet[0]%16);//前一半：Version...后一半：length...
  //记录正确校验和sum
  uint16_t sum = (packet[10] << 8) + packet[11];
  //将分组头中的校验和区域填充为 0
  packet[10] = 0;  
  packet[11] = 0;
  //求校验和
  uint32_t checksum = 0;  
  uint16_t hi;
  for(int i = 0; i < header_len; i = i+2) {
    checksum = checksum + packet[i+1] + (packet[i] << 8);//将所有 16 比特整数相加
    hi = checksum>>16;
    while(hi) {//如果和发生溢出，循环操作直到不溢出
      checksum = (checksum << 16) >> 16;//截取低位
      checksum = checksum + hi;  //将溢出部分加到低 16 比特
      hi = checksum>>16;
    }
  }
//按位取反
checksum = ((~checksum)<<16)>>16;
//与旧检验和比较并返回
return checksum==sum?true:false;

}

uint16_t calculateUDPChecksum(uint8_t *packet, size_t len){
    const uint32_t checkpoint = 65536;
    const uint32_t low_checkpoint = 256;
    uint32_t packet_len = (packet[2] << 8) + packet[3];
    uint32_t sum = 0;
    
    packet[26] = packet[27] = 0;
    sum += 17;
    sum += (packet[24] << 8) + packet[25];
    for(int i = 12 ; i < packet_len; i += 2){
        uint32_t h = uint32_t(packet[i]) * low_checkpoint;
        uint32_t l = uint32_t(packet[i+1]);
        sum = sum + h + l;
    }

    while(( sum / checkpoint ) > 0){
        uint32_t temp1 = sum % checkpoint;
        uint32_t temp2 = sum / checkpoint;
        sum = temp1 + temp2;
    }
    sum = (~sum) % checkpoint;
    uint32_t low = sum % low_checkpoint;
    uint32_t high = (sum % checkpoint / low_checkpoint) % low_checkpoint;
    uint16_t cal_checksum = (high << 8) + low;
    packet[26] = high;
    packet[27] = low;
    return cal_checksum;
}
