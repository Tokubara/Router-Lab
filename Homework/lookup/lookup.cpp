// #include "router.h"
// #include <stdint.h>
// #include <stdlib.h>
// #include <stdio.h>



// const int ENTRY_NUM = 10000;
// RoutingTableEntry entry_array[ENTRY_NUM];
// bool location_indication[ENTRY_NUM];
// uint32_t current_len = 0;

// uint32_t ip_match(uint32_t s_ip, uint32_t m_ip, uint32_t pre_len);

// RoutingTableEntry* get_routingtable(){ return entry_array; }
// uint32_t get_routingtable_len(){ return current_len; }
// bool* get_valid_routing_table(){ return location_indication; }


// bool in_same_net(uint32_t addr1, uint32_t mask1, uint32_t addr2, uint32_t mask2){
//   uint32_t net1 = addr1 & mask1;
//   uint32_t net2 = addr2 & mask2;
//   return net1 == net2;
// }
// /*
//   RoutingTable Entry 的定义如下：
//   typedef struct {
//     uint32_t addr; // 大端序，IPv4 地址
//     uint32_t len; // 小端序，前缀长度
//     uint32_t if_index; // 小端序，出端口编号
//     uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
//     uint32_t metric;
//     uint32_t timestamp;
//   } RoutingTableEntry;

//   约定 addr 和 nexthop 以 **大端序** 存储。
//   这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
//   保证 addr 仅最低 len 位可能出现非零。
//   当 nexthop 为零时这是一条直连路由。
//   你可以在全局变量中把路由表以一定的数据结构格式保存下来。
// */

// /**
//  * @brief 插入/删除一条路由表表项
//  * @param insert 如果要插入则为 true ，要删除则为 false
//  * @param entry 要插入/删除的表项
//  * 
//  * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
//  * 删除时按照 addr 和 len 匹配。
//  */
// bool update(bool insert, RoutingTableEntry entry) {
//   // TODO:
//   int index = current_len;
//   if(insert){
//     bool insert_flag = false;
//     for(int i = 0 ; i < current_len; i++){
//       if(location_indication[i] == true && entry.addr == entry_array[i].addr && entry.len == entry_array[i].len){
//         // find matching routing
//         // update when: 1. from the same source net ; 2. from different source net and smaller metric
//         // metric + 1
//         uint32_t metric_sv = (entry.metric >> 24) & 255;
//         uint32_t table_metric = (entry_array[i].metric >> 24) & 255;
//         if(table_metric == 0) return false;
//         if(entry.if_index != entry_array[i].if_index && metric_sv >= table_metric) return false;
//         entry_array[i] = entry;
//         // entry_array[i].metric += (1 << 24);
//         location_indication[i] = true;
//         insert_flag = true;
//       }
//     }
//     if(!insert_flag){
//       for(int i = 0 ; i < current_len; i++){
//         if(location_indication[i] == false){
//           index = i;
//           break;
//         }
//       }
//       location_indication[index] = true;
//       entry_array[index] = entry;
//       if(index >= current_len) current_len += 1;
//       uint32_t add = entry.addr;
//       printf("add a entry: %u.%u.%u.%u,  len: %u \n", add & 255, (add>>8)&255, (add>>16)&255, (add>>24)&&255, entry.len);
//     }
//   }else{
//     for(int i = 0; i < current_len; i++){
//       if(location_indication[i] == true && entry_array[i].addr == entry.addr && entry_array[i].len == entry.len){
//         location_indication[i] = false;
//       }
//     }
//   }
//   return true;
// }

// /**
//  * @brief 进行一次路由表的查询，按照最长前缀匹配原则
//  * @param addr 需要查询的目标地址，大端序
//  * @param nexthop 如果查询到目标，把表项的 nexthop 写入
//  * @param if_index 如果查询到目标，把表项的 if_index 写入
//  * @return 查到则返回 true ，没查到则返回 false
//  */
// bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
//   // TODO:
//   bool match_flag = false;
//   uint32_t max_macth_len = 0;
//   for(int i = 0 ; i < current_len; i++){
//     if(location_indication[i]){
//       uint32_t temp_len = ip_match(addr, entry_array[i].addr, entry_array[i].len);
//       if(temp_len > 0){
//         match_flag = true;
//         if(temp_len > max_macth_len){
//           *nexthop = entry_array[i].nexthop;
//           *if_index = entry_array[i].if_index;
//         }
//       }

//     }
//   }
//   return match_flag;
// }

// uint32_t ip_match(uint32_t s_ip, uint32_t m_ip, uint32_t pre_len){
//   uint64_t temp = 1;
//   const uint32_t tool = 255;
//   uint32_t len = 0;
//   for(int i = 0 ; i < pre_len; i++) temp = temp * 2;
//   temp = temp - 1;
//   if((s_ip & temp) == (m_ip & temp)){
//     for(int k = 0 ; k < 4; k++){
//       uint32_t temp1 = s_ip & tool;
//       uint32_t temp2 = m_ip & tool;
//       if(temp1 == temp2) {
//         len += 8;
//       }else{
//         for(int pre = 0 ; pre < 8 ; pre++){
//           if((temp1 >> pre) == (temp2 >> pre)){
//             len += 8 - pre;
//             break;
//           }
//         }
//         break;
//       }
//       s_ip = s_ip >> 8;
//       m_ip = m_ip >> 8;
//     }
//     return len;
//   }else{
//     return 0;
//   }
// }




#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <bitset>
#include <arpa/inet.h>
using namespace std;




/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

typedef vector<RoutingTableEntry> Data;
Data data;

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
 //路由表的更新
void update(bool insert, RoutingTableEntry entry) {
  //记录数据
  uint32_t dst_addr = entry.addr;
  uint32_t dst_len = entry.len;
  uint32_t src_addr,src_len;
  if(insert){//插入
    for(auto &i :data){
      src_addr = i.addr;
      src_len = i.len;
      if(dst_addr == src_addr && dst_len == src_len)
        return;
    }
    data.push_back(entry);
  }
  else{//删除
    int count =0;
    for(Data::iterator i = data.begin(); i != data.end(); i++){
      src_addr = data[count].addr;
      src_len = data[count].len;
      if(dst_addr == src_addr && dst_len == src_len){
        data.erase(i);
        break;
      }
        count++;
    }
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */

//判断能否匹配
//都是大端，方便
bool judge(uint32_t dst_addr, uint32_t src_addr, uint32_t src_len){
  bitset<32> com(dst_addr^src_addr);
  for(auto i=0;i<src_len;i++){
    if(com[i]){
      return false;
    }
  }
return true;
}

 //路由表的查询
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  uint32_t dst_addr = addr;
  uint32_t src_addr,src_len,max = 0;
  int count =0;
  for(Data::iterator i = data.begin(); i != data.end(); i++){
    src_addr = data[count].addr;
    src_len = data[count].len;
    //判断能否匹配
    if(judge(dst_addr,src_addr,src_len)){
      if(src_len>max){
        max = src_len; 
        *nexthop = data[count].nexthop;
        *if_index = data[count].if_index;
      }
    }
    count++;
  }
  if(max) return true;
  else return false;
}



