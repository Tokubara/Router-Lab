#include <stdint.h>

// 路由表的一项
typedef struct {
    uint32_t addr; // 地址
    uint32_t len; // 前缀长度
    uint32_t if_index; // 出端口编号
    uint32_t nexthop; // 下一条的地址，0 表示直连
    uint32_t mask; // 来自 rip
    uint32_t metric; // 路由表一项的metric,
    uint32_t timestamp; // 暂未用到
    uint32_t entry_from;
    // 为了实现 RIP 协议，需要在这里添加额外的字段
} RoutingTableEntry;


RoutingTableEntry* get_routingtable();
uint32_t get_routingtable_len();
bool* get_valid_routing_table();
bool in_same_net(uint32_t addr1, uint32_t mask1, uint32_t addr2, uint32_t mask2);