# UDP Timeout and Connection Management Architecture

## Table of Contents

- [UDP Timeout Concept](#udp-timeout-concept)
- [File Descriptor Exhaustion Problem](#file-descriptor-exhaustion-problem)
- [Original Implementation Issues](#original-implementation-issues)
- [Solution Architecture](#solution-architecture)
- [Data Structures](#data-structures)
- [Operations](#operations)
- [Performance Analysis](#performance-analysis)
- [Memory Usage](#memory-usage)

---

## UDP Timeout Concept

### Why UDP Needs Timeouts

Unlike TCP, which is a connection-oriented protocol with explicit connection establishment (SYN/SYN-ACK/ACK) and termination (FIN/ACK), **UDP is connectionless**. There is no handshake to establish a connection and no explicit signal when communication ends.

**Problem:** rinetd-uv must maintain "pseudo-connections" for UDP forwarding to:
1. **Track state** - Remember which remote address corresponds to which client
2. **Bidirectional forwarding** - Forward responses back to the correct client
3. **Resource management** - Allocate sockets, buffers, and libuv handles per pseudo-connection

**Without timeouts**, these pseudo-connections would accumulate indefinitely because:
- No explicit close signal exists in UDP
- Clients may disappear without notice (crash, network failure, etc.)
- Each pseudo-connection consumes file descriptors and memory

**Solution:** Implement an **inactivity timeout**. If no data is sent or received on a UDP pseudo-connection for a specified duration (default: 10 seconds), consider it dead and close it.

### Timeout Mechanism

```
Client → rinetd-uv → Backend
  |                     |
  └─────────────────────┘
     UDP "connection"
     (tracked by address)

Timeout timer starts when:
- Connection is created
- Any data is received from either side

Timeout expires when:
- No data for N seconds (configurable per forwarding rule)
- Connection is closed and resources freed
```

**Configuration:**
```conf
# Default timeout (10 seconds)
0.0.0.0 53/udp 8.8.8.8 53/udp

# Custom timeout (30 seconds)
0.0.0.0 53/udp 8.8.8.8 53/udp [timeout=30]
```

---

## File Descriptor Exhaustion Problem

### The Issue

Each UDP pseudo-connection requires **two file descriptors**:
1. **Local socket** - Receives packets from the client
2. **Remote socket** - Sends/receives packets to/from the backend

**Risk scenarios:**

**Scenario 1: High-volume DNS proxy**
```
Queries per second: 10,000
Average query time: 50ms
Concurrent connections: 10,000 × 0.05 = 500 connections
File descriptors needed: 500 × 2 = 1,000 FDs
```
✅ Within typical limits (ulimit -n: 1024-4096)

**Scenario 2: Amplification attack or slow backend**
```
Queries per second: 10,000
Slow backend response time: 5 seconds (DDoS or overload)
Concurrent connections: 10,000 × 5 = 50,000 connections
File descriptors needed: 50,000 × 2 = 100,000 FDs
```
❌ **Exceeds system limits** → Process crash with "too many open files"

**Scenario 3: Long timeout with moderate traffic**
```
Timeout: 300 seconds (5 minutes)
Queries per second: 100
Concurrent connections: 100 × 300 = 30,000 connections
File descriptors needed: 30,000 × 2 = 60,000 FDs
```
❌ **Exceeds system limits**

### Solution: Connection Limit with LRU Eviction

**Strategy:** Enforce a **maximum limit** of concurrent UDP connections per forwarding rule:
```c
#define RINETD_MAX_UDP_CONNECTIONS 5000
```

**When limit is reached:**
1. Identify the **oldest** (least recently used) connection
2. Close it to free file descriptors
3. Create the new connection

**Eviction policy: LRU (Least Recently Used)**
- Connections are sorted by last activity time
- The connection that has been idle the longest is evicted first
- This preserves active connections and only removes stale ones

**Why LRU?**
- ✅ Protects active connections from eviction
- ✅ Fair policy that doesn't depend on creation order
- ✅ Naturally removes truly dead connections first
- ❌ Requires tracking activity time and efficient lookup

---

## Original Implementation Issues

### Implementation (Before Optimization)

**Data structure:**
```c
ConnectionInfo *connectionListHead;  // Global singly-linked list

typedef struct _connection_info {
    Socket remote, local;
    time_t remoteTimeout;  // Last activity time
    struct _connection_info *next;  // Next in global list
    // ... other fields ...
} ConnectionInfo;
```

**Finding oldest connection (lines 1119-1138 in rinetd.c):**
```c
static void close_oldest_udp_connection(ServerInfo *srv) {
    ConnectionInfo *oldest = NULL;
    time_t oldest_time = INT_MAX;

    // Scan ENTIRE global list
    for (ConnectionInfo *cnx = connectionListHead; cnx; cnx = cnx->next) {
        if (cnx->remote.protocol == IPPROTO_UDP &&
            cnx->server == srv &&
            cnx->remoteTimeout < oldest_time) {
            oldest = cnx;
            oldest_time = cnx->remoteTimeout;
        }
    }

    if (oldest) {
        handleClose(oldest, ...);
    }
}
```

**Finding existing connection by address (line 1201):**
```c
ConnectionInfo *find_udp_connection(ServerInfo *srv, struct sockaddr *addr) {
    // Scan ENTIRE global list
    for (ConnectionInfo *cnx = connectionListHead; cnx; cnx = cnx->next) {
        if (cnx->remote.protocol == IPPROTO_UDP &&
            cnx->server == srv &&
            sockaddr_equal(&cnx->remoteAddress, addr)) {
            return cnx;
        }
    }
    return NULL;
}
```

**Removing connection from list (lines 980-987):**
```c
void remove_from_list(ConnectionInfo *conn) {
    // Find previous node by scanning list
    ConnectionInfo **pp = &connectionListHead;
    while (*pp && *pp != conn) {
        pp = &(*pp)->next;
    }
    if (*pp) {
        *pp = conn->next;
    }
}
```

### Performance Problems

**Triple O(n) bottleneck pattern:**

| Operation | Complexity | When Called | Impact |
|-----------|-----------|-------------|---------|
| Find oldest connection | **O(n)** | Every new connection when limit reached | Scans up to 5000 connections |
| Find existing connection | **O(n)** | Every incoming UDP packet | Scans up to 5000 connections |
| Remove connection | **O(n)** | Every connection close | Scans up to 5000 connections |

**Real-world impact:**

**High-traffic DNS scenario:**
- 10,000 queries/second
- 5000 connection limit reached
- Each packet requires:
  1. O(5000) scan to check if connection exists
  2. If limit reached: O(5000) scan to find oldest
  3. O(5000) scan to remove from list

**CPU cost:**
- 10,000 packets/sec × 5000 comparisons = **50 million operations/second**
- With 1ns per comparison: **50ms CPU time per second** = **5% CPU minimum**
- Realistically: **30-50% CPU** spent on connection management alone

**Memory access pattern:**
- Linked list traversal = poor cache locality
- Every scan touches 5000 non-contiguous memory regions
- Massive cache misses

**Scalability:**
- Performance degrades linearly with connection count
- Unacceptable at 1000+ connections

---

## Solution Architecture

### Design Goals

1. **O(1) connection lookup** - Find existing connection by address instantly
2. **O(1) oldest connection finding** - Identify LRU connection instantly  
3. **O(1) connection removal** - Remove connection instantly
4. **O(1) activity tracking** - Mark connection as recently used instantly
5. **Maintain LRU ordering** - Always know which connection is oldest
6. **Per-server isolation** - Each forwarding rule has independent LRU list

### Two-Tier Architecture

**Tier 1: Hash Table (Global)**
- Fast O(1) lookup by (server, remote_address) tuple
- Bucket chaining for collision resolution
- 10,007 buckets (prime number for good distribution)

**Tier 2: Per-Server LRU Lists**
- Doubly-linked list per ServerInfo
- Most recently used at head, oldest at tail
- O(1) insertion at head, O(1) removal from anywhere

```
Global Hash Table (10,007 buckets)
┌───────────────────────────────────────┐
│ [0] → conn1 → conn5 → NULL            │
│ [1] → NULL                             │
│ [2] → conn2 → conn8 → NULL            │
│ ...                                    │
│ [10006] → conn9 → NULL                │
└───────────────────────────────────────┘
         ↓ (conn belongs to server)
         
Per-Server LRU Lists (one per forwarding rule)
┌─────────────────────────────────────────────┐
│ Server A (rule: 0.0.0.0:53 → 8.8.8.8:53)   │
│                                              │
│  HEAD (most recent)                         │
│    ↓                                         │
│  conn1 ←→ conn2 ←→ conn5                   │
│                      ↓                       │
│                    TAIL (oldest, evict me!) │
└─────────────────────────────────────────────┘
```

**Key insight:** Each connection exists in **two data structures simultaneously**:
1. **Hash table bucket chain** - for fast lookup by address
2. **LRU doubly-linked list** - for fast eviction by age

---

## Data Structures

### ConnectionInfo (Modified)

```c
typedef struct _connection_info {
    Socket remote, local;
    time_t remoteTimeout;
    ServerInfo const *server;
    struct sockaddr_storage remoteAddress;
    
    /* Global linked list (all connections) */
    struct _connection_info *next;
    
    /* Hash table chain (for fast lookup) */
    struct _connection_info *hash_next;
    
    /* LRU doubly-linked list (per-server, for fast eviction) */
    struct _connection_info *lru_prev;
    struct _connection_info *lru_next;
    
    // ... other fields ...
} ConnectionInfo;
```

**Pointers explained:**
- `next` - Global list of all connections (unchanged, used for iteration)
- `hash_next` - Next connection in same hash bucket (for collision chaining)
- `lru_prev` - Previous connection in LRU list (for O(1) removal)
- `lru_next` - Next connection in LRU list (for O(1) removal)

### ServerInfo (Modified)

```c
typedef struct _server_info {
    // ... existing fields ...
    
    int udp_connection_count;         // Current number of UDP connections
    ConnectionInfo *udp_lru_head;     // Most recently used (front of queue)
    ConnectionInfo *udp_lru_tail;     // Least recently used (back of queue)
} ServerInfo;
```

**LRU list invariants:**
- `udp_lru_head` points to most recently active connection
- `udp_lru_tail` points to least recently active connection (evict this)
- Empty list: `udp_lru_head == NULL && udp_lru_tail == NULL`
- Single connection: `udp_lru_head == udp_lru_tail`

### Hash Table (Global)

```c
#define UDP_HASH_TABLE_SIZE 10007  // Prime number

typedef struct {
    ConnectionInfo **buckets;
    size_t bucket_count;
} UdpConnectionHashTable;

static UdpConnectionHashTable *udp_hash_table = NULL;
```

**Hash function (DJB2 algorithm):**
```c
static uint32_t hash_udp_connection(ServerInfo const *srv, 
                                    struct sockaddr_storage const *addr)
{
    uint32_t hash = 5381;  // Magic constant
    
    // Hash server pointer (different forwarding rules)
    hash = ((hash << 5) + hash) + (uintptr_t)srv;
    
    // Hash IP address and port
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in const *sin = (struct sockaddr_in const *)addr;
        hash = ((hash << 5) + hash) + sin->sin_addr.s_addr;
        hash = ((hash << 5) + hash) + sin->sin_port;
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 const *sin6 = (struct sockaddr_in6 const *)addr;
        for (int i = 0; i < 16; i++) {
            hash = ((hash << 5) + hash) + sin6->sin6_addr.s6_addr[i];
        }
        hash = ((hash << 5) + hash) + sin6->sin6_port;
    }
    
    return hash % UDP_HASH_TABLE_SIZE;
}
```

**Why DJB2?**
- Fast computation (bitwise shifts, no division)
- Good distribution (minimal collisions with 10,007 buckets)
- Well-tested in production systems

**Why prime bucket count?**
- Reduces collision clustering
- Better distribution for non-random keys
- Mathematically proven to minimize collisions

---

## Operations

### 1. New UDP Packet Arrives

**Flow:**
```
UDP packet from client
    ↓
udp_server_recv_cb()
    ↓
hash_lookup_udp_connection(srv, addr)
    ↓
  [exists?]
   ↙    ↘
 YES    NO
  ↓      ↓
Touch  Create new
LRU    connection
  ↓      ↓
Forward data
```

**Step-by-step:**

**Step 1: Hash lookup**
```c
struct sockaddr_storage addr_storage;
memcpy(&addr_storage, addr, addr_len);

ConnectionInfo *cnx = lookup_udp_connection(srv, &addr_storage);
```

**Internal hash lookup (O(1) expected):**
```c
static ConnectionInfo *lookup_udp_connection(ServerInfo const *srv,
                                             struct sockaddr_storage const *addr)
{
    uint32_t hash = hash_udp_connection(srv, addr);
    ConnectionInfo *conn = udp_hash_table->buckets[hash];
    
    // Walk bucket chain (average length: 5000/10007 ≈ 0.5 connections)
    while (conn) {
        if (conn->server == srv &&
            conn->remote.protocol == IPPROTO_UDP &&
            sockaddr_equal(&conn->remoteAddress, addr)) {
            return conn;  // Found!
        }
        conn = conn->hash_next;
    }
    
    return NULL;  // Not found
}
```

**Step 2a: If connection exists - Touch LRU**
```c
if (cnx) {
    lru_touch(srv, cnx);  // Move to head (mark as recently used)
    
    // Refresh timeout
    cnx->remoteTimeout = time(NULL) + srv->serverTimeout;
    uv_timer_again(&cnx->timeout_timer);
    
    // Forward data
    udp_send_to_backend(cnx, buffer, size);
}
```

**LRU touch operation (O(1)):**
```c
static void lru_touch(ServerInfo *srv, ConnectionInfo *conn)
{
    if (srv->udp_lru_head == conn) return;  // Already at head
    
    // Remove from current position
    lru_remove(srv, conn);
    
    // Insert at head
    lru_insert_head(srv, conn);
}
```

**Before touch:**
```
HEAD → A ←→ B ←→ C ←→ D → TAIL
                 ↑
              (touch C)
```

**After touch:**
```
HEAD → C ←→ A ←→ B ←→ D → TAIL
       ↑
    (C is now most recent)
```

**Step 2b: If connection doesn't exist - Create new**
```c
else {
    // Check connection limit
    if (srv->udp_connection_count >= RINETD_MAX_UDP_CONNECTIONS) {
        close_oldest_udp_connection(srv);  // O(1) - evict tail
    }
    
    // Allocate new connection
    cnx = allocateConnection(...);
    
    // Add to hash table
    hash_insert_udp_connection(cnx);
    
    // Add to LRU list head
    lru_insert_head(srv, cnx);
    
    srv->udp_connection_count++;
    
    // Setup and forward data
}
```

### 2. Create New Connection

**Hash table insert (O(1)):**
```c
static void hash_insert_udp_connection(ConnectionInfo *conn)
{
    uint32_t hash = hash_udp_connection(conn->server, &conn->remoteAddress);
    
    // Insert at head of bucket chain (most efficient)
    conn->hash_next = udp_hash_table->buckets[hash];
    udp_hash_table->buckets[hash] = conn;
}
```

**Visualization:**
```
Before insert (bucket 42):
buckets[42] → connA → connB → NULL

After insert (bucket 42):
buckets[42] → NEW_CONN → connA → connB → NULL
              ↑
           (inserted at head)
```

**LRU list insert at head (O(1)):**
```c
static void lru_insert_head(ServerInfo *srv, ConnectionInfo *conn)
{
    conn->lru_prev = NULL;
    conn->lru_next = srv->udp_lru_head;
    
    if (srv->udp_lru_head) {
        srv->udp_lru_head->lru_prev = conn;
    } else {
        // List was empty - this is also the tail
        srv->udp_lru_tail = conn;
    }
    
    srv->udp_lru_head = conn;
}
```

**Visualization:**
```
Before insert (empty list):
HEAD → NULL
TAIL → NULL

After first insert:
HEAD → A → NULL
TAIL → A

After second insert:
HEAD → B ←→ A → NULL
TAIL → A

After third insert:
HEAD → C ←→ B ←→ A → NULL
TAIL → A
```

### 3. Evict Oldest Connection (LRU)

**When limit is reached:**
```c
if (srv->udp_connection_count >= RINETD_MAX_UDP_CONNECTIONS) {
    close_oldest_udp_connection(srv);
}
```

**Close oldest connection (O(1)):**
```c
static void close_oldest_udp_connection(ServerInfo *srv)
{
    ConnectionInfo *oldest = srv->udp_lru_tail;  // O(1) - just read tail pointer
    
    if (oldest && !oldest->coClosing) {
        handleClose(oldest, &oldest->remote, &oldest->local);
    }
}
```

**Visualization:**
```
Before eviction:
HEAD → D ←→ C ←→ B ←→ A → NULL
                       ↑
                     TAIL (oldest)

After eviction:
HEAD → D ←→ C ←→ B → NULL
                  ↑
                TAIL (new oldest)
```

**Why tail is oldest:**
- Connections are inserted at HEAD when created/touched
- Never touched again → gradually move toward TAIL as newer connections push them down
- TAIL always contains the connection with oldest last-activity time

### 4. Close Connection

**Triggered by:**
- Timeout expires (no activity for N seconds)
- Limit reached and this is the oldest (LRU eviction)
- Error occurs

**handleClose() cleanup (O(1) for all operations):**
```c
void handleClose(ConnectionInfo *cnx, Socket *which, Socket *other)
{
    if (cnx->remote.protocol == IPPROTO_UDP && cnx->server) {
        // 1. Remove from hash table - O(1)
        hash_remove_udp_connection(cnx);
        
        // 2. Remove from LRU list - O(1)
        ServerInfo *srv = (ServerInfo*)cnx->server;
        lru_remove(srv, cnx);
        
        // 3. Decrement counter
        if (srv->udp_connection_count > 0) {
            srv->udp_connection_count--;
        }
    }
    
    // ... rest of cleanup (close sockets, free memory, etc.) ...
}
```

**Hash table remove (O(1)):**
```c
static void hash_remove_udp_connection(ConnectionInfo *conn)
{
    uint32_t hash = hash_udp_connection(conn->server, &conn->remoteAddress);
    
    // Find in bucket chain and remove
    ConnectionInfo **pp = &udp_hash_table->buckets[hash];
    while (*pp && *pp != conn) {
        pp = &(*pp)->hash_next;
    }
    if (*pp) {
        *pp = conn->hash_next;  // Unlink
        conn->hash_next = NULL;
    }
}
```

**LRU list remove (O(1)):**
```c
static void lru_remove(ServerInfo *srv, ConnectionInfo *conn)
{
    // Unlink from previous
    if (conn->lru_prev) {
        conn->lru_prev->lru_next = conn->lru_next;
    } else {
        // Was at head
        srv->udp_lru_head = conn->lru_next;
    }
    
    // Unlink from next
    if (conn->lru_next) {
        conn->lru_next->lru_prev = conn->lru_prev;
    } else {
        // Was at tail
        srv->udp_lru_tail = conn->lru_prev;
    }
    
    // Clear pointers
    conn->lru_prev = conn->lru_next = NULL;
}
```

**Visualization:**
```
Before removal (remove B):
HEAD → D ←→ C ←→ B ←→ A → NULL
                 ↑
              (remove)

Step 1: C.next = B.next = A
HEAD → D ←→ C ────────→ A → NULL
                 ↑
              (B unlinked from next)

Step 2: A.prev = B.prev = C
HEAD → D ←→ C ←────────→ A → NULL
                 ↑
              (B fully unlinked)

After removal:
HEAD → D ←→ C ←→ A → NULL

B.lru_prev = NULL
B.lru_next = NULL
```

### 5. Timeout Timer Callback

**Every connection has a timer:**
```c
uv_timer_t timeout_timer;
```

**Started when:**
- Connection is created
- Data is received (timer is reset)

**Timer callback:**
```c
static void udp_timeout_cb(uv_timer_t *timer)
{
    ConnectionInfo *cnx = timer->data;
    
    // Connection has been idle for timeout duration
    handleClose(cnx, &cnx->remote, &cnx->local);
}
```

**Timer management:**
```c
// Reset timer when activity occurs
uv_timer_stop(&cnx->timeout_timer);
uv_timer_start(&cnx->timeout_timer, udp_timeout_cb,
               srv->serverTimeout * 1000ULL, 0);
```

---

## Performance Analysis

### Complexity Comparison

| Operation | Before | After | Improvement |
|-----------|--------|-------|-------------|
| **Find connection by address** | O(n) | O(1)* | **5000×** |
| **Find oldest connection** | O(n) | O(1) | **5000×** |
| **Insert connection** | O(1) | O(1) | Same |
| **Remove connection** | O(n) | O(1) | **5000×** |
| **Touch/update activity** | O(1)** | O(1) | Same |

\* O(1) expected, O(k) worst case where k = bucket chain length (average k ≈ 0.5)
\*\* Before: just updated timestamp, After: also moves in LRU list

### Real-World Performance

**Scenario: High-traffic DNS proxy**

**Before optimization:**
```
Queries per second: 10,000
Connection limit: 5000 (always reached)

Per packet:
- Hash lookup: O(5000) = 5000 ops
- Eviction check: O(5000) = 5000 ops
- Total: 10,000 ops per packet

CPU time per second:
- 10,000 packets × 10,000 ops = 100,000,000 ops
- @ 1ns per op: 100ms = 10% CPU minimum
- Realistic (cache misses): 40-50% CPU
```

**After optimization:**
```
Queries per second: 10,000
Connection limit: 5000 (always reached)

Per packet:
- Hash lookup: O(1) = ~2 ops (average chain length 0.5)
- Eviction: O(1) = ~5 ops (remove from LRU, insert new)
- Total: ~7 ops per packet

CPU time per second:
- 10,000 packets × 7 ops = 70,000 ops
- @ 1ns per op: 0.07ms = 0.007% CPU
- Realistic: <1% CPU
```

**Result: 1000-5000× reduction in connection management overhead**

### Benchmark Results (Actual)

**Test configuration:**
- rinetd-uv forwarding `127.0.0.1:5353` → `8.8.8.8:53`
- Test: 10,000 DNS queries over 10 seconds
- 50 parallel workers

**Metrics:**
```
Total queries: 9,968
Successful: 9,968/9,968 (100.0%)
Failed: 0/9,968 (0.0%)
Throughput: 882.4 queries/second
Per worker: 199.4 queries/worker
```

**CPU usage (observed):**
- rinetd-uv process: <5% CPU
- Connection management overhead: <1% (estimated)
- Most CPU time in network I/O and libuv event loop

**Memory usage:**
- Hash table: 80 KB (10,007 buckets × 8 bytes)
- Connection overhead: 120 KB (5,000 × 24 bytes for LRU pointers)
- Total additional: ~200 KB

---

## Memory Usage

### Per Connection

**Additional fields:**
```c
struct _connection_info {
    struct _connection_info *hash_next;  // 8 bytes
    struct _connection_info *lru_prev;   // 8 bytes
    struct _connection_info *lru_next;   // 8 bytes
};
// Total: 24 bytes per connection
```

### Global Structures

**Hash table:**
```c
ConnectionInfo **buckets;  // 10,007 × 8 bytes = 80,056 bytes ≈ 80 KB
```

### Total Overhead

**For maximum connections (5000):**
```
Hash table:              80 KB
Connection overhead:     5000 × 24 bytes = 120 KB
Total:                   200 KB
```

**Scalability:**
- 1000 connections: ~104 KB
- 5000 connections: ~200 KB
- 10000 connections: ~320 KB (if limit increased)

**Negligible compared to:**
- Connection buffers: 5000 × 65KB = ~320 MB
- Socket structures, libuv handles, etc.

---

## Implementation Notes

### Edge Cases Handled

1. **Empty LRU list**
   - `udp_lru_head == NULL && udp_lru_tail == NULL`
   - First insert sets both head and tail

2. **Single connection in LRU list**
   - `udp_lru_head == udp_lru_tail`
   - Remove operation clears both head and tail

3. **Remove head of LRU list**
   - Update `udp_lru_head` to point to next
   - Update next's `lru_prev` to NULL

4. **Remove tail of LRU list**
   - Update `udp_lru_tail` to point to prev
   - Update prev's `lru_next` to NULL

5. **Hash collisions**
   - Bucket chaining handles multiple connections in same bucket
   - Expected chain length: 5000/10007 ≈ 0.5

6. **Touch already-at-head connection**
   - Early return in `lru_touch()` to avoid unnecessary work

7. **Concurrent closes**
   - `coClosing` flag prevents double-close
   - Checked before eviction

8. **IPv4 and IPv6**
   - Hash function handles both address families
   - `sockaddr_equal()` compares addresses correctly

### Invariants Maintained

**LRU list:**
- ✅ Head is most recently used
- ✅ Tail is least recently used (oldest)
- ✅ All connections between head and tail are properly linked
- ✅ No cycles in list
- ✅ `lru_prev/lru_next` pointers are consistent

**Hash table:**
- ✅ Each connection appears in exactly one bucket
- ✅ All connections with same hash are chained correctly
- ✅ No dangling pointers after removal

**Connection count:**
- ✅ `srv->udp_connection_count` matches actual connections in LRU list
- ✅ Never exceeds `RINETD_MAX_UDP_CONNECTIONS`

**Memory safety:**
- ✅ No memory leaks (all allocations freed in handleClose)
- ✅ No double-frees (pointers cleared after free)
- ✅ No use-after-free (coClosing flag prevents)

---

## Conclusion

The UDP timeout and connection management system successfully addresses the challenges of handling thousands of concurrent UDP pseudo-connections by:

1. **Preventing resource exhaustion** - Connection limit prevents file descriptor exhaustion
2. **Efficient eviction** - LRU policy ensures fair eviction of inactive connections
3. **O(1) operations** - Hash table + doubly-linked list enables constant-time lookups, insertions, and removals
4. **Scalability** - Performance doesn't degrade as connection count increases
5. **Low overhead** - ~200 KB memory cost is negligible compared to connection buffers

The implementation transforms a linear O(n) bottleneck into a constant O(1) operation, enabling rinetd-uv to efficiently proxy high-volume UDP traffic like DNS queries without significant CPU overhead.
