// DMR sync words and the burst initialiser (see dmr.h)
// Copyright 2026, Matthew Kaufman, KA6SQG
#include <string.h>

#include "dmr.h"

// TS 102 361-1 table 9.2, values as sdrtrunk's DMRSyncPattern.java (GPL-3, Dennis Sheirer,
// github.com/DSheirer/sdrtrunk)
uint64_t const Dmr_sync_words[DMR_SYNC_PATTERNS] = {
  0x755FD7DF75F7ULL, // BS voice
  0xDFF57D75DF5DULL, // BS data
  0x7F7D5DD57DFDULL, // MS voice
  0xD5D7F77FD757ULL, // MS data
  0x77D55F7DFD77ULL, // MS reverse channel
  0x5D577F7757FFULL, // direct voice TS1
  0xF7FDD5DDFD55ULL, // direct data TS1
  0x7DFFD5F55D5FULL, // direct voice TS2
  0xD7557F5FF7F5ULL, // direct data TS2
  0xDD7FF5D757DDULL, // reserved
};

void dmr_burst_init(struct dmr_burst *b){
  memset(b,0,sizeof *b);
  b->sync = DMR_SYNC_NONE;
  b->kind = DMR_KIND_DATA;
  b->confirmed = true;
  b->data_type = DMR_DT_RESERVED15;
}
