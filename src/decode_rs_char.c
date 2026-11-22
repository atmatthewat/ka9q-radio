// From Phil Karn's libfec, https://github.com/ka9q/libfec at commit 7c6706fb969c3f8fe6ec7778b2472762e0d88acc
// (2022-09-04), the Reed-Solomon codec used by rs63.c; unchanged below this note
/* General purpose Reed-Solomon decoder for 8-bit symbols or less
 * Copyright 2003 Phil Karn, KA9Q
 * May be used under the terms of the GNU Lesser General Public License (LGPL)
 */

#ifdef DEBUG
#include <stdio.h>
#endif

#include <string.h>

#include "char.h"
#include "rs-common.h"

int decode_rs_char(void *p, data_t *data, int *eras_pos, int no_eras){
  int retval;
  struct rs *rs = (struct rs *)p;
 
#include "decode_rs.h"
  
  return retval;
}
