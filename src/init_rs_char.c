// From Phil Karn's libfec, https://github.com/ka9q/libfec at commit 7c6706fb969c3f8fe6ec7778b2472762e0d88acc
// (2022-09-04), the Reed-Solomon codec used by rs63.c; unchanged below this note
/* Initialize a RS codec
 *
 * Copyright 2002 Phil Karn, KA9Q
 * May be used under the terms of the GNU Lesser General Public License (LGPL)
 */
#include <stdlib.h>

#include "char.h"
#include "rs-common.h"

void free_rs_char(void *p){
  struct rs *rs = (struct rs *)p;

  free(rs->alpha_to);
  free(rs->index_of);
  free(rs->genpoly);
  free(rs);
}

/* Initialize a Reed-Solomon codec
 * symsize = symbol size, bits
 * gfpoly = Field generator polynomial coefficients
 * fcr = first root of RS code generator polynomial, index form
 * prim = primitive element to generate polynomial roots
 * nroots = RS code generator polynomial degree (number of roots)
 * pad = padding bytes at front of shortened block
 */
void *init_rs_char(int symsize,int gfpoly,int fcr,int prim,
	int nroots,int pad){
  struct rs *rs;

#include "init_rs.h"

  return rs;
}
