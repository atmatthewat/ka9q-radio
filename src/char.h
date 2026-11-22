// From Phil Karn's libfec, https://github.com/ka9q/libfec at commit 7c6706fb969c3f8fe6ec7778b2472762e0d88acc
// (2022-09-04), the Reed-Solomon codec used by rs63.c; unchanged below this note
/* Stuff specific to the 8-bit symbol version of the general purpose RS codecs
 *
 * Copyright 2003, Phil Karn, KA9Q
 * May be used under the terms of the GNU Lesser General Public License (LGPL)
 */
typedef unsigned char data_t;

#define MODNN(x) modnn(rs,x)

#define MM (rs->mm)
#define NN (rs->nn)
#define ALPHA_TO (rs->alpha_to) 
#define INDEX_OF (rs->index_of)
#define GENPOLY (rs->genpoly)
#define NROOTS (rs->nroots)
#define FCR (rs->fcr)
#define PRIM (rs->prim)
#define IPRIM (rs->iprim)
#define PAD (rs->pad)
#define A0 (NN)




