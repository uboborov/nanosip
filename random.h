#ifndef __RANDOM_H__
#define __RANDOM_H__

#include <stdint.h>
//*****************************************************************************
//
// If building with a C++ compiler, make all of the definitions in this header
// have a C binding.
//
//*****************************************************************************
#ifdef __cplusplus
extern "C"
{
#endif
//*****************************************************************************
//
// Prototypes for the random number generator functions.
//
//*****************************************************************************
extern void random_add_entropy(uint32_t ulEntropy);
extern void random_seed(void);
extern uint32_t random_number(void);

//*****************************************************************************
//
// Mark the end of the C bindings section for C++ compilers.
//
//*****************************************************************************
#ifdef __cplusplus
}
#endif

#endif // __RANDOM_H__
