#ifndef H_TRIE_BUILDER_H
#define H_TRIE_BUILDER_H

#include <iostream>
#include <string>
#include <map>
#include <list>
#include <fstream>

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Range{
   uint8_t min;
   uint8_t max;
}Range;

typedef struct ChildInfo
{
  Range range;
  std::list<Range> free_range;
}ChildInfo;

typedef struct MatchInfo
{
  uint32_t uMatchPos;
  uint32_t uMatchLen;
  const char *szValue;
  uint32_t uValueLen;
  int32_t iOpArg;
}MatchInfo;

typedef struct MatcherUnit
{
  int32_t iBase;
  int32_t iPrev;
  uint32_t uValuePos;
  uint32_t uValueLen;
}MatcherUnit;

#endif
