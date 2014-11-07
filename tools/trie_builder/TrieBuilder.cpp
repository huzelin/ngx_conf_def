#include "TrieBuilder.h"

#define MAX_LINE_SIZE 8192

bool
CalcPrefixInfo(std::map<std::string, ChildInfo>& childInfos, const char* file)
{
   std::ifstream in(file);
   if(!in.is_open())
   {
     fprintf(stderr, "open file %s failed!\n", file);
     return false;
   }
   std::string raw_line;
   while(getline(in, raw_line))
   {
     std::string line;
     size_t pos = raw_line.find_first_of('\t', 0);
     if(pos == std::string::npos)
     {
       fprintf(stderr, "line: %s not contain \t\n", raw_line.c_str());
       continue;
     }
     else
     {
       line = raw_line.substr(0, pos);
     }
     for(size_t ui = 0; ui < line.length(); ++ui)
     {
       std::string sub_str = line.substr(0, ui);
       uint8_t cur = line.at(ui);
       std::map<std::string, ChildInfo>::iterator iter = childInfos.find(sub_str);
       if(iter == childInfos.end())
       {
         ChildInfo childInfo;
         childInfo.range.min = cur;
         childInfo.range.max = cur;
         childInfos.insert(std::pair<std::string, ChildInfo>(sub_str, childInfo));
       }
       else
       {
         if(cur > iter->second.range.max)
         {
            if(cur > iter->second.range.max + 1)
            {
               Range free_range = {iter->second.range.max + 1, cur - 1};
               iter->second.free_range.push_back(free_range);
            }
            iter->second.range.max = cur;          
         }
         else if(cur < iter->second.range.min)
         {
            if(cur + 1 < iter->second.range.min)
            {
               Range free_range = {cur + 1, iter->second.range.min - 1};
               iter->second.free_range.push_back(free_range);
            }
            iter->second.range.min = cur;
         }
         else
         {
            std::list<Range>& free_ranges = iter->second.free_range;
            for(std::list<Range>::iterator it = free_ranges.begin(); it != free_ranges.end(); ++it)
            {
               if(cur >= it->min && cur <= it->max)
               {
                  Range del_range = *it;
                  free_ranges.erase(it);

                  if(del_range.min != cur)
                  {
                     Range free_range = {del_range.min, cur - 1};
                     free_ranges.push_back(free_range);
                  }

                  if(del_range.max != cur)
                  {
                     Range free_range = {cur + 1, del_range.max};
                     free_ranges.push_back(free_range);
                  }                  
                  break;
               }
            } 
         }
       }
     }  
   }
   in.close();
   return true;
}

size_t
CalcMaxUnitCount(std::map<std::string, ChildInfo>& childInfos)
{
   size_t count = 2;
   for(std::map<std::string, ChildInfo>::iterator iter = childInfos.begin(); iter != childInfos.end(); ++iter)
   {
      count += iter->second.range.max - iter->second.range.min + 1;
   }   
   return count;
}

void
AppendFreePositions(std::list<Range>& free_positions, Range& new_range)
{
   std::list<Range>::iterator free_iter = free_positions.begin();
   for(; free_iter != free_positions.end(); ++free_iter)
   {
     if(free_iter->max - free_iter->min < new_range.max - new_range.min)
     {
       free_positions.insert(free_iter, new_range);
       break;
     }
   }
   if(free_iter == free_positions.end())
   {
     free_positions.push_back(new_range);
   }  
}

bool
BuildTrie(const char* infile, const char* outfile)
{
   std::map<std::string, ChildInfo> prefixInfo;
   if(!CalcPrefixInfo(prefixInfo, infile))
   {
     fprintf(stderr, "Error during calculating prefix info\n");
     return false;
   }

   size_t maxUnitCount = CalcMaxUnitCount(prefixInfo);
   MatcherUnit *pUnits = new MatcherUnit[maxUnitCount];
   bool* fpValid = new bool[maxUnitCount];
   if(pUnits == NULL || fpValid == NULL)
   {
     fprintf(stderr, "Failed to allocate space\n");
     delete [] pUnits;
     delete [] fpValid;
     return false;
   }
   memset(pUnits,  0, sizeof(MatcherUnit)*maxUnitCount);
   memset(fpValid, 0, sizeof(bool)*maxUnitCount);

   /*** read file and parse trie ***/
   std::ifstream in(infile);
   char buf[256];
   sprintf(buf, "%s.key",   outfile);
   FILE *fp_key   = fopen(buf, "w");
   sprintf(buf, "%s.value", outfile);
   FILE *fp_value = fopen(buf, "w");
   uint32_t uUsedValueLen = 0, uUsedKeyCount = 2;

   if(!in.is_open() || !fp_key || !fp_value)
   {
     fprintf(stderr, "open file %s failed!\n", infile);
     return false;
   }
   std::string raw_line;
   std::list<Range> free_positions;
   bool use_cc = true;

   while(getline(in, raw_line))
   {
     std::string key, value;
     size_t pos = raw_line.find_first_of('\t', 0);
     if(pos == std::string::npos)
     {
       fprintf(stderr, "line: %s not contain \t\n", raw_line.c_str());
       continue;
     }
     else
     {
       key   = raw_line.substr(0, pos);
       value = raw_line.substr(pos + 1, raw_line.length() - pos);
     }

     uint32_t iPos = 1;
     for(size_t ui = 0; ui < key.length(); ++ui)
     {
        if(!fpValid[iPos])
        {
           std::string tmp = key.substr(0, ui);
           std::map<std::string, ChildInfo>::const_iterator iter = prefixInfo.find(tmp);
           if(iter == prefixInfo.end())
           {
             fprintf(stderr, "Incomplete prefix info\n");
             delete [] fpValid;
             return false;
           }
           
           if(!use_cc || free_positions.size() == 0 ||
              free_positions.begin()->max - free_positions.begin()->min < iter->second.range.max - iter->second.range.min)
           {
              uint32_t uUsedKeyCountLast = uUsedKeyCount;
              pUnits[iPos].iBase = static_cast<int32_t>(uUsedKeyCount) - iPos - static_cast<int32_t>(iter->second.range.min);    
              uUsedKeyCount += iter->second.range.max + 1 - iter->second.range.min;
              
              if(use_cc)
              {
                const std::list<Range>& ranges = iter->second.free_range;
                for(std::list<Range>::const_iterator range_iter = ranges.begin(); range_iter != ranges.end(); ++range_iter)
                {
                  Range new_range = {uUsedKeyCountLast + range_iter->min - iter->second.range.min,  uUsedKeyCountLast + range_iter->max - iter->second.range.min};
                  AppendFreePositions(free_positions, new_range);  
                } 
              }
           }
           else
           {
              std::list<Range>::iterator free_iter = free_positions.begin();
              std::list<Range>::iterator free_iter_last = free_iter;
              for(; free_iter != free_positions.end(); )
              {
                 if(free_iter->max - free_iter->min < iter->second.range.max - iter->second.range.min)
                 {
                   break;
                 }
                 free_iter_last = free_iter;
                 ++free_iter; 
              }
              Range raw_new_range = *free_iter_last;
              Range new_range     = raw_new_range;
              free_positions.erase(free_iter_last); 

              pUnits[iPos].iBase = static_cast<int32_t>(new_range.min) - iPos - static_cast<int32_t>(iter->second.range.min);
             
              new_range.min = new_range.min + iter->second.range.max + 1 - iter->second.range.min;
              if(new_range.min <= new_range.max)
              {
                AppendFreePositions(free_positions, new_range);   
              }

              const std::list<Range>& ranges = iter->second.free_range;
              for(std::list<Range>::const_iterator range_iter = ranges.begin(); range_iter != ranges.end(); ++range_iter)
              {
                 Range new_new_range = {raw_new_range.min + range_iter->min - iter->second.range.min, 
                                        raw_new_range.min + range_iter->max - iter->second.range.min};
                 AppendFreePositions(free_positions, new_new_range);
              } 
           }

           if(ui == 0)
           {
             pUnits[iPos].iPrev = -1;
           }   
           fpValid[iPos] = true;
        } 

        int32_t iRelative = static_cast<int32_t>(static_cast<uint8_t>(key[ui]));
        int32_t iNext = iPos + pUnits[iPos].iBase + iRelative;
       
        pUnits[iNext].iPrev = iPos - iNext;
        if(ui + 1 == key.length())
        {
           pUnits[iNext].uValuePos = uUsedValueLen;
           pUnits[iNext].uValueLen = value.length();
        }
        iPos = iNext;
     }

     if(value.length() != fwrite(value.c_str(), 1, value.length(), fp_value))
     {
        fprintf(stderr, "Error during writing to value file\n");
        delete [] pUnits;
        delete [] fpValid;
        return false;
     }
     uUsedValueLen += value.length();
   }

   if(uUsedKeyCount != fwrite(pUnits, sizeof(MatcherUnit), uUsedKeyCount, fp_key))
   {
      delete [] pUnits;
      delete [] fpValid;
      return false;
   }

   std::cout<<"uUsedKeyCount: "<<uUsedKeyCount<<std::endl;
   delete [] pUnits;
   delete [] fpValid;
   return true; 
}

int 
main(int argc, char** argv)
{
  if(argc != 3)
  {
     fprintf(stderr, "Usage: %s input dict_name\n", argv[0]);
     return 0;
  }
  if(!BuildTrie(argv[1], argv[2]))
  {
     fprintf(stderr, "Build Trie %s failed\n", argv[1]);
     return 0;
  }
  return 1;
}
