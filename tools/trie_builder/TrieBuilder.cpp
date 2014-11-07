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
      count += iter->second.range.max - iter->second.range.min;
   }   
   return count;
}

bool
BuildTrie(const char* infile, const char* outfile)
{
   std::map<std::string, ChildInfo> childInfos;
   if(!CalcPrefixInfo(childInfos, infile))
   {
     fprintf(stderr, "Error during calculating prefix info\n");
     return false;
   }

   size_t maxUnitCount = CalcMaxUnitCount(childInfos);
   MatcherUnit *pUnits = new MatcherUnit[maxUnitCount];
   if(pUnits == NULL)
   {
     fprintf(stderr, "Failed to allocate space\n");
     return false;
   }
   memset(pUnits, 0, sizeof(MatcherUnit)*maxUnitCount);
   

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
