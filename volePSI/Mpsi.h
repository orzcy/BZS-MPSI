#pragma once

#include "volePSI/Defines.h"
#include "volePSI/RsOprf.h"
#include "volePSI/RsPsi.h"
#include "sparsehash/dense_hash_map"
#include "cryptoTools/Common/Timer.h"

namespace volePSI
{
    class Mpsi_User : public oc::TimerAdapter
    {
    public:
        size_t Comm = 0;
        size_t Size_Intersection = 0;
        std::vector<block> Multi_Intersection;
        void run(u64 User_Num, u64 My_Id, u64 Set_Size, u64 Lambda, u64 Thread_Num, block Seed, std::vector<block> Inputs, std::vector<Socket> Chl, bool PSI_CA = false, bool broadcast = false);
    };
}