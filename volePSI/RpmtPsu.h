#include "volePSI/Defines.h"
#include "volePSI/RsOprf.h"
#include "volePSI/RsPsi.h"
#include "sparsehash/dense_hash_map"
#include "cryptoTools/Common/Timer.h"

namespace volePSI
{
    class RpmtPsu_User : public oc::TimerAdapter
    {
    public:
        size_t Comm = 0;
        size_t Size_Different = 0;
        std::vector<block> Different;
        void run(bool My_Role, u64 Sender_Set_Size, u64 Receiver_Set_Size, u64 Lambda, u64 Thread_Num, block Seed, std::vector<block> Inputs, Socket& Chl);
    };
}