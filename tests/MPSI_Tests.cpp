#include <thread>
#include "MPSI_Tests.h"
#include "volePSI/Mpsi.h"
#include "volePSI/fbMpsi.h"
#include "cryptoTools/Network/Channel.h"
#include "cryptoTools/Network/Session.h"
#include "cryptoTools/Network/IOService.h"
#include "coproto/Socket/AsioSocket.h"
#include "Common.h"
using namespace oc;
using namespace volePSI;
using coproto::LocalAsyncSocket;

#define LEADER_PIVOT_PORT 10000
#define LEADER_CLIENT_BASE_PORT 10100
#define PIVOT_CLIENT_BASE_PORT 10500

namespace
{
    Mpsi_User run(u64 User_Num, u64 Set_Size, u64 Lambda, u64 Thread_Num, u64 Test_Size, bool PSI_CA, bool broadcast,  std::string ipp, std::string ipl)
    {
        std::vector<Mpsi_User> User(User_Num);
        std::vector<std::thread> Thrds(User_Num);
        for (u64 ii = 0ull; ii < User_Num; ii++){
            Thrds[ii] = std::thread([&, ii]() {
            std::vector<Socket> Chl;
			u64 Chl_Num;
			std::string exip;

			if (ii == User_Num - 1){
				Chl_Num = User_Num - 1;
				Chl.resize(Chl_Num);
				for (u64 i = 0ull; i < User_Num - 2; i++){
					exip = ipl + ":" + std::to_string(LEADER_CLIENT_BASE_PORT + i);
					Chl[i] = coproto::asioConnect(exip, true);
				}
				exip = ipl + ":" + std::to_string(LEADER_PIVOT_PORT);
				Chl[User_Num - 2] = coproto::asioConnect(exip, true);
			}
			else if (ii == User_Num - 2){
				Chl_Num = User_Num - 1;
				Chl.resize(Chl_Num);
				for (u64 i = 0ull; i < User_Num - 2; i++){
					exip = ipp + ":" + std::to_string(PIVOT_CLIENT_BASE_PORT + i);
					Chl[i] = coproto::asioConnect(exip, true);
				}
				exip = ipl + ":" + std::to_string(LEADER_PIVOT_PORT);
				Chl[User_Num - 2] = coproto::asioConnect(exip, false);
			}
			else {
				Chl_Num = 2;
				Chl.resize(Chl_Num);
				exip = ipl + ":" + std::to_string(LEADER_CLIENT_BASE_PORT + ii);
				Chl[0] = coproto::asioConnect(exip, false);
				exip = ipp + ":" + std::to_string(PIVOT_CLIENT_BASE_PORT + ii);
				Chl[1] = coproto::asioConnect(exip, false);
			}
                PRNG prng(toBlock(ii));
                std::vector<block> User_Set(Set_Size);	
                prng.get<block>(User_Set);
                for (u64 j=0ull; j<Test_Size; j++)
                    User_Set[(j+ii)%Set_Size]=toBlock(j);
                block Seed=ZeroBlock;
                User[ii].run(User_Num, ii, Set_Size, Lambda, Thread_Num, Seed, User_Set, Chl, PSI_CA, broadcast);
				for (u64 i = 0ull; i < Chl_Num; i++)
					coproto::sync_wait(Chl[i].close());
                return ;
            });
        }

    for (auto& thrd : Thrds) thrd.join();

    return User[User_Num - 1];
    }
}


void MPSI_3Party_Empty_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = 0;  //empty test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=0) //empty test
        throw RTE_LOC;
}

void MPSI_3Party_Partial_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Full_Test(const CLP& cmd)
{
	u64 User_Num = 3ull; //3 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = Set_Size;  //full test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Set_Size) //full test
        throw RTE_LOC;
}

void MPSI_3Party_Mthreads_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 4; //multy threads
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Cardinality_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = true;  //yes ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Size_Intersection!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Broadcast_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool broadcast = true; //yes bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Empty_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = 0;  //empty test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=0) //empty test
        throw RTE_LOC;
}

void MPSI_5Party_Partial_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Full_Test(const CLP& cmd)
{
	u64 User_Num = 5ull; //5 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = Set_Size;  //full test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Set_Size) //full test
        throw RTE_LOC;
}

void MPSI_5Party_Mthreads_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 4; //multy threads
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Cardinality_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = true;  //yes ca
	bool broadcast = false; //no bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Size_Intersection!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Broadcast_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	// u64 ii = cmd.getOr("id", User_Num - 1);
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool broadcast = true; //yes bc
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, broadcast, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}
