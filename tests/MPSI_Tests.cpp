#include <thread>
#include "MPSI_Tests.h"
#include "volePSI/Mpsi.h"
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
#define ReCR User[User_Num - 1].Receiver_Cpsi_Results
#define SeCR User[User_Num - 2].Sender_Cpsi_Results

namespace
{
    Mpsi_User run(u64 User_Num, u64 Set_Size, u64 Lambda, u64 Thread_Num, u64 Test_Size, bool PSI_CA, bool Circuit, bool broadcast, bool Mal, std::string ipp, std::string ipl)
    {
        std::vector<Mpsi_User> User(User_Num);
        std::vector<std::thread> Thrds(User_Num);
		std::vector<block> Leader_Set(Set_Size);

        for (u64 My_Id = 0ull; My_Id < User_Num; My_Id++){
            Thrds[My_Id] = std::thread([&, My_Id]() {
            std::vector<Socket> Chl;
			u64 Chl_Num;
			std::string exip;
			u64 All_Set_Size[User_Num];
			for (u64 i = 0ull; i < User_Num; i++)
				All_Set_Size[i] = Set_Size;

			if (My_Id == User_Num - 1){
				Chl_Num = User_Num - 1;
				Chl.resize(Chl_Num);
				for (u64 i = 0ull; i < User_Num - 2; i++){
					exip = ipl + ":" + std::to_string(LEADER_CLIENT_BASE_PORT + i);
					Chl[i] = coproto::asioConnect(exip, true);
				}
				exip = ipl + ":" + std::to_string(LEADER_PIVOT_PORT);
				Chl[User_Num - 2] = coproto::asioConnect(exip, true);
			}
			else if (My_Id == User_Num - 2){
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
				exip = ipl + ":" + std::to_string(LEADER_CLIENT_BASE_PORT + My_Id);
				Chl[0] = coproto::asioConnect(exip, false);
				exip = ipp + ":" + std::to_string(PIVOT_CLIENT_BASE_PORT + My_Id);
				Chl[1] = coproto::asioConnect(exip, false);
			}
                PRNG prng(toBlock(My_Id));
                std::vector<block> User_Set(Set_Size);	
                prng.get<block>(User_Set);
                for (u64 j=0ull; j<Test_Size; j++)
                    User_Set[(j+My_Id)%Set_Size]=toBlock(j);
                block Seed=block(My_Id,My_Id);
                User[My_Id].run(User_Num, My_Id, All_Set_Size, Lambda, Thread_Num, Seed, User_Set, Chl, PSI_CA, Circuit, broadcast, Mal);
				if (Circuit && My_Id == User_Num - 1)
					std::memcpy(Leader_Set.data(), User_Set.data(), Set_Size * sizeof(block));
				for (u64 i = 0ull; i < Chl_Num; i++)
					coproto::sync_wait(Chl[i].close());
                return ;
            });
        }

		for (auto& thrd : Thrds) thrd.join();

		if (Circuit){

			for (u64 i = 0; i < Set_Size; i++)
			{

				auto k = ReCR.mMapping[i];

				if (ReCR.mFlagBits[k] ^ SeCR.mFlagBits[k]){
					User[User_Num - 1].Multi_Intersection.push_back(Leader_Set[i]);
					auto rv = *(block*)&ReCR.mValues(k, 0);
					auto sv = *(block*)&SeCR.mValues(k, 0);
					auto act = (rv ^ sv);
					if (Leader_Set[i] != act){
						User[User_Num - 1].Multi_Intersection.clear();
						return User[User_Num - 1];
					}
				}
			}
		}

		if (broadcast)
			return User[1];
		else
			return User[User_Num - 1];
    }
}


void MPSI_3Party_Empty_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = 0;  //empty test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=0) //empty test
        throw RTE_LOC;
}

void MPSI_3Party_Partial_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Full_Test(const CLP& cmd)
{
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = Set_Size;  //full test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Set_Size) //full test
        throw RTE_LOC;
}

void MPSI_3Party_Mthreads_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 4; //multy threads
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Cardinality_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = true;  //yes ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Size_Intersection!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Circuit_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = true; //yes ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    // if (inter.Size_Intersection!=Test_Size) //partial test
    //     throw RTE_LOC;
}

void MPSI_3Party_Broadcast_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = true; //yes bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_3Party_Malicious_Test(const CLP& cmd)
{
    
	u64 User_Num = 3ull; //3 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = true; //yes malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Empty_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = 0;  //empty test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=0) //empty test
        throw RTE_LOC;
}

void MPSI_5Party_Partial_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Full_Test(const CLP& cmd)
{
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = Set_Size;  //full test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Set_Size) //full test
        throw RTE_LOC;
}

void MPSI_5Party_Mthreads_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 4; //multy threads
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Cardinality_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = true;  //yes ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Size_Intersection!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Circuit_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = true; //yes ci
	bool broadcast = false; //no bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    // if (inter.Size_Intersection!=Test_Size) //partial test
    //     throw RTE_LOC;
}

void MPSI_5Party_Broadcast_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = true; //yes bc
	bool Mal = false; //no malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}

void MPSI_5Party_Malicious_Test(const CLP& cmd)
{
    
	u64 User_Num = 5ull; //5 party
	u64 Set_Size =  1ull << cmd.getOr("nn", 10);
	u64 Lambda = cmd.getOr("la", 40ull);
	u64 Thread_Num = 1; //single thread
	u64 Test_Size = cmd.getOr("ts", Set_Size/10);  //partial test
	bool PSI_CA = false;  //no ca
	bool Circuit = false; //no ci
	bool broadcast = false; //no bc
	bool Mal = true; //yes malicious
    std::string ipp = cmd.getOr<std::string>("ipp", "localhost");
	std::string ipl = cmd.getOr<std::string>("ipl", "localhost");
    
    auto inter = run(User_Num, Set_Size, Lambda, Thread_Num, Test_Size, PSI_CA, Circuit, broadcast, Mal, ipp, ipl);

    if (inter.Multi_Intersection.size()!=Test_Size) //partial test
        throw RTE_LOC;
}
