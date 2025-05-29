#include "fileBased.h"
#include "fbMpsi.h"
#include "volePSI/RsPsi.h"
#include "volePSI/RsOprf.h"
#include <array>
#include <map>
#include <future>
#include <thread>
#include <unordered_set>
#include "volePSI/SimpleIndex.h"
#include "libdivide.h"
#include "coproto/Socket/AsioSocket.h"
#include "libOTe/Tools/DefaultCurve.h"
#include <cryptoTools/Crypto/SodiumCurve.h>

#define CUCKOO_HASH_NUM 3
#define GCT_Bin_Size 1<<14
#define HASH_SEED oc::ZeroBlock

namespace volePSI
{
    // Run a participant in BZS-MPSI
    // In MPSI, there are "User_Num" ( User_Num > 2 ) parties
    // Each parties P_i holds a dataset "Inputs" of size "Set_Size"
    // They want to compute the intersection "Multi_Intersection" of their sets without revealing any additional information

    void fbMpsi_User::run(u64 User_Num, u64 My_Id, u64 Set_Size[], u64 Lambda, u64 Thread_Num, block Seed, std::vector<block> Inputs, std::vector<Socket> Chl, bool PSI_CA, bool broadcast){

        setTimePoint("Start");
          
        PRNG Prng(Seed);

        // *Leader : Id = User_Num - 1 
        // Pivot   : Id = User_Num - 2
        // Client  : Id = [0,User_Num - 3]

        if (My_Id == User_Num - 1){

            // Init & Encode OKVS "GCT"
            // GCT = Encode ( { (Input[i], Rand_Num[i]) } ) 
            // "P_size" is the size of GCT

            std::vector<block> Rand_Num(Set_Size[My_Id]);
            Prng.get<block>(Rand_Num);
            std::vector<block> GCT;
            Baxos Paxos;
            u64 P_size;
            Paxos.init(Set_Size[My_Id], GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, HASH_SEED);
            P_size=Paxos.size();
            GCT.resize(P_size);
            Paxos.solve<block>(Inputs,Rand_Num,GCT,&Prng,1);

            setTimePoint("GCT Finish");

            std::vector<block> Share_Seed(User_Num - 1);
            Prng.get<block>(Share_Seed);
            std::vector<block> Share(P_size);

            // Share & Send OKVS "GCT"
            // Share[i] = PRG ( Share_Seed[i] )  i = [0,User_Num-3]
            // Share[User_Num-2] = GCT xor Share[i]  i = [0,User_Num-3]
            // i.e. " GCT = GCT ^ Share " in the code
            // Send Share_Seed[i]     to Client P_i  i = [0,User_Num-3]
            // Send Share[User_Num-2] to Pivot  P_(User_Num-2) 

            std::vector<std::thread> shareThrds(User_Num - 2);

            for (u64 i = 0ull; i < User_Num - 2; i++){
                shareThrds[i] = std::thread([&, i]() {
                    coproto::sync_wait(Chl[i].send(Share_Seed[i]));
                    return ;
                });
            }

            for (auto& thrd : shareThrds) thrd.join();

            for (u64 i = 0ull; i < User_Num - 2; i++){
                PRNG Share_Prng(Share_Seed[i]);
                Share_Prng.get<block>(Share);
                for (u64 j = 0ull; j < P_size; j++)
                    GCT[j] = GCT[j] ^ Share[j];
            }

            coproto::sync_wait(Chl[User_Num - 2].send(GCT));

            setTimePoint("Share Finish");
            
            // If there is "-CA", only output the intersection size (MPSI-CA) 
            // Otherwise, output the complete intersection (Standard MPSI)

            if (!PSI_CA)
            {
                setTimePoint("2PSI Begin");

                // Invoke 2-party PSI with Pivot P_(User_Num-2)
                // Input "Rand_Num" ( values during OKVS "GCT" Encode )
                // Receive output "Psi_Receiver.mIntersection"
                // "Psi_Receiver.mIntersection[] = x" means that the x-th element of Rand_Num ( i.e. Rand_Num[x] ) is in the 2-party PSI result
                // Then the MPSI result "Multi_Intersection" are all Inputs[x] 

                RsPsiReceiver Psi_Receiver;
                Psi_Receiver.init(Set_Size[User_Num - 2],Set_Size[My_Id],Lambda,Seed,false,Thread_Num);
                auto p = Psi_Receiver.run(Rand_Num,Chl[User_Num - 2]);
                auto re = macoro::sync_wait(macoro::when_all_ready(std::move(p)));

                setTimePoint("2PSI Finish");  

                Size_Intersection = Psi_Receiver.mIntersection.size();
                Multi_Intersection.clear();

                for (u64 i = 0ull; i < Size_Intersection; i++)
                    Multi_Intersection.push_back(Inputs[Psi_Receiver.mIntersection[i]]);

                Size_Intersection = Multi_Intersection.size();

                setTimePoint("Get Intersection Finish");

            }
            else{

                // Run 2-party DH-based PSI-CA with Pivot P_(User_Num-2) to achieve MPSI-CA
                // Input "Rand_Num" ( values during OKVS "GCT" Encode )
                // Receive output "Size_Intersection", which is also the result of MPSI-CA

                setTimePoint("2PSI-CA Begin");

                std::vector<osuCrypto::Sodium::Monty25519> Se_point(Set_Size[User_Num - 2]),Re_point(Set_Size[My_Id]);
                osuCrypto::Sodium::Scalar25519 G = osuCrypto::Sodium::Scalar25519(Prng);

                if (Thread_Num > 1){

                    std::vector<std::thread> Y_beta(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; i++){
                        Y_beta[i] = std::thread([&, i]() {
                            unsigned char Th_point_bytes[32];  
                            memset(Th_point_bytes,0,32);
                            u64 Th_Begin = i * Set_Size[My_Id] / Thread_Num, Th_End = (i+1) * Set_Size[My_Id] / Thread_Num;
                            for (u64 j = Th_Begin; j < Th_End; j++){
                                unsigned char* block_bytes = Rand_Num[j].data();
                                memcpy(Th_point_bytes, block_bytes, 16);
                                Re_point[j].fromBytes(Th_point_bytes);
                                Re_point[j] = G * Re_point[j];
                            }
                            return ;
                        });
                    }

                    for (auto& thrd : Y_beta) thrd.join();

                    coproto::sync_wait(Chl[User_Num - 2].recv(Se_point));
                    coproto::sync_wait(Chl[User_Num - 2].send(Re_point));

                    std::vector<std::thread> X_alpha_beta(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; i++){
                        X_alpha_beta[i] = std::thread([&, i]() {
                            u64 Th_Begin = i * Set_Size[User_Num - 2] / Thread_Num, Th_End = (i+1) * Set_Size[User_Num - 2] / Thread_Num;
                            for (u64 j = Th_Begin; j < Th_End; j++)
                                Se_point[j] = G * Se_point[j];
                            return ;
                        });
                    }

                    for (auto& thrd : X_alpha_beta) thrd.join();

                    coproto::sync_wait(Chl[User_Num - 2].recv(Re_point));

                }
                else {

                    unsigned char point_bytes[32];  
                    memset(point_bytes,0,32);

                    for (u64 i = 0ull; i < Set_Size[My_Id]; i++){
                        unsigned char* block_bytes = Rand_Num[i].data();
                        memcpy(point_bytes, block_bytes, 16);
                        Re_point[i].fromBytes(point_bytes);
                        Re_point[i] = G * Re_point[i];
                    }

                    coproto::sync_wait(Chl[User_Num - 2].recv(Se_point));
                    coproto::sync_wait(Chl[User_Num - 2].send(Re_point));

                    for (u64 i = 0; i < Set_Size[User_Num - 2]; i++)
                        Se_point[i] = G * Se_point[i];
            
                    coproto::sync_wait(Chl[User_Num - 2].recv(Re_point));
                    
                }

                setTimePoint("2PSI-CA Finish");

                unsigned char point_bytes[32];  
                memset(point_bytes,0,32);
                std::vector<block> Se_block(Set_Size[User_Num - 2]), Re_block(Set_Size[My_Id]);

                for (u64 i = 0ull; i < Set_Size[User_Num - 2]; i++){
                    Se_point[i].toBytes(point_bytes);
                    std::memcpy(Se_block[i].data(),point_bytes,16);
                }
                for (u64 i = 0ull; i < Set_Size[My_Id]; i++){
                    Re_point[i].toBytes(point_bytes);
                    std::memcpy(Re_block[i].data(),point_bytes,16);
                }

                std::unordered_set<block> Re_set;

                for (u64 i = 0; i < Set_Size[My_Id]; i++)
                    Re_set.insert(Re_block[i]);

                for (u64 i = 0; i < Set_Size[User_Num - 2]; i++)
                    if (Re_set.find(Se_block[i]) != Re_set.end())
                        Size_Intersection++;

                setTimePoint("Get MPSI-CA Finish");
            }

            // If there is "-BC", Leader broadcasts the MPSI(-CA) result to all parties

            if (broadcast){
                
                std::vector<std::thread> outputThrds(User_Num - 1);

                for (u64 i = 0; i < User_Num - 1; ++i){
                    outputThrds[i] = std::thread([&, i]() {
                        coproto::sync_wait(Chl[i].send(Size_Intersection));
                        if (!PSI_CA && Size_Intersection > 0)
                            coproto::sync_wait(Chl[i].send(Multi_Intersection));
                        return ;
                    });
                }

                for (auto& thrd : outputThrds) thrd.join();

                setTimePoint("Broadcast Intersection Finish");
            }

            for (u64 i = 0ull; i < User_Num - 1; i++){
                coproto::sync_wait(Chl[i].flush());
                Comm += Chl[i].bytesSent();
            }

            setTimePoint("Finish");
        }

        // Leader  : Id = User_Num - 1 
        // *Pivot  : Id = User_Num - 2
        // Client  : Id = [0,User_Num - 3]

        else if (My_Id == User_Num - 2)
        {
                        
            // Init OKVS "GCT[i]" i = [0, User_Num-2]
            // "P_size[i]" is the size of GCT[i] i = [0, User_Num-2]

            std::vector<std::vector<block>> GCT(User_Num - 1);
            Baxos Paxos[User_Num - 1];
            u64 P_size[User_Num - 1];
            for (u64 i = 0ull; i < User_Num - 1; i++){
                if (i < User_Num - 2)
                    Paxos[i].init(Set_Size[i], GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, HASH_SEED);
                else
                    Paxos[i].init(Set_Size[i+1], GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, HASH_SEED);
                P_size[i] = Paxos[i].size();
                GCT[i].resize(P_size[i]);
            }

            // Receive OKVS "Share[User_Num-2]" (i.e. GCT[User_Num-2] here) from Leader P_(User_Num-1) 

            std::vector<std::thread> recvThrds(User_Num - 1);

            // Receive OKVS "GCT" (i.e. GCT[i] here) from Client P_i  i = [0, User_Num-3]
            
            for (u64 i = 0ull; i < User_Num - 1; i++){
                recvThrds[i] = std::thread([&, i]() {
                        coproto::sync_wait(Chl[i].recv(GCT[i]));
                    return ;
                });
            }

            for (auto& thrd : recvThrds) thrd.join();

            setTimePoint("receive GCT Finish");

            // Decode OKVS "GCT[i]" i = [0, User_Num-2] and compute the XOR-sum using all elements in Inputs
            // Result[j] = xor Result_i[j] where Result_i[j] = Decode ( Inputs[j], GCT[i] ) i = [0, User_Num-2]

            std::vector<block> Result_i(Set_Size[My_Id]),Result(Set_Size[My_Id]);
            for (u64 i = 0ull; i < User_Num - 1; i++){
                Paxos[i].decode<block>(Inputs,Result_i,GCT[i],Thread_Num);
                for (u64 j = 0ull; j < Set_Size[My_Id]; j++){
                    Result[j] ^= Result_i[j];
                    Result_i[j] = osuCrypto::ZeroBlock;
                }
            }

            setTimePoint("Decode Finish");
            
            // If there is "-CA", only output the intersection size (MPSI-CA) 
            // Otherwise, output the complete intersection (Standard MPSI)

            if (!PSI_CA){

                // Invoke 2-party PSI with Leader P_(User_Num-1)
                // Input "Result" ( XOR-sum of GCT[i] Decode )

                RsPsiSender Psi_Sender;
                Psi_Sender.init(Set_Size[My_Id],Set_Size[User_Num - 1],Lambda,Seed,false,Thread_Num);
                auto p = Psi_Sender.run(Result, Chl[User_Num - 2]);
                auto re = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
 
                setTimePoint("2PSI Finish");

            }
            else{

                // Run 2-party DH-based PSI-CA with Leader P_(User_Num-1)
                // Input "Result" ( values during OKVS "GCT[0]" Decode )

                setTimePoint("2PSI-CA Begin");

                std::vector<osuCrypto::Sodium::Monty25519> Se_point(Set_Size[My_Id]),Re_point(Set_Size[User_Num - 1]);
                osuCrypto::Sodium::Scalar25519 G = osuCrypto::Sodium::Scalar25519(Prng);

                if (Thread_Num > 1){

                    std::vector<std::thread> X_alpha(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; i++){
                        X_alpha[i] = std::thread([&, i]() {
                            unsigned char Th_point_bytes[32];  
                            memset(Th_point_bytes,0,32);
                            u64 Th_Begin = i * Set_Size[My_Id] / Thread_Num, Th_End = (i+1) * Set_Size[My_Id] / Thread_Num;
                            for (u64 j = Th_Begin; j < Th_End; j++){
                                unsigned char* block_bytes = Result[j].data();
                                memcpy(Th_point_bytes, block_bytes, 16);
                                Se_point[j].fromBytes(Th_point_bytes);
                                Se_point[j] = G * Se_point[j];
                            }
                            return ;
                        });
                    }

                    for (auto& thrd : X_alpha) thrd.join();

                    coproto::sync_wait(Chl[User_Num - 2].send(Se_point));
                    coproto::sync_wait(Chl[User_Num - 2].recv(Re_point));

                    std::vector<std::thread> Y_alpha_beta(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; i++){
                        Y_alpha_beta[i] = std::thread([&, i]() {
                            u64 Th_Begin = i * Set_Size[User_Num - 1] / Thread_Num, Th_End = (i+1) * Set_Size[User_Num - 1] / Thread_Num;
                            for (u64 j = Th_Begin; j < Th_End; j++){
                                Re_point[j] = G * Re_point[j];
                            }
                            return ;
                        });
                    }

                    for (auto& thrd : Y_alpha_beta) thrd.join();

                    std::shuffle(Re_point.begin(),Re_point.end(),Prng);
                    coproto::sync_wait(Chl[User_Num - 2].send(Re_point));

                }
                else {

                    unsigned char point_bytes[32]; 
                    memset(point_bytes,0,32);

                    for (u64 i = 0ull; i < Set_Size[My_Id]; i++){
                        unsigned char* block_bytes = Result[i].data();
                        memcpy(point_bytes, block_bytes, 16);
                        Se_point[i].fromBytes(point_bytes);
                        Se_point[i] = G * Se_point[i];
                    }

                    coproto::sync_wait(Chl[User_Num - 2].send(Se_point));
                    coproto::sync_wait(Chl[User_Num - 2].recv(Re_point));

                    for (u64 i = 0; i < Set_Size[User_Num - 1]; i++)
                        Re_point[i] = G * Re_point[i];
                    
                    std::shuffle(Re_point.begin(),Re_point.end(),Prng);
                    coproto::sync_wait(Chl[User_Num - 2].send(Re_point));
                }

                setTimePoint("2PSI-CA Finish");
            }

            // If there is "-BC", Pivot receives the MPSI(-CA) result from Leader's broadcast

            if (broadcast){
                coproto::sync_wait(Chl[User_Num - 2].recv(Size_Intersection));
                if (!PSI_CA && Size_Intersection > 0){
                    Multi_Intersection.resize(Size_Intersection);
                    coproto::sync_wait(Chl[User_Num - 2].recv(Multi_Intersection));
                }
                    
                setTimePoint("Receive Intersection Finish");
            }

            for (u64 i = 0ull; i < User_Num - 1; i++){
                coproto::sync_wait(Chl[i].flush());
                Comm += Chl[i].bytesSent();
            }

            setTimePoint("Finish");
        }

        // Leader  : Id = User_Num - 1 
        // Pivot   : Id = User_Num - 2
        // *Client : Id = [0,User_Num - 3]

        else
        {

            // Init OKVS "GCT" & "Share" 
            // "P_size_En" is the size of GCT
            // "P_size_De" is the size of Share

            Baxos Paxos_De,Paxos_En;
            u64 P_size_De,P_size_En;
            Paxos_De.init(Set_Size[User_Num - 1], GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, HASH_SEED);
            P_size_De=Paxos_De.size();
            Paxos_En.init(Set_Size[My_Id], GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, HASH_SEED);
            P_size_En=Paxos_En.size();
            std::vector<block> GCT(P_size_En), Share(P_size_De);

            // Receive Share_Seed[i] (i.e. Share_Seed here) from Leader P_(User_Num-1) 

            block Share_Seed;
            coproto::sync_wait(Chl[0].recv(Share_Seed));

            // Reconstruct OKVS "Share"
            // Share = PRG ( Share_Seed )

            std::vector<block> Decode_Share(Set_Size[My_Id]);
            PRNG Share_Prng(Share_Seed);
            Share_Prng.get<block>(Share);

            setTimePoint("receive Share Finish");

            // Decode OKVS "Share" using all elements in Inputs
            // Decode_Share[i] = Decode ( Inputs[i], Share )
            // Then Encode another OKVS "GCT"
            // GCT = Encode ( { ( Inputs[i], Decode_Share[i] ) } )

            Paxos_De.decode<block>(Inputs,Decode_Share,Share,Thread_Num);
            Paxos_En.solve<block>(Inputs,Decode_Share,GCT,&Prng,1);

            setTimePoint("GCT Reconstruction Finish");
            
            // Send the new OKVS "GCT" to Pivot P_(User_Num-2) 

            coproto::sync_wait(Chl[1].send(GCT));
            
            setTimePoint("Send GCT Finish");

            // If there is "-BC", Client receives the MPSI(-CA) result from Leader's broadcast

            if (broadcast){
                coproto::sync_wait(Chl[0].recv(Size_Intersection));
                if (!PSI_CA && Size_Intersection > 0){
                    Multi_Intersection.resize(Size_Intersection);
                    coproto::sync_wait(Chl[0].recv(Multi_Intersection));
                }
                setTimePoint("Receive Intersection Finish");
            }
            coproto::sync_wait(Chl[0].flush());
            coproto::sync_wait(Chl[1].flush());
            Comm += Chl[1].bytesSent();

            setTimePoint("Finish");
        }
        return ;
    }
}