#include "Mpsi.h"
#include "volePSI/RsPsi.h"
#include "volePSI/RsOprf.h"
#include <array>
#include <map>
#include <future>
#include <thread>
#include "volePSI/SimpleIndex.h"
#include "libdivide.h"
#include "coproto/Socket/AsioSocket.h"
#include "libOTe/Tools/DefaultCurve.h"
#include <cryptoTools/Crypto/SodiumCurve.h>

#define CUCKOO_HASH_NUM 3
#define GCT_Bin_Size 1<<14
using x25519_point = std::array<oc::u8, 32>;

namespace volePSI
{
    // Run a participant in benchmark
    // In MPSI, there are "User_Num" ( User_Num > 2 ) parties
    // Each parties P_i holds a dataset "Inputs" of size "Set_Size"
    // They want to compute the intersection "Multi_Intersection" of their sets without revealing any additional information

    void Mpsi_User::run(u64 User_Num, u64 My_Id, u64 Set_Size, u64 Lambda, u64 Thread_Num, block Seed, std::vector<block> Inputs, std::vector<Socket> Chl, bool PSI_CA, bool broadcast){

        PRNG Prng(Seed);
        Baxos Paxos;
        u64 P_size;

        setTimePoint("Start");
  
        // *Leader : Id = User_Num - 1 
        // Pivot   : Id = User_Num - 2
        // Client  : Id = [0,User_Num - 3]

        if (My_Id == User_Num - 1){

            // Encode OKVS "GCT"
            // GCT = Encode ( { (Input[i], Rand_Num[i]) } ) 
            // "P_size" is the size of GCT

            std::vector<block> Rand_Num(Set_Size);
            Prng.get<block>(Rand_Num);
            std::vector<block> GCT;
            Paxos.init(Set_Size, GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, Seed);
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

            for (u64 i = 0ull; i < User_Num - 1 - 1; i++){
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
                Psi_Receiver.init(Set_Size,Set_Size,Lambda,Seed,false,Thread_Num);
                auto p = Psi_Receiver.run(Rand_Num,Chl[User_Num -1 -1]);
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

                unsigned char point_bytes[32];  

                for (u64 i = 0ull; i < 32ull ; i++)
                    point_bytes[i]=0;

                setTimePoint("2PSI-CA Begin");

                PRNG Prng_CA(block(My_Id,My_Id));
                std::vector<osuCrypto::Sodium::Monty25519> Se_point(Set_Size),Re_point(Set_Size);
                osuCrypto::Sodium::Scalar25519 G = osuCrypto::Sodium::Scalar25519(Prng_CA);

                if(Thread_Num>1){
                    std::vector<std::thread> Re_CA(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; ++i){
                        Re_CA[i] = std::thread([&, i]() {
                            unsigned char Th_point_bytes[32];  
                            for (u64 jj = 0ull; jj < 32ull ; jj++)
                                Th_point_bytes[jj]=0;
                            u64 Th_Length = Set_Size/Thread_Num;
                            u64 Th_Begin= i*Th_Length, Th_End= (i==Thread_Num-1)?Set_Size:((i+1)*Th_Length);
                            for (u64 j = Th_Begin; j < Th_End; j++){
                                unsigned char* block_bytes = Rand_Num[j].data();
                                for (u64 jj = 0ull; jj < 16ull; jj++)
                                    Th_point_bytes[jj] = block_bytes[jj];
                                Se_point[j].fromBytes(Th_point_bytes);
                                Se_point[j] = G * Se_point[j];
                            }
                            return ;
                        });
                    }

                    for (auto& thrd : Re_CA) thrd.join();
                }
                else {
                    for (u64 i = 0ull; i < Set_Size; i++){
                        unsigned char* block_bytes = Rand_Num[i].data();
                        for (u64 j = 0ull; j < 16ull; j++)
                            point_bytes[j] = block_bytes[j];
                        Se_point[i].fromBytes(point_bytes);
                        Se_point[i] = G * Se_point[i];
                    }
                }

                coproto::sync_wait(Chl[User_Num - 2].recv(Re_point));
                coproto::sync_wait(Chl[User_Num - 2].send(Se_point));

                if(Thread_Num>1){
                    std::vector<std::thread> Re_CA_2(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; ++i){
                        Re_CA_2[i] = std::thread([&, i]() {
                            u64 Th_Length = Set_Size/Thread_Num;
                            u64 Th_Begin= i*Th_Length, Th_End= (i==Thread_Num-1)?Set_Size:((i+1)*Th_Length);
                            for (u64 j = Th_Begin; j < Th_End; j++)
                                Re_point[j] = G * Re_point[j];
                            return ;
                        });
                    }

                    for (auto& thrd : Re_CA_2) thrd.join();
                }
                else {
                    for (u64 i = 0; i < Set_Size; i++)
                        Re_point[i] = G * Re_point[i];
                }

                coproto::sync_wait(Chl[User_Num - 2].recv(Se_point));

                setTimePoint("DH Finish");

                std::vector<block> Se_block(Set_Size), Re_block(Set_Size);

                for (u64 i = 0ull; i < Set_Size; i++){
                    Se_point[i].toBytes(point_bytes);
                    std::memcpy(Se_block[i].data(),point_bytes,16);
                    Re_point[i].toBytes(point_bytes);
                    std::memcpy(Re_block[i].data(),point_bytes,16);
                }

                std::sort(Se_block.begin(),Se_block.end());
                std::sort(Re_block.begin(),Re_block.end());
                u64 Se_p = 0ull, Re_p = 0ull;

                while (Se_p<Set_Size && Re_p<Set_Size){
                    if (Se_block[Se_p] == Re_block[Re_p]){
                        Size_Intersection++;
                        Se_p++; Re_p++;
                    } 
                    else if (Se_block[Se_p] < Re_block[Re_p])
                        Se_p++;
                    else Re_p++;
                }

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
 
            // Init OKVS "GCT" 
            // "P_size" is the size of GCT

            std::vector<std::vector<block>> GCT(User_Num - 1);
            Paxos.init(Set_Size, GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, Seed);
            P_size=Paxos.size();

            GCT[User_Num - 2].resize(P_size);

            // Receive OKVS "Share[User_Num-2]" (i.e. GCT[User_Num-2] here) from Leader P_(User_Num-1) 

            coproto::sync_wait(Chl[User_Num - 2].recv(GCT[User_Num - 2]));
            
            // Receive OKVS "GCT" (i.e. GCT[i] here) from Client P_i  i = [0, User_Num-3]

            std::vector<block> Result(Set_Size);
            std::vector<std::thread> recvThrds(User_Num - 2);
            
            for (u64 i = 0ull; i < User_Num - 2; i++){
                recvThrds[i] = std::thread([&, i]() {
                    GCT[i].resize(P_size);
                    coproto::sync_wait(Chl[i].recv(GCT[i]));
                    return ;
                });
            }

            for (auto& thrd : recvThrds) thrd.join();

            setTimePoint("receive GCT Finish");
            
            // Reconstruct OKVS "GCT"
            // GCT = xor GCT[i]  i = [0,User_Num-2]
            // i.e. " GCT[0] = GCT[0] ^ GCT[i] " in the code

            for (u64 i = 1; i < User_Num - 1; i++){
                for (u64 j = 0; j < P_size; j++)
                    GCT[0][j] ^= GCT[i][j];
            }

            // Decode OKVS "GCT" (i.e. GCT[0] here) using all elements in Inputs
            // Result[i] = Decode ( Inputs[i], GCT[0] )

            Paxos.decode<block>(Inputs,Result,GCT[0],Thread_Num);

            setTimePoint("Decode Finish");
            
            // If there is "-CA", only output the intersection size (MPSI-CA) 
            // Otherwise, output the complete intersection (Standard MPSI)

            if (!PSI_CA){

                // Invoke 2-party PSI with Leader P_(User_Num-1)
                // Input "Result" ( values during OKVS "GCT[0]" Decode )

                RsPsiSender Psi_Sender;
                Psi_Sender.init(Set_Size,Set_Size,Lambda,Seed,false,Thread_Num);
                auto p = Psi_Sender.run(Result, Chl[User_Num - 2]);
                auto re = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
 
                setTimePoint("2PSI Finish");

            }
            else{

                // Run 2-party DH-based PSI-CA with Leader P_(User_Num-1)
                // Input "Result" ( values during OKVS "GCT[0]" Decode )

                setTimePoint("2PSI-CA Begin");
                unsigned char point_bytes[32]; 

                for (u64 i = 0ull; i < 32 ; i++)
                    point_bytes[i]=0;

                PRNG Prng_CA(block(My_Id,My_Id));
                std::vector<osuCrypto::Sodium::Monty25519> Se_point(Set_Size),Re_point(Set_Size);
                osuCrypto::Sodium::Scalar25519 G = osuCrypto::Sodium::Scalar25519(Prng_CA);
                if(Thread_Num>1){
                    std::vector<std::thread> Re_CA(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; ++i){
                        Re_CA[i] = std::thread([&, i]() {
                            unsigned char Th_point_bytes[32];  
                            for (u64 jj = 0ull; jj < 32ull ; jj++)
                                Th_point_bytes[jj]=0;
                            u64 Th_Length = Set_Size/Thread_Num;
                            u64 Th_Begin= i*Th_Length, Th_End= (i==Thread_Num-1)?Set_Size:((i+1)*Th_Length);
                            for (u64 j = Th_Begin; j < Th_End; j++){
                                unsigned char* block_bytes = Result[j].data();
                                for (u64 jj = 0ull; jj < 16ull; jj++)
                                    Th_point_bytes[jj] = block_bytes[jj];
                                Se_point[j].fromBytes(Th_point_bytes);
                                Se_point[j] = G * Se_point[j];
                            }
                            return ;
                        });
                    }

                    for (auto& thrd : Re_CA) thrd.join();
                }
                else {
                    for (u64 i = 0ull; i < Set_Size; i++){
                        unsigned char* block_bytes = Result[i].data();
                        for (u64 j = 0ull; j < 16ull; j++)
                            point_bytes[j] = block_bytes[j];
                        Se_point[i].fromBytes(point_bytes);
                        Se_point[i] = G * Se_point[i];
                    }
                }

                coproto::sync_wait(Chl[User_Num - 2].send(Se_point));
                coproto::sync_wait(Chl[User_Num - 2].recv(Re_point));

                if(Thread_Num>1){
                    std::vector<std::thread> Re_CA_2(Thread_Num);

                    for (u64 i = 0ull; i < Thread_Num; ++i){
                        Re_CA_2[i] = std::thread([&, i]() {
                            u64 Th_Length = Set_Size/Thread_Num;
                            u64 Th_Begin= i*Th_Length, Th_End= (i==Thread_Num-1)?Set_Size:((i+1)*Th_Length);
                            for (u64 j = Th_Begin; j < Th_End; j++){
                                Re_point[j] = G * Re_point[j];
                            }
                            return ;
                        });
                    }

                    for (auto& thrd : Re_CA_2) thrd.join();
                }
                else {
                    for (u64 i = 0; i < Set_Size; i++)
                        Re_point[i] = G * Re_point[i];
                }
                std::shuffle(Re_point.begin(),Re_point.end(),Prng_CA);
                coproto::sync_wait(Chl[User_Num - 2].send(Re_point));

                setTimePoint("DH Finish");
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

            // Receive Share_Seed[i] (i.e. Share_Seed here) from Leader P_(User_Num-1) 

            block Share_Seed;
            coproto::sync_wait(Chl[0].recv(Share_Seed));

            // Reconstruct OKVS "Share"
            // Share = PRG ( Share_Seed )

            Paxos.init(Set_Size, GCT_Bin_Size, CUCKOO_HASH_NUM, Lambda, PaxosParam::GF128, Seed);
            P_size=Paxos.size();
            std::vector<block> Share(P_size), Decode_Share(Set_Size);
            PRNG Share_Prng(Share_Seed);
            Share_Prng.get<block>(Share);

            setTimePoint("receive Share Finish");

            // Decode OKVS "Share" using all elements in Inputs
            // Decode_Share[i] = Decode ( Inputs[i], Share )
            // Then Encode another OKVS "GCT"
            // GCT = Encode ( { ( Inputs[i], Decode_Share[i] ) } )

            std::vector<block> GCT(P_size);

            Paxos.decode<block>(Inputs,Decode_Share,Share,Thread_Num);
            Paxos.solve<block>(Inputs,Decode_Share,GCT,&Prng,1);

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