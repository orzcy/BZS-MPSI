#include "RpmtPsu.h"
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
#include <cryptoTools/Crypto/RandomOracle.h>
#include "libOTe/Base/BaseOT.h"
#include "libOTe/Base/SimplestOT.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
    
namespace volePSI
{

    void RpmtPsu_User::run(bool My_Role, u64 Sender_Set_Size, u64 Receiver_Set_Size, u64 Sender_Max_Length, u64 Lambda, u64 Thread_Num, block Seed, std::vector<std::string> Inputs_String, Socket& Chl){

        if (My_Role == 1){

            // DH-Based RPMT

            PRNG Prng(Seed);
            oc::RandomOracle hash(16);
            std::vector<block> Inputs_DH(Receiver_Set_Size);

            for (u64 i = 0ull; i < Receiver_Set_Size; i++)
            {
                hash.Reset();
                hash.Update(Inputs_String[i].data(), Inputs_String[i].size());
                hash.Final(Inputs_DH[i]);
            }

            std::vector<osuCrypto::Sodium::Monty25519> Se_point(Sender_Set_Size),Re_point(Receiver_Set_Size);
            osuCrypto::Sodium::Scalar25519 G = osuCrypto::Sodium::Scalar25519(Prng);

            if (Thread_Num > 1){

                std::vector<std::thread> Y_beta(Thread_Num);

                for (u64 i = 0ull; i < Thread_Num; i++){
                    Y_beta[i] = std::thread([&, i]() {
                        unsigned char Th_point_bytes[32];  
                        memset(Th_point_bytes,0,32);
                        u64 Th_Begin = i * Receiver_Set_Size / Thread_Num, Th_End = (i+1) * Receiver_Set_Size / Thread_Num;
                        for (u64 j = Th_Begin; j < Th_End; j++){
                            unsigned char* block_bytes = Inputs_DH[j].data();
                            memcpy(Th_point_bytes, block_bytes, 16);
                            Re_point[j].fromBytes(Th_point_bytes);
                            Re_point[j] = G * Re_point[j];
                        }
                        return ;
                    });
                }

                for (auto& thrd : Y_beta) thrd.join();

                coproto::sync_wait(Chl.recv(Se_point));
                coproto::sync_wait(Chl.send(Re_point));

                std::vector<std::thread> X_alpha_beta(Thread_Num);

                for (u64 i = 0ull; i < Thread_Num; i++){
                    X_alpha_beta[i] = std::thread([&, i]() {
                        u64 Th_Begin = i * Sender_Set_Size / Thread_Num, Th_End = (i+1) * Sender_Set_Size / Thread_Num;
                        for (u64 j = Th_Begin; j < Th_End; j++)
                            Se_point[j] = G * Se_point[j];
                        return ;
                    });
                }

                for (auto& thrd : X_alpha_beta) thrd.join();

                coproto::sync_wait(Chl.recv(Re_point));

            }
            else {

                unsigned char point_bytes[32];  
                memset(point_bytes,0,32);

                for (u64 i = 0ull; i < Receiver_Set_Size; i++){
                    unsigned char* block_bytes = Inputs_DH[i].data();
                    memcpy(point_bytes, block_bytes, 16);
                    Re_point[i].fromBytes(point_bytes);
                    Re_point[i] = G * Re_point[i];
                }

                coproto::sync_wait(Chl.recv(Se_point));
                coproto::sync_wait(Chl.send(Re_point));

                for (u64 i = 0; i < Sender_Set_Size; i++)
                    Se_point[i] = G * Se_point[i];
        
                coproto::sync_wait(Chl.recv(Re_point));
                
            }

            unsigned char point_bytes[32];  
            memset(point_bytes,0,32);
            std::vector<block> Se_block(Sender_Set_Size), Re_block(Receiver_Set_Size);

            for (u64 i = 0ull; i < Sender_Set_Size; i++){
                Se_point[i].toBytes(point_bytes);
                std::memcpy(Se_block[i].data(),point_bytes,16);
            }
            for (u64 i = 0ull; i < Receiver_Set_Size; i++){
                Re_point[i].toBytes(point_bytes);
                std::memcpy(Re_block[i].data(),point_bytes,16);
            }

            std::unordered_set<block> Re_set;

            for (u64 i = 0; i < Receiver_Set_Size; i++)
                Re_set.insert(Re_block[i]);

            std::vector<bool> Se_check(Sender_Set_Size);

            for (u64 i = 0; i < Sender_Set_Size; i++)
                Se_check[i] = (Re_set.find(Se_block[i]) != Re_set.end());

            // OT Receiver

            u64 Block_Num = ((Sender_Max_Length + 15ull) / 16) + 1ull;
            u64 OT_Num = Block_Num * Sender_Set_Size;
            std::vector<bool> OT_Choise(OT_Num);
            
            for (u64 i = 0ull; i < Sender_Set_Size; i++)
                for (u64 j = 0ull; j < Block_Num; j++)
                    OT_Choise[i*Block_Num+j] = Se_check[i];

            std::vector<oc::block> recvMsg(OT_Num);

            if(OT_Num <= 128) // using libOTe-CO15
            {
                PRNG prng(oc::block(oc::sysRandomSeed()));
                osuCrypto::DefaultBaseOT baseOTs;
                std::vector<oc::block> mask(OT_Num);
                std::vector<oc::block> maskMsg(OT_Num);

                osuCrypto::BitVector choices;
                choices.resize(OT_Num);
                for(u64 i = 0; i < OT_Num; i++) {
                    choices[i] = 1 - OT_Choise[i];
                }

                // random OT
                auto p = baseOTs.receive(choices, mask, prng, Chl);
                auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
                std::get<0>(r).result();

                // random OT -> OT
                coproto::sync_wait(Chl.recv(maskMsg));
                for(u64 i = 0; i < OT_Num; i++)
                    recvMsg[i] = maskMsg[i] ^ mask[i];
            }
            else // IKNP
            {
                PRNG prng(oc::block(oc::sysRandomSeed()));
                oc::DefaultBaseOT baseOTs;
                std::vector<oc::block> mask(OT_Num);
                std::vector<oc::block> maskMsg(OT_Num);
                std::vector<std::array<oc::block, 2>> baseSend(128); // kappa == 128

                prng.get((u8*)baseSend.data()->data(), sizeof(oc::block) * 2 * baseSend.size());
                auto p = baseOTs.send(baseSend, prng, Chl);
                auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
                std::get<0>(r).result();

                oc::IknpOtExtReceiver recv;
                recv.setBaseOts(baseSend);
                
                osuCrypto::BitVector choices;
                choices.resize(OT_Num);
                for(u64 i = 0; i < OT_Num; i++) {
                    choices[i] = 1 - OT_Choise[i];
                }

                auto proto = recv.receive(choices, mask, prng, Chl);
                auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
                std::get<0>(result).result();

                // random OT -> OT
                coproto::sync_wait(Chl.recv(maskMsg));
                for(u64 i = 0; i < OT_Num; i++)
                    recvMsg[i] = maskMsg[i] ^ mask[i];
            }
            for (u64 i = 0ull; i < Sender_Set_Size; i++)
                if (Se_check[i] == 0){
                    Size_Different++; 
                    for (u64 j = 0ull; j < Block_Num; j++)
                        Different.push_back(recvMsg[i*Block_Num+j]); 
                }
        }
        else {

            // DH-Based RPMT

            PRNG Prng(Seed);
            oc::RandomOracle hash(16);
            std::vector<block> Inputs_DH(Sender_Set_Size);

            for (u64 i = 0ull; i < Sender_Set_Size; i++)
            {
                hash.Reset();
                hash.Update(Inputs_String[i].data(), Inputs_String[i].size());
                hash.Final(Inputs_DH[i]);
            }

            std::vector<osuCrypto::Sodium::Monty25519> Se_point(Sender_Set_Size),Re_point(Receiver_Set_Size);
            osuCrypto::Sodium::Scalar25519 G = osuCrypto::Sodium::Scalar25519(Prng);

            if (Thread_Num > 1){

                std::vector<std::thread> X_alpha(Thread_Num);

                for (u64 i = 0ull; i < Thread_Num; i++){
                    X_alpha[i] = std::thread([&, i]() {
                        unsigned char Th_point_bytes[32];  
                        memset(Th_point_bytes,0,32);
                        u64 Th_Begin = i * Sender_Set_Size / Thread_Num, Th_End = (i+1) * Sender_Set_Size / Thread_Num;
                        for (u64 j = Th_Begin; j < Th_End; j++){
                            unsigned char* block_bytes = Inputs_DH[j].data();
                            memcpy(Th_point_bytes, block_bytes, 16);
                            Se_point[j].fromBytes(Th_point_bytes);
                            Se_point[j] = G * Se_point[j];
                        }
                        return ;
                    });
                }

                for (auto& thrd : X_alpha) thrd.join();

                coproto::sync_wait(Chl.send(Se_point));
                coproto::sync_wait(Chl.recv(Re_point));

                std::vector<std::thread> Y_alpha_beta(Thread_Num);

                for (u64 i = 0ull; i < Thread_Num; i++){
                    Y_alpha_beta[i] = std::thread([&, i]() {
                        u64 Th_Begin = i * Receiver_Set_Size / Thread_Num, Th_End = (i+1) * Receiver_Set_Size / Thread_Num;
                        for (u64 j = Th_Begin; j < Th_End; j++){
                            Re_point[j] = G * Re_point[j];
                        }
                        return ;
                    });
                }

                for (auto& thrd : Y_alpha_beta) thrd.join();

                std::shuffle(Re_point.begin(),Re_point.end(),Prng);
                coproto::sync_wait(Chl.send(Re_point));

                setTimePoint("DH-Based RPMT Finish");

            }
            else {

                setTimePoint("DH-Based RPMT Begin");

                unsigned char point_bytes[32]; 
                memset(point_bytes,0,32);

                for (u64 i = 0ull; i < Sender_Set_Size; i++){
                    unsigned char* block_bytes = Inputs_DH[i].data();
                    memcpy(point_bytes, block_bytes, 16);
                    Se_point[i].fromBytes(point_bytes);
                    Se_point[i] = G * Se_point[i];
                }

                coproto::sync_wait(Chl.send(Se_point));
                coproto::sync_wait(Chl.recv(Re_point));

                for (u64 i = 0; i < Receiver_Set_Size; i++)
                    Re_point[i] = G * Re_point[i];
                
                std::shuffle(Re_point.begin(),Re_point.end(),Prng);
                coproto::sync_wait(Chl.send(Re_point));
            }

            // OT Sender

            u64 Block_Num = ((Sender_Max_Length + 15ull) / 16) + 1ull;
            u64 OT_Num = Block_Num * Sender_Set_Size;
            u64 lowu, highu;
            std::vector<block> Rand_Num(OT_Num), OT_Inputs(OT_Num);
            Prng.get<block>(Rand_Num);
            
            for (u64 i = 0ull; i < Sender_Set_Size; i++){
                u64 Length = Inputs_String[i].length();
                OT_Inputs[i*Block_Num] = oc::toBlock(Length);
                for (u64 j = 1ull; j < Block_Num; j++){
                    lowu = 0ull; highu = 0ull;
                    for (u64 k = 0ull; k < 8ull; k++){
                        highu = highu << 8;
                        u64 Now_At = (j-1)*16+k;
                        if (Now_At < Length)
                            highu = highu | Inputs_String[i][Now_At];
                    }
                    for (u64 k = 8ull; k < 16ull; k++){
                        lowu = lowu << 8;
                        u64 Now_At = (j-1)*16+k;
                        if (Now_At < Length)
                            lowu = lowu | Inputs_String[i][Now_At];
                    }
                    OT_Inputs[i*Block_Num+j] = oc::toBlock(highu,lowu);
                }
            }

            if(OT_Num <= 128) // using libOTe-CO15
            {
                // config basic messages
                osuCrypto::DefaultBaseOT baseOTs;
                PRNG prng(oc::block(oc::sysRandomSeed()));
                std::vector<oc::block> half_sendMsg(OT_Num);
                std::vector<std::array<oc::block, 2>> randMsg(OT_Num);

                // generate random OT
                auto p = baseOTs.send(randMsg, prng, Chl);
                auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
                std::get<0>(r).result();

                // random OT -> OT
                for(u64 i = 0; i < OT_Num; i++)
                {
                    half_sendMsg[i] = OT_Inputs[i] ^ randMsg[i][1];
                }
                coproto::sync_wait(Chl.send(half_sendMsg));
            }
            else // IKNP
            {

                // configure
                oc::DefaultBaseOT baseOTs;
                PRNG prng(oc::block(oc::sysRandomSeed()));
                std::vector<oc::block> half_sendMsg(OT_Num);
                std::vector<std::array<oc::block, 2>> randMsg(OT_Num);

                // set base random messages
                std::vector<oc::block> baseRecv(128); // kappa == 128
                osuCrypto::BitVector baseChoice(128); // kappa == 128
                
                baseChoice.randomize(prng);

                // random OT (base)
                auto p = baseOTs.receive(baseChoice, baseRecv, prng, Chl);
                auto r = macoro::sync_wait(macoro::when_all_ready(std::move(p)));
                std::get<0>(r).result();

                // execute extension
                osuCrypto::IknpOtExtSender sender;
                sender.setBaseOts(baseRecv, baseChoice);
                auto proto = sender.send(randMsg, prng, Chl);
                auto result = macoro::sync_wait(macoro::when_all_ready(std::move(proto)));
                std::get<0>(result).result();

                // random OT -> OT
                for(u64 i = 0; i < OT_Num; i++)
                {
                    half_sendMsg[i] = OT_Inputs[i] ^ randMsg[i][1];
                }
                coproto::sync_wait(Chl.send(half_sendMsg));
            }

        }

        return ;
    
    }
}